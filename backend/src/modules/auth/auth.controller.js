const crypto = require('crypto');
const { createClerkClient } = require('@clerk/express');
const { env } = require('../../config/env');
const auditRepository = require('../audit/audit.repository');
const userRepository = require('../users/user.repository');
const { hashPassword, verifyPassword } = require('./password.service');
const { createToken } = require('./token.service');

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
    last_login_at: user.last_login_at
  };
}

async function issueSession(user, action) {
  await userRepository.markLogin(user.id);
  await auditRepository.createAuditLog({
    actorUserId: user.id,
    actorEmail: user.email,
    action,
    targetType: 'user',
    targetId: user.id,
    metadata: { role: user.role }
  });

  return {
    token: createToken(user),
    user: publicUser(user)
  };
}

async function register(req, res) {
  const { email, password } = req.body;

  if (!email || !password || password.length < 8) {
    res.status(400).json({ error: { message: 'Email and password with at least 8 characters are required.' } });
    return;
  }

  if (env.adminEmail && email.toLowerCase() === env.adminEmail.toLowerCase()) {
    res.status(403).json({ error: { message: 'Admin account cannot be registered from public signup.' } });
    return;
  }

  const existingUser = await userRepository.findUserByEmail(email);
  if (existingUser) {
    res.status(409).json({ error: { message: 'User already exists.' } });
    return;
  }

  const user = await userRepository.createUser({
    email,
    passwordHash: hashPassword(password),
    role: 'user'
  });

  const session = await issueSession(user, 'auth.registered');
  res.status(201).json(session);
}

async function login(req, res) {
  const { email, password } = req.body;
  const user = email ? await userRepository.findUserByEmail(email) : null;

  if (!user || user.role === 'admin' || !verifyPassword(password || '', user.password_hash)) {
    res.status(401).json({ error: { message: 'Invalid email or password.' } });
    return;
  }

  const session = await issueSession(user, 'auth.login');
  res.json(session);
}

async function adminLogin(req, res) {
  const { email, password } = req.body;

  if (!env.adminEmail || !env.adminPassword) {
    res.status(500).json({ error: { message: 'Admin credentials are not configured.' } });
    return;
  }

  if (email?.toLowerCase() !== env.adminEmail.toLowerCase() || password !== env.adminPassword) {
    res.status(401).json({ error: { message: 'Invalid admin credentials.' } });
    return;
  }

  let adminUser = await userRepository.findUserByEmail(env.adminEmail);
  if (!adminUser) {
    adminUser = await userRepository.createUser({
      email: env.adminEmail,
      passwordHash: hashPassword(env.adminPassword),
      role: 'admin'
    });
  } else if (adminUser.role !== 'admin') {
    adminUser = await userRepository.updateUserRole(adminUser.id, 'admin');
  }

  const session = await issueSession(adminUser, 'auth.admin_login');
  res.json(session);
}

async function me(req, res) {
  res.json({ user: req.currentUser });
}

/**
 * Google / Clerk OAuth sign-in.
 * Frontend sends the Clerk session token; we verify it, then find-or-create
 * the user in our DB and return our own custom JWT.
 */
async function clerkAuth(req, res) {
  const { clerkToken } = req.body;

  if (!clerkToken) {
    return res.status(400).json({ error: { message: 'clerkToken is required.' } });
  }

  if (!env.clerkSecretKey) {
    return res.status(500).json({ error: { message: 'Clerk is not configured on this server.' } });
  }

  try {
    const clerk = createClerkClient({ secretKey: env.clerkSecretKey });

    // Verify the Clerk JWT — throws if invalid / expired
    const payload = await clerk.verifyToken(clerkToken);
    const clerkUserId = payload.sub;

    // Fetch the Clerk user to get their primary email
    const clerkUser = await clerk.users.getUser(clerkUserId);
    const email = clerkUser.emailAddresses?.[0]?.emailAddress;

    if (!email) {
      return res.status(400).json({ error: { message: 'Account has no accessible email address.' } });
    }

    // Prevent hijacking the admin account via Clerk providers
    if (env.adminEmail && email.toLowerCase() === env.adminEmail.toLowerCase()) {
      return res.status(403).json({ error: { message: 'Admin account must use the admin login form.' } });
    }

    // Find or auto-create the user
    let user = await userRepository.findUserByEmail(email);
    if (!user) {
      // OAuth/managed login users have no password — store a cryptographically random unusable hash
      const unusableHash = crypto.randomBytes(32).toString('hex');
      user = await userRepository.createUser({ email, passwordHash: unusableHash, role: 'user' });
    }

    const session = await issueSession(user, 'auth.clerk_login');
    return res.json(session);
  } catch (err) {
    console.error('[clerkAuth] Clerk verification failed:', err?.message || err);
    return res.status(401).json({ error: { message: 'Sign-in failed. Please try again.' } });
  }
}

async function googleAuth(req, res) {
  // Backward compatible endpoint (Google only)
  return clerkAuth(req, res);
}

module.exports = { adminLogin, googleAuth, clerkAuth, login, me, register };
