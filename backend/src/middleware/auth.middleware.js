const { env } = require('../config/env');

function getPrimaryEmail(user) {
  return user.emailAddresses?.find((email) => email.id === user.primaryEmailAddressId)?.emailAddress || null;
}

async function attachCurrentUser(req, res, next) {
  if (!env.clerkAuthEnabled) {
    req.currentUser = {
      id: 'dev-user',
      email: 'dev@example.local',
      role: 'admin',
      isAdmin: true
    };
    return next();
  }

  const { clerkClient, getAuth } = require('@clerk/express');
  const auth = getAuth(req);

  if (!auth.isAuthenticated) {
    return res.status(401).json({ error: { message: 'Authentication required.' } });
  }

  try {
    const user = await clerkClient.users.getUser(auth.userId);
    const role = user.publicMetadata?.role === 'admin' ? 'admin' : 'user';

    req.currentUser = {
      id: auth.userId,
      email: getPrimaryEmail(user),
      role,
      isAdmin: role === 'admin'
    };

    return next();
  } catch (error) {
    return next(error);
  }
}

function requireAdmin(req, res, next) {
  if (!req.currentUser?.isAdmin) {
    return res.status(403).json({ error: { message: 'Admin access required.' } });
  }

  return next();
}

module.exports = { attachCurrentUser, requireAdmin };
