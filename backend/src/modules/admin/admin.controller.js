const auditRepository = require('../audit/audit.repository');
const { clerkClient } = require('@clerk/express');

function mapClerkUser(user) {
  const primaryEmail =
    user.emailAddresses?.find((email) => email.id === user.primaryEmailAddressId)?.emailAddress ||
    user.emailAddresses?.[0]?.emailAddress ||
    null;

  return {
    id: user.id,
    email: primaryEmail,
    firstName: user.firstName,
    lastName: user.lastName,
    role: user.publicMetadata?.role === 'admin' ? 'admin' : 'user',
    createdAt: user.createdAt,
    lastSignInAt: user.lastSignInAt
  };
}

async function listAuditLogs(_req, res) {
  const filters = {
    action: _req.query.action,
    targetType: _req.query.targetType,
    actorEmail: _req.query.actorEmail
  };
  const auditLogs = await auditRepository.listAuditLogs(filters);
  res.json({ auditLogs });
}

async function listUsers(_req, res) {
  const { data, totalCount } = await clerkClient.users.getUserList({
    limit: 100,
    orderBy: '-created_at'
  });

  res.json({
    users: data.map(mapClerkUser),
    totalCount
  });
}

async function updateUserRole(req, res) {
  const { userId } = req.params;
  const { role } = req.body;

  if (!['admin', 'user'].includes(role)) {
    res.status(400).json({ error: { message: 'Role must be admin or user.' } });
    return;
  }

  const publicMetadata = role === 'admin' ? { role: 'admin' } : { role: 'user' };
  const updatedUser = await clerkClient.users.updateUserMetadata(userId, {
    publicMetadata
  });

  await auditRepository.createAuditLog({
    actorUserId: req.currentUser.id,
    actorEmail: req.currentUser.email,
    action: 'user.role.updated',
    targetType: 'user',
    targetId: userId,
    metadata: { role }
  });

  res.json({ user: mapClerkUser(updatedUser) });
}

module.exports = { listAuditLogs, listUsers, updateUserRole };
