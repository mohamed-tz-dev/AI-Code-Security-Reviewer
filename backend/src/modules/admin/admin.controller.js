const auditRepository = require('../audit/audit.repository');
const userRepository = require('../users/user.repository');

async function listAuditLogs(req, res) {
  const filters = {
    action: req.query.action,
    targetType: req.query.targetType,
    actorEmail: req.query.actorEmail
  };
  const auditLogs = await auditRepository.listAuditLogs(filters);
  res.json({ auditLogs });
}

async function listUsers(_req, res) {
  const users = await userRepository.listUsers();
  res.json({ users, totalCount: users.length });
}

async function updateUserRole(req, res) {
  const { userId } = req.params;
  const { role } = req.body;

  if (!['admin', 'user'].includes(role)) {
    res.status(400).json({ error: { message: 'Role must be admin or user.' } });
    return;
  }

  const updatedUser = await userRepository.updateUserRole(userId, role);

  if (!updatedUser) {
    res.status(404).json({ error: { message: 'User not found.' } });
    return;
  }

  await auditRepository.createAuditLog({
    actorUserId: req.currentUser.id,
    actorEmail: req.currentUser.email,
    action: 'user.role.updated',
    targetType: 'user',
    targetId: userId,
    metadata: { role }
  });

  res.json({ user: updatedUser });
}

module.exports = { listAuditLogs, listUsers, updateUserRole };
