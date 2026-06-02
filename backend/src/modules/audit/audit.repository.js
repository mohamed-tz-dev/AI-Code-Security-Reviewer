const { pool } = require('../../db/pool');

async function createAuditLog({ actorUserId, actorEmail, action, targetType, targetId, metadata = {} }) {
  await pool.query(
    `
      insert into audit_logs (
        actor_user_id,
        actor_email,
        action,
        target_type,
        target_id,
        metadata
      )
      values ($1, $2, $3, $4, $5, $6)
    `,
    [actorUserId || null, actorEmail || null, action, targetType, targetId || null, metadata]
  );
}

async function listAuditLogs(filters = {}) {
  const { action, targetType, actorEmail } = filters;
  const clauses = [];
  const params = [];

  if (action) {
    params.push(action);
    clauses.push(`action = $${params.length}`);
  }

  if (targetType) {
    params.push(targetType);
    clauses.push(`target_type = $${params.length}`);
  }

  if (actorEmail) {
    params.push(`%${actorEmail}%`);
    clauses.push(`actor_email ilike $${params.length}`);
  }

  const whereClause = clauses.length > 0 ? `where ${clauses.join(' and ')}` : '';
  const result = await pool.query(
    `
      select *
      from audit_logs
      ${whereClause}
      order by created_at desc
      limit 100
    `,
    params
  );

  return result.rows;
}

module.exports = { createAuditLog, listAuditLogs };
