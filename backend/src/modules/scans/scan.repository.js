const { pool } = require('../../db/pool');

async function createScan({ projectName, sourceType, sourceReference, userId, userEmail, organizationId = null, teamId = null }) {
  const result = await pool.query(
    `
      insert into scans (project_name, source_type, source_reference, status, progress, user_id, user_email, organization_id, team_id)
      values ($1, $2, $3, 'queued', 0, $4, $5, $6, $7)
      returning *
    `,
    [projectName, sourceType, sourceReference, userId, userEmail, organizationId, teamId]
  );

  return result.rows[0];
}

async function getScanById(scanId, { userId, isAdmin }) {
  const scanResult = await pool.query(
    `
      select *
      from scans
      where id = $1
        and ($2::boolean = true or user_id = $3)
    `,
    [scanId, isAdmin, userId]
  );

  if (scanResult.rowCount === 0) {
    return null;
  }

  const vulnerabilitiesResult = await pool.query(
    `
      select *
      from vulnerabilities
      where scan_id = $1
      order by
        case severity
          when 'critical' then 1
          when 'high' then 2
          when 'medium' then 3
          when 'low' then 4
          else 5
        end,
        file_path asc
    `,
    [scanId]
  );

  return {
    ...scanResult.rows[0],
    vulnerabilities: vulnerabilitiesResult.rows
  };
}

async function listScans({ userId, isAdmin }) {
  const result = await pool.query(
    `
    select
      s.*,
      count(v.id)::int as vulnerability_count
    from scans s
    left join vulnerabilities v on v.scan_id = s.id
    where ($1::boolean = true or s.user_id = $2)
    group by s.id
    order by s.created_at desc
    limit 50
  `,
    [isAdmin, userId]
  );

  return result.rows;
}

async function getAdminSummary() {
  const result = await pool.query(`
    select
      count(*)::int as total_scans,
      count(*) filter (where status = 'queued')::int as queued_scans,
      count(*) filter (where status = 'running')::int as running_scans,
      count(*) filter (where status = 'completed')::int as completed_scans,
      count(*) filter (where status = 'failed')::int as failed_scans,
      count(distinct user_id)::int as user_count,
      coalesce(avg(security_score) filter (where security_score is not null), 0)::int as average_security_score
    from scans
  `);

  return result.rows[0];
}

async function getScanOwner(scanId) {
  const result = await pool.query(
    `
      select id, project_name, user_id, user_email, status
      from scans
      where id = $1
    `,
    [scanId]
  );

  return result.rows[0] || null;
}

async function markScanRunning(scanId) {
  await pool.query(
    "update scans set status = 'running', started_at = now(), progress = 5, error_message = null where id = $1",
    [scanId]
  );
}

async function markScanProgress(scanId, progress) {
  await pool.query(
    'update scans set progress = $2 where id = $1',
    [scanId, progress]
  );
}

async function markScanCompleted(scanId, securityScore, aiRecommendations = null) {
  await pool.query(
    "update scans set status = 'completed', security_score = $2, ai_recommendations = $3, progress = 100, completed_at = now() where id = $1",
    [scanId, securityScore, aiRecommendations]
  );
}

async function markScanFailed(scanId, errorMessage) {
  await pool.query(
    "update scans set status = 'failed', error_message = $2, progress = 100, completed_at = now() where id = $1",
    [scanId, errorMessage]
  );
}

module.exports = {
  createScan,
  getAdminSummary,
  getScanOwner,
  getScanById,
  listScans,
  markScanRunning,
  markScanProgress,
  markScanCompleted,
  markScanFailed
};
