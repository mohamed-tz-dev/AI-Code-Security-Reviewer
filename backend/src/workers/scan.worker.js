require('dotenv').config();

const { Worker } = require('bullmq');

const { pool } = require('../db/pool');
const { SCAN_QUEUE_NAME } = require('../queue/constants');
const { createRedisConnection } = require('../queue/redis');
const auditRepository = require('../modules/audit/audit.repository');
const scanRepository = require('../modules/scans/scan.repository');
const { scanRepository: runRepositoryScan } = require('../scanner/scan.service');

async function updateScanProgress(scanId, job, progress) {
  await scanRepository.markScanProgress(scanId, progress);

  if (job && typeof job.updateProgress === 'function') {
    await job.updateProgress(progress);
  }
}

async function processScanJob(job) {
  const { scanId } = job.data;
  await scanRepository.markScanRunning(scanId);
  const scanOwner = await scanRepository.getScanOwner(scanId);

  await auditRepository.createAuditLog({
    actorUserId: scanOwner?.user_id,
    actorEmail: scanOwner?.user_email,
    action: 'scan.started',
    targetType: 'scan',
    targetId: scanId,
    metadata: {
      jobId: job.id
    }
  });

  try {
    await updateScanProgress(scanId, job, 10);
    const result = await runRepositoryScan(job.data, async (stageProgress) => {
      await updateScanProgress(scanId, job, stageProgress);
    });
    await updateScanProgress(scanId, job, 95);
    await scanRepository.markScanCompleted(
      scanId,
      result.securityScore,
      Array.isArray(result.topRecommendations) ? result.topRecommendations.join('\n') : null
    );
    await auditRepository.createAuditLog({
      actorUserId: scanOwner?.user_id,
      actorEmail: scanOwner?.user_email,
      action: 'scan.completed',
      targetType: 'scan',
      targetId: scanId,
      metadata: result
    });
  } catch (error) {
    await scanRepository.markScanFailed(scanId, error.message);
    await updateScanProgress(scanId, job, 100);
    await auditRepository.createAuditLog({
      actorUserId: scanOwner?.user_id,
      actorEmail: scanOwner?.user_email,
      action: 'scan.failed',
      targetType: 'scan',
      targetId: scanId,
      metadata: {
        error: error.message
      }
    });
    throw error;
  }
}

const worker = new Worker(SCAN_QUEUE_NAME, processScanJob, {
  connection: createRedisConnection(),
  concurrency: 2
});

worker.on('completed', (job) => {
  console.log(`Completed scan job ${job.id}`);
});

worker.on('failed', (job, error) => {
  console.error(`Failed scan job ${job?.id}:`, error);
});

process.on('SIGTERM', async () => {
  await worker.close();
  await pool.end();
  process.exit(0);
});
