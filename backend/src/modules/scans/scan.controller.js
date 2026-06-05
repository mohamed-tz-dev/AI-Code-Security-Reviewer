const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const { z } = require('zod');

const { scanQueue } = require('../../queue/scan.queue');
const auditRepository = require('../audit/audit.repository');
const { createScanReportPdf } = require('../../lib/pdf.service');
const scanRepository = require('./scan.repository');
const vulnerabilityRepository = require('../vulnerabilities/vulnerability.repository');
const { env } = require('../../config/env');
const { askQuestion, generateSecurePatch } = require('../../scanner/chat.service');

const githubScanSchema = z.object({
  repositoryUrl: z.string().url(),
  githubAccessToken: z.string().min(1).optional(),
  branch: z.string().min(1).optional(),
  commitSha: z.string().regex(/^[0-9a-fA-F]{7,40}$/).optional(),
  organizationId: z.string().uuid().optional(),
  teamId: z.string().uuid().optional()
});

const ciTemplateProviders = {
  'github-actions': 'github-actions-security-scan.yml',
  'gitlab-ci': 'gitlab-ci.yml',
  jenkins: 'jenkins-pipeline.groovy'
};

const githubAppSystemUser = {
  id: 'github-app',
  email: 'github-app@internal'
};

function getProjectNameFromUpload(file) {
  return path.basename(file.originalname, path.extname(file.originalname));
}

async function createZipScan(req, res) {
  if (!req.file) {
    res.status(400).json({ error: { message: 'ZIP file is required.' } });
    return;
  }

  const organizationId = req.body.organizationId || null;
  const teamId = req.body.teamId || null;

  const scan = await scanRepository.createScan({
    projectName: getProjectNameFromUpload(req.file),
    sourceType: 'zip',
    sourceReference: req.file.path,
    userId: req.currentUser.id,
    userEmail: req.currentUser.email,
    organizationId,
    teamId
  });

  await scanQueue.add('scan-uploaded-zip', {
    scanId: scan.id,
    uploadPath: req.file.path,
    organizationId,
    teamId
  });

  await auditRepository.createAuditLog({
    actorUserId: req.currentUser.id,
    actorEmail: req.currentUser.email,
    action: 'scan.created',
    targetType: 'scan',
    targetId: scan.id,
    metadata: {
      sourceType: 'zip',
      projectName: scan.project_name
    }
  });

  res.status(202).json({ scan });
}

async function createGithubScan(req, res) {
  const payload = githubScanSchema.parse(req.body);
  const projectName = new URL(payload.repositoryUrl).pathname.split('/').filter(Boolean).pop();

  const scan = await scanRepository.createScan({
    projectName,
    sourceType: 'github',
    sourceReference: payload.repositoryUrl,
    userId: req.currentUser.id,
    userEmail: req.currentUser.email,
    organizationId: payload.organizationId || null,
    teamId: payload.teamId || null
  });

  await scanQueue.add('scan-github-repository', {
    scanId: scan.id,
    repositoryUrl: payload.repositoryUrl,
    githubAccessToken: payload.githubAccessToken,
    branch: payload.branch || null,
    commitSha: payload.commitSha || null,
    organizationId: payload.organizationId || null,
    teamId: payload.teamId || null
  });

  await auditRepository.createAuditLog({
    actorUserId: req.currentUser.id,
    actorEmail: req.currentUser.email,
    action: 'scan.created',
    targetType: 'scan',
    targetId: scan.id,
    metadata: {
      sourceType: 'github',
      projectName: scan.project_name
    }
  });

  res.status(202).json({ scan });
}

async function getScan(req, res) {
  const scan = await scanRepository.getScanById(req.params.scanId, {
    userId: req.currentUser.id,
    isAdmin: req.currentUser.isAdmin
  });

  if (!scan) {
    res.status(404).json({ error: { message: 'Scan not found.' } });
    return;
  }

  res.json({ scan });
}

function verifyGithubWebhookSignature(rawBody, signatureHeader) {
  if (!env.githubWebhookSecret) {
    return;
  }

  const signature = typeof signatureHeader === 'string' ? signatureHeader : '';
  if (!signature.startsWith('sha256=')) {
    throw new Error('Missing or invalid GitHub webhook signature.');
  }

  const expected = crypto
    .createHmac('sha256', env.githubWebhookSecret)
    .update(rawBody)
    .digest('hex');

  const provided = signature.slice('sha256='.length);
  const expectedBuffer = Buffer.from(expected, 'hex');
  const providedBuffer = Buffer.from(provided, 'hex');

  if (expectedBuffer.length !== providedBuffer.length || !crypto.timingSafeEqual(expectedBuffer, providedBuffer)) {
    throw new Error('GitHub webhook signature verification failed.');
  }
}

async function createAutomatedGithubScan({ repositoryUrl, sourceType, sourceReference, branch, commitSha }) {
  const projectName = `${new URL(repositoryUrl).pathname.split('/').filter(Boolean).pop()}${branch ? `:${branch}` : ''}${commitSha ? `@${commitSha.slice(0, 7)}` : ''}`;

  const scan = await scanRepository.createScan({
    projectName,
    sourceType,
    sourceReference,
    userId: githubAppSystemUser.id,
    userEmail: githubAppSystemUser.email,
    organizationId: null,
    teamId: null
  });

  await scanQueue.add('scan-github-repository', {
    scanId: scan.id,
    repositoryUrl,
    githubAccessToken: env.githubDefaultAccessToken,
    branch: branch || null,
    commitSha: commitSha || null
  });

  await auditRepository.createAuditLog({
    actorUserId: githubAppSystemUser.id,
    actorEmail: githubAppSystemUser.email,
    action: 'scan.created',
    targetType: 'scan',
    targetId: scan.id,
    metadata: {
      sourceType,
      sourceReference
    }
  });

  return scan;
}

async function githubWebhook(req, res) {
  const rawBody = req.body;
  const event = req.headers['x-github-event'];
  const signatureHeader = req.headers['x-hub-signature-256'];

  if (!event) {
    res.status(400).json({ error: { message: 'Missing X-GitHub-Event header.' } });
    return;
  }

  try {
    verifyGithubWebhookSignature(rawBody, signatureHeader);
  } catch (error) {
    res.status(401).json({ error: { message: error.message } });
    return;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch (error) {
    res.status(400).json({ error: { message: 'Invalid JSON payload.' } });
    return;
  }

  if (event === 'ping') {
    res.status(200).json({ message: 'pong' });
    return;
  }

  if (event === 'pull_request') {
    const action = payload.action;
    if (!['opened', 'reopened', 'synchronize'].includes(action)) {
      res.status(204).json({ message: 'Ignored pull request event.' });
      return;
    }

    const repositoryUrl = payload.pull_request?.head?.repo?.clone_url;
    const branch = payload.pull_request?.head?.ref;
    const commitSha = payload.pull_request?.head?.sha;

    if (!repositoryUrl || !branch || !commitSha) {
      res.status(400).json({ error: { message: 'Incomplete pull request payload.' } });
      return;
    }

    await createAutomatedGithubScan({
      repositoryUrl,
      sourceType: 'github-pull-request',
      sourceReference: `${repositoryUrl}#pr/${payload.number}`,
      branch,
      commitSha
    });

    res.status(202).json({ message: 'GitHub pull request scan scheduled.' });
    return;
  }

  if (event === 'push') {
    const repositoryUrl = payload.repository?.clone_url;
    const ref = payload.ref;
    if (!repositoryUrl || !ref || !ref.startsWith('refs/heads/')) {
      res.status(400).json({ error: { message: 'Unsupported push payload.' } });
      return;
    }

    const branch = ref.replace('refs/heads/', '');
    const commitSha = payload.after;
    await createAutomatedGithubScan({
      repositoryUrl,
      sourceType: 'github-push',
      sourceReference: `${repositoryUrl}#${branch}`,
      branch,
      commitSha
    });

    res.status(202).json({ message: 'GitHub push scan scheduled.' });
    return;
  }

  res.status(204).json({ message: 'GitHub event ignored.' });
}

async function exportScanPdf(req, res) {
  const scan = await scanRepository.getScanById(req.params.scanId, {
    userId: req.currentUser.id,
    isAdmin: req.currentUser.isAdmin
  });

  if (!scan) {
    res.status(404).json({ error: { message: 'Scan not found.' } });
    return;
  }

  await auditRepository.createAuditLog({
    actorUserId: req.currentUser.id,
    actorEmail: req.currentUser.email,
    action: 'scan.pdf.exported',
    targetType: 'scan',
    targetId: scan.id,
    metadata: {
      projectName: scan.project_name
    }
  });

  const pdf = createScanReportPdf(scan);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${scan.project_name}-security-report.pdf"`);
  res.send(pdf);
}

async function askChat(req, res) {
  const chatSchema = z.object({
    question: z.string().min(1),
    scanId: z.string().uuid().optional()
  });

  const { question, scanId } = chatSchema.parse(req.body);
  let scan = null;

  if (scanId) {
    scan = await scanRepository.getScanById(scanId, {
      userId: req.currentUser.id,
      isAdmin: req.currentUser.isAdmin
    });

    if (!scan) {
      res.status(404).json({ error: { message: 'Scan not found.' } });
      return;
    }
  }

  const answer = await askQuestion(question, scan);

  res.json({ answer });
}

async function listCiTemplates(_req, res) {
  res.json({ providers: Object.keys(ciTemplateProviders) });
}

async function getCiTemplate(req, res) {
  const provider = req.params.provider.toLowerCase();
  const templateFile = ciTemplateProviders[provider];

  if (!templateFile) {
    res.status(404).json({ error: { message: 'CI template not found.' } });
    return;
  }

  const templatePath = path.resolve(__dirname, '../../ci-templates', templateFile);
  const content = await fs.readFile(templatePath, 'utf8');

  res.setHeader('Content-Type', 'text/plain');
  res.send(content);
}

async function listScans(req, res) {
  const scans = await scanRepository.listScans({
    userId: req.currentUser.id,
    isAdmin: req.currentUser.isAdmin
  });
  res.json({ scans, currentUser: req.currentUser });
}

async function getAdminSummary(_req, res) {
  const summary = await scanRepository.getAdminSummary();
  res.json({ summary });
}

async function generateFindingPatch(req, res) {
  const paramsSchema = z.object({
    scanId: z.string().uuid(),
    findingId: z.string().uuid()
  });

  const { scanId, findingId } = paramsSchema.parse(req.params);

  const scan = await scanRepository.getScanById(scanId, {
    userId: req.currentUser.id,
    isAdmin: req.currentUser.isAdmin
  });

  if (!scan) {
    res.status(404).json({ error: { message: 'Scan not found.' } });
    return;
  }

  const finding = scan.vulnerabilities.find((item) => item.id === findingId);

  if (!finding) {
    res.status(404).json({ error: { message: 'Finding not found.' } });
    return;
  }

  const securePatch = await generateSecurePatch(finding);
  const updated = await vulnerabilityRepository.setSecurePatch(findingId, securePatch);

  res.json({ securePatch, finding: updated });
}

module.exports = {
  createZipScan,
  createGithubScan,
  githubWebhook,
  exportScanPdf,
  askChat,
  generateFindingPatch,
  getAdminSummary,
  getCiTemplate,
  listCiTemplates,
  getScan,
  listScans
};
