const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { env } = require('../config/env');

const SEMGREP_COMMANDS = [
  ['semgrep'],
  ['python', '-m', 'semgrep'],
  ['python3', '-m', 'semgrep'],
  ['py', '-3', '-m', 'semgrep']
];

let cachedSemgrepCommand;
let hasLoggedMissingSemgrep = false;

function findSemgrepCommand() {
  if (cachedSemgrepCommand !== undefined) {
    return cachedSemgrepCommand;
  }

  cachedSemgrepCommand = null;

  for (const command of SEMGREP_COMMANDS) {
    const result = spawnSync(command[0], [...command.slice(1), '--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });

    if (result.status === 0) {
      cachedSemgrepCommand = { command: command[0], args: command.slice(1) };
      break;
    }
  }

  if (!cachedSemgrepCommand && !hasLoggedMissingSemgrep) {
    console.log('Semgrep analysis disabled: install semgrep and ensure it is available on PATH.');
    hasLoggedMissingSemgrep = true;
  }

  return cachedSemgrepCommand;
}

function normalizeSeverity(value) {
  if (!value) {
    return 'medium';
  }

  const normalized = String(value).toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
    return normalized;
  }

  if (normalized === 'error') {
    return 'high';
  }

  return 'medium';
}

function normalizeConfidence(precision) {
  if (!precision) {
    return 0.7;
  }

  const normalized = String(precision).toLowerCase();
  switch (normalized) {
    case 'high':
      return 0.85;
    case 'medium':
      return 0.7;
    case 'low':
      return 0.6;
    default:
      return 0.7;
  }
}

function buildFinding(result, repositoryPath) {
  const extra = result.extra || {};
  const metadata = extra.metadata || {};
  const relativePath = path
    .relative(repositoryPath, result.path || '')
    .split(path.sep)
    .join('/');

  if (!relativePath) {
    return null;
  }

  const lineStart = result.start?.line || null;
  const lineEnd = result.end?.line || lineStart;

  return {
    title: extra.message || result.check_id || 'Semgrep finding',
    category: 'Semgrep',
    severity: normalizeSeverity(metadata.severity || result.severity),
    filePath: relativePath,
    lineStart,
    lineEnd,
    description: `Semgrep rule ${result.check_id}: ${extra.message || 'Review the matching code.'}`,
    recommendation:
      extra.message || metadata.message || `Review the Semgrep rule ${result.check_id} and fix the reported issue.`,
    evidence: extra.lines?.code?.trim?.().slice(0, 500) || null,
    confidence: normalizeConfidence(metadata.precision || extra.precision)
  };
}

function buildArgs(repositoryPath) {
  const args = ['--json', '--config', env.semgrepConfig || 'auto', '--exclude', '.git', repositoryPath];
  return args;
}

async function scanRepositoryWithSemgrep(repositoryPath) {
  if (!env.semgrepEnabled) {
    return [];
  }

  const semgrepCommand = findSemgrepCommand();
  if (!semgrepCommand) {
    return [];
  }

  return new Promise((resolve) => {
    const args = [...semgrepCommand.args, ...buildArgs(repositoryPath)];
    const child = spawn(semgrepCommand.command, args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      resolve([]);
    }, env.semgrepTimeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', () => {
      clearTimeout(timeout);
      resolve([]);
    });

    child.on('close', (code) => {
      clearTimeout(timeout);

      if (code !== 0 && !stdout) {
        resolve([]);
        return;
      }

      try {
        const json = JSON.parse(stdout || '{}');
        const results = Array.isArray(json.results) ? json.results : [];
        const findings = results
          .map((result) => buildFinding(result, repositoryPath))
          .filter(Boolean);

        resolve(findings);
      } catch (_error) {
        resolve([]);
      }
    });
  });
}

function isSemgrepConfigured() {
  return env.semgrepEnabled;
}

module.exports = { scanRepositoryWithSemgrep, isSemgrepConfigured, findSemgrepCommand };
