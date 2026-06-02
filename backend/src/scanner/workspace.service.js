const fs = require('fs/promises');
const nodeFs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const unzipper = require('unzipper');

const { env } = require('../config/env');
const { MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_BYTES } = require('./scanner.config');

async function createScanWorkspace(scanId) {
  const workspacePath = path.join(env.workspaceDir, scanId);
  const repositoryPath = path.join(workspacePath, 'repository');

  await fs.rm(workspacePath, { recursive: true, force: true });
  await fs.mkdir(repositoryPath, { recursive: true });

  return { workspacePath, repositoryPath };
}

async function extractZipToWorkspace(zipPath, destinationPath) {
  const zipDirectory = await unzipper.Open.file(zipPath);
  const destinationRoot = path.resolve(destinationPath);

  if (zipDirectory.files.length > MAX_ZIP_ENTRIES) {
    throw new Error('ZIP contains too many files for an MVP scan.');
  }

  for (const entry of zipDirectory.files) {
    const normalizedEntryPath = path.normalize(entry.path);

    if (normalizedEntryPath.startsWith('..') || path.isAbsolute(normalizedEntryPath)) {
      throw new Error('ZIP contains an unsafe file path.');
    }

    const destination = path.resolve(destinationPath, normalizedEntryPath);
    const relativeDestination = path.relative(destinationRoot, destination);

    if (relativeDestination.startsWith('..') || path.isAbsolute(relativeDestination)) {
      throw new Error('ZIP contains a path traversal attempt.');
    }

    if (entry.type === 'Directory') {
      await fs.mkdir(destination, { recursive: true });
      continue;
    }

    const uncompressedSize = entry.uncompressedSize || entry.vars?.uncompressedSize || 0;
    if (uncompressedSize > MAX_ZIP_ENTRY_BYTES) {
      continue;
    }

    await fs.mkdir(path.dirname(destination), { recursive: true });
    await new Promise((resolve, reject) => {
      entry
        .stream()
        .pipe(nodeFs.createWriteStream(destination, { flags: 'wx' }))
        .on('finish', resolve)
        .on('error', reject);
    });
  }
}

function validateGithubUrl(repositoryUrl) {
  const url = new URL(repositoryUrl);

  if (url.protocol !== 'https:' || url.hostname !== 'github.com') {
    throw new Error('Only HTTPS GitHub repository URLs are supported in the MVP.');
  }

  const segments = url.pathname.split('/').filter(Boolean);
  if (segments.length < 2) {
    throw new Error('GitHub repository URL must include an owner and repository name.');
  }
}

async function cloneGithubRepository(repositoryUrl, destinationPath, githubAccessToken, ref) {
  validateGithubUrl(repositoryUrl);

  const cloneUrl = githubAccessToken
    ? buildGitHubAuthCloneUrl(repositoryUrl, githubAccessToken)
    : repositoryUrl;

  const refIsCommit = typeof ref === 'string' && /^[0-9a-f]{7,40}$/i.test(ref);
  const cloneArgs = ['clone', '--depth', '1', '--no-tags'];

  if (ref && !refIsCommit) {
    cloneArgs.push('--branch', ref, '--single-branch');
  }

  cloneArgs.push(cloneUrl, destinationPath);

  await runGitCommand(cloneArgs, destinationPath);

  if (ref && refIsCommit) {
    await runGitCommand(['-C', destinationPath, 'fetch', '--depth', '1', 'origin', ref], destinationPath);
    await runGitCommand(['-C', destinationPath, 'checkout', 'FETCH_HEAD'], destinationPath);
  }
}

function runGitCommand(args, destinationPath) {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stderr = '';
    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error('Git command timed out.'));
    }, 120000);

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on('close', (code) => {
      clearTimeout(timeout);
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`Git command failed: ${stderr.trim() || `exit code ${code}`}`));
    });
  });
}

function buildGitHubAuthCloneUrl(repositoryUrl, githubAccessToken) {
  const url = new URL(repositoryUrl);
  const cleanToken = githubAccessToken.trim();
  url.username = 'x-access-token';
  url.password = cleanToken;
  return url.toString();
}

module.exports = {
  cloneGithubRepository,
  createScanWorkspace,
  extractZipToWorkspace
};
