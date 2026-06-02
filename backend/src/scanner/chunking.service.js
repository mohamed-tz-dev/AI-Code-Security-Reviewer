const fs = require('fs/promises');
const path = require('path');

const { env } = require('../config/env');

const SECURITY_RELEVANT_NAMES = [
  'auth',
  'login',
  'session',
  'jwt',
  'token',
  'password',
  'secret',
  'user',
  'admin',
  'route',
  'controller',
  'handler',
  'db',
  'database',
  'query',
  'sql',
  'upload',
  'webhook',
  'payment'
];

function addLineNumbers(content) {
  return content
    .split(/\r?\n/)
    .map((line, index) => `${index + 1}: ${line}`)
    .join('\n');
}

function scoreFileForAiReview(sourceFile, staticFindings) {
  const lowerPath = sourceFile.relativePath.toLowerCase();
  const staticFindingCount = staticFindings.filter((finding) => {
    return finding.filePath === sourceFile.relativePath;
  }).length;

  const pathScore = SECURITY_RELEVANT_NAMES.reduce((score, name) => {
    return lowerPath.includes(name) ? score + 2 : score;
  }, 0);

  const extension = path.extname(lowerPath);
  const languageScore = ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.go'].includes(extension)
    ? 3
    : 1;

  return staticFindingCount * 10 + pathScore + languageScore;
}

async function buildAiReviewChunks(sourceFiles, staticFindings) {
  const rankedFiles = [...sourceFiles]
    .map((sourceFile) => ({
      sourceFile,
      score: scoreFileForAiReview(sourceFile, staticFindings)
    }))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, env.aiMaxFiles);

  const chunks = [];

  for (const entry of rankedFiles) {
    const rawContent = await fs.readFile(entry.sourceFile.absolutePath, 'utf8');
    const truncatedContent = rawContent.slice(0, env.aiMaxCharsPerFile);

    chunks.push({
      filePath: entry.sourceFile.relativePath,
      content: addLineNumbers(truncatedContent),
      truncated: rawContent.length > truncatedContent.length
    });
  }

  return chunks;
}

module.exports = { buildAiReviewChunks };
