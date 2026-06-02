const fs = require('fs/promises');
const path = require('path');

const vulnerabilityRepository = require('../modules/vulnerabilities/vulnerability.repository');
const { analyzeChunksWithAi, isAiAnalysisConfigured } = require('./ai-analysis.service');
const { scanJavaScriptAst } = require('./ast-analysis.service');
const { scanDependencyFiles } = require('./dependency-vulnerability.service');
const { scanBackendApiSecurity } = require('./backend-analysis.service');
const { buildAiReviewChunks } = require('./chunking.service');
const { collectSourceFiles } = require('./file-traversal.service');
const { dedupeFindings } = require('./finding-dedupe.service');
const { scanFileWithSecretPatterns } = require('./secret-detection.service');
const { scanPythonAst } = require('./python-ast-analysis.service');
const { retrieveSecurityContext } = require('./rag/retrieval.service');
const { calculateSecurityScore } = require('./score.service');
const { scanFileWithStaticRules } = require('./static-rules.service');
const {
  cloneGithubRepository,
  createScanWorkspace,
  extractZipToWorkspace
} = require('./workspace.service');

async function prepareRepository(jobData) {
  const { scanId } = jobData;
  const { repositoryPath } = await createScanWorkspace(scanId);

  if (jobData.uploadPath) {
    await extractZipToWorkspace(jobData.uploadPath, repositoryPath);
    return repositoryPath;
  }

  if (jobData.repositoryUrl) {
    await fs.rm(repositoryPath, { recursive: true, force: true });
    const cloneRef = jobData.commitSha || jobData.branch || jobData.ref;
    await cloneGithubRepository(
      jobData.repositoryUrl,
      repositoryPath,
      jobData.githubAccessToken,
      cloneRef
    );
    return repositoryPath;
  }

  throw new Error('Scan job is missing a ZIP upload path or GitHub repository URL.');
}

async function scanRepository(jobData, progressCallback) {
  const repositoryPath = await prepareRepository(jobData);
  if (typeof progressCallback === 'function') {
    await progressCallback(20);
  }

  const sourceFiles = await collectSourceFiles(repositoryPath);
  const staticFindings = [];
  const astFindings = [];

  if (typeof progressCallback === 'function') {
    await progressCallback(30);
  }

  for (let index = 0; index < sourceFiles.length; index += 1) {
    const sourceFile = sourceFiles[index];
    const content = await fs.readFile(sourceFile.absolutePath, 'utf8');
    staticFindings.push(...scanFileWithStaticRules(sourceFile, content));
    staticFindings.push(...scanFileWithSecretPatterns(sourceFile, content));

    const extension = path.extname(sourceFile.relativePath).toLowerCase();
    if (extension === '.py') {
      astFindings.push(...(await scanPythonAst(sourceFile, content)));
    } else {
      astFindings.push(...scanJavaScriptAst(sourceFile, content));
    }

    if (typeof progressCallback === 'function') {
      const fileProgress = 30 + Math.round(((index + 1) / sourceFiles.length) * 30);
      await progressCallback(Math.min(60, fileProgress));
    }
  }

  const dependencyFindings = await scanDependencyFiles(repositoryPath);
  if (dependencyFindings.length > 0) {
    staticFindings.push(...dependencyFindings);
  }

  if (typeof progressCallback === 'function') {
    await progressCallback(60);
  }

  const backendSecurityFindings = await scanBackendApiSecurity(repositoryPath);
  if (backendSecurityFindings.length > 0) {
    staticFindings.push(...backendSecurityFindings);
  }

  const preAiFindings = dedupeFindings([...staticFindings, ...astFindings]);

  let aiFindings = [];
  let topRecommendations = [];

  if (isAiAnalysisConfigured()) {
    try {
      if (typeof progressCallback === 'function') {
        await progressCallback(65);
      }

      const aiChunks = await buildAiReviewChunks(sourceFiles, preAiFindings);
      const securityContexts = retrieveSecurityContext(aiChunks, preAiFindings);
      console.log(
        `AI analysis enabled. Reviewing ${aiChunks.length} file chunk(s) with ${securityContexts.length} retrieved context item(s).`
      );

      const aiResult = await analyzeChunksWithAi(aiChunks, securityContexts);
      aiFindings = aiResult.vulnerabilities;
      topRecommendations = aiResult.topRecommendations;
      console.log(`AI analysis produced ${aiFindings.length} finding(s).`);

      if (typeof progressCallback === 'function') {
        await progressCallback(80);
      }
    } catch (error) {
      console.log(`AI analysis skipped after provider error: ${error.message}`);
      if (typeof progressCallback === 'function') {
        await progressCallback(70);
      }
    }
  } else {
    console.log('AI analysis disabled or not configured.');
    if (typeof progressCallback === 'function') {
      await progressCallback(70);
    }
  }

  const vulnerabilities = dedupeFindings([...preAiFindings, ...aiFindings]);
  await vulnerabilityRepository.createVulnerabilities(jobData.scanId, vulnerabilities);

  if (typeof progressCallback === 'function') {
    await progressCallback(90);
  }

  return {
    filesScanned: sourceFiles.length,
    astFindingCount: astFindings.length,
    dependencyFindingCount: dependencyFindings.length,
    vulnerabilityCount: vulnerabilities.length,
    securityScore: calculateSecurityScore(vulnerabilities),
    topRecommendations
  };
}

module.exports = { scanRepository };
