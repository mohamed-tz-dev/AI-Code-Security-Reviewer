const path = require('path');
const { spawn, spawnSync } = require('child_process');

const PYTHON_COMMANDS = ['python', 'python3', 'py'];
let cachedPythonCommand;
let hasLoggedMissingPython = false;

function findPythonCommand() {
  if (cachedPythonCommand !== undefined) {
    return cachedPythonCommand;
  }

  cachedPythonCommand = null;

  for (const command of PYTHON_COMMANDS) {
    const result = spawnSync(command, ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });

    if (result.status === 0) {
      cachedPythonCommand = command;
      break;
    }
  }

  if (!cachedPythonCommand && !hasLoggedMissingPython) {
    console.log('Python AST analysis disabled: install Python and ensure it is available on PATH.');
    hasLoggedMissingPython = true;
  }

  return cachedPythonCommand;
}

function normalizePythonFinding(sourceFile, finding) {
  return {
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    filePath: sourceFile.relativePath,
    lineStart: finding.lineStart,
    lineEnd: finding.lineEnd,
    description: finding.description,
    recommendation: finding.recommendation,
    evidence: finding.evidence ? finding.evidence.slice(0, 500) : null,
    confidence: finding.confidence || 0.82
  };
}

async function runPythonAstScanner(command, content) {
  const scriptPath = path.resolve(__dirname, '..', '..', 'scripts', 'python_ast_scanner.py');

  return new Promise((resolve, reject) => {
    const child = spawn(command, [scriptPath], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error('Python AST scanner timed out.'));
    }, 10000);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on('close', (code) => {
      clearTimeout(timeout);

      if (code !== 0) {
        reject(new Error(stderr.trim() || `Python AST scanner exited with code ${code}`));
        return;
      }

      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        reject(error);
      }
    });

    child.stdin.end(content);
  });
}

async function scanPythonAst(sourceFile, content) {
  if (path.extname(sourceFile.relativePath).toLowerCase() !== '.py') {
    return [];
  }

  const command = findPythonCommand();
  if (!command) {
    return [];
  }

  try {
    const result = await runPythonAstScanner(command, content);
    return (result.findings || []).map((finding) => normalizePythonFinding(sourceFile, finding));
  } catch (error) {
    console.log(`Python AST analysis skipped for ${sourceFile.relativePath}: ${error.message}`);
    return [];
  }
}

module.exports = { scanPythonAst };
