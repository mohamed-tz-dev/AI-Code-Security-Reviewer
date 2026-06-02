const path = require('path');

const JS_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
let hasLoggedMissingParser = false;

function loadParser() {
  try {
    return require('@babel/parser');
  } catch (_error) {
    if (!hasLoggedMissingParser) {
      console.log('AST analysis disabled: install @babel/parser to enable JavaScript/TypeScript AST rules.');
      hasLoggedMissingParser = true;
    }
    return null;
  }
}

function getNodeName(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'Super') return 'super';
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'NumericLiteral') return String(node.value);
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    return [getNodeName(node.object), getNodeName(node.property)].filter(Boolean).join('.');
  }
  return '';
}

function isDynamicString(node) {
  return ['BinaryExpression', 'TemplateLiteral'].includes(node?.type);
}

function isFalseLiteral(node) {
  return node?.type === 'BooleanLiteral' && node.value === false;
}

function buildFinding({ sourceFile, node, title, category, severity, description, recommendation, evidence }) {
  return {
    title,
    category,
    severity,
    filePath: sourceFile.relativePath,
    lineStart: node.loc?.start?.line || null,
    lineEnd: node.loc?.end?.line || node.loc?.start?.line || null,
    description,
    recommendation,
    evidence: evidence ? evidence.slice(0, 500) : null,
    confidence: 0.82
  };
}

function walkAst(node, visitor, parent = null) {
  if (!node || typeof node !== 'object') return;

  visitor(node, parent);

  for (const key of Object.keys(node)) {
    if (['loc', 'start', 'end', 'extra', 'leadingComments', 'trailingComments'].includes(key)) {
      continue;
    }

    const value = node[key];

    if (Array.isArray(value)) {
      for (const child of value) {
        if (child?.type) walkAst(child, visitor, node);
      }
      continue;
    }

    if (value?.type) {
      walkAst(value, visitor, node);
    }
  }
}

function getLine(content, lineNumber) {
  if (!lineNumber) return null;
  return content.split(/\r?\n/)[lineNumber - 1]?.trim() || null;
}

function scanJavaScriptAst(sourceFile, content) {
  const extension = path.extname(sourceFile.relativePath).toLowerCase();
  if (!JS_EXTENSIONS.has(extension)) {
    return [];
  }

  const parser = loadParser();
  if (!parser) {
    return [];
  }

  let ast;
  try {
    ast = parser.parse(content, {
      sourceType: 'unambiguous',
      errorRecovery: true,
      plugins: [
        'jsx',
        'typescript',
        'classProperties',
        'decorators-legacy',
        'dynamicImport',
        'objectRestSpread',
        'optionalChaining',
        'topLevelAwait'
      ]
    });
  } catch (_error) {
    return [];
  }

  const findings = [];

  walkAst(ast, (node) => {
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
      const calleeName = getNodeName(node.callee);
      const firstArgument = node.arguments?.[0];

      if (['eval', 'Function'].includes(calleeName)) {
        findings.push(
          buildFinding({
            sourceFile,
            node,
            title: 'AST: dynamic code execution',
            category: 'Unsafe APIs',
            severity: 'high',
            description: 'AST analysis found dynamic code execution. This can execute attacker-controlled input if data reaches this call.',
            recommendation: 'Remove dynamic execution and replace it with explicit parsing or allowlisted behavior.',
            evidence: getLine(content, node.loc?.start?.line)
          })
        );
      }

      if (['exec', 'execSync', 'child_process.exec', 'child_process.execSync'].includes(calleeName)) {
        findings.push(
          buildFinding({
            sourceFile,
            node,
            title: 'AST: command execution sink',
            category: 'Command injection',
            severity: 'high',
            description: 'AST analysis found a shell command execution sink. Dynamic arguments can lead to command injection.',
            recommendation: 'Avoid shell execution, or pass allowlisted arguments to APIs that do not invoke a shell.',
            evidence: getLine(content, node.loc?.start?.line)
          })
        );
      }

      if (/\.(query|execute|raw)$/.test(calleeName) && isDynamicString(firstArgument)) {
        findings.push(
          buildFinding({
            sourceFile,
            node,
            title: 'AST: dynamic SQL query',
            category: 'SQL Injection',
            severity: 'high',
            description: 'AST analysis found a database query built from a dynamic string.',
            recommendation: 'Use parameterized queries or prepared statements.',
            evidence: getLine(content, node.loc?.start?.line)
          })
        );
      }

      if (calleeName === 'jwt.sign' && node.arguments?.length < 3) {
        findings.push(
          buildFinding({
            sourceFile,
            node,
            title: 'AST: JWT signing without options',
            category: 'Authentication issues',
            severity: 'medium',
            description: 'AST analysis found JWT signing without explicit options such as expiration, issuer, and audience.',
            recommendation: 'Set short expiration, issuer, audience, and use a strong secret or private key.',
            evidence: getLine(content, node.loc?.start?.line)
          })
        );
      }
    }

    if (node.type === 'AssignmentExpression') {
      const leftName = getNodeName(node.left);
      if (leftName.endsWith('.innerHTML')) {
        findings.push(
          buildFinding({
            sourceFile,
            node,
            title: 'AST: DOM XSS sink',
            category: 'XSS',
            severity: 'medium',
            description: 'AST analysis found assignment to innerHTML, which can create DOM XSS when fed untrusted input.',
            recommendation: 'Use textContent or sanitize trusted HTML before rendering.',
            evidence: getLine(content, node.loc?.start?.line)
          })
        );
      }
    }

    if (node.type === 'ObjectProperty' || node.type === 'ObjectMethod') {
      const keyName = getNodeName(node.key);
      if (keyName === 'rejectUnauthorized' && isFalseLiteral(node.value)) {
        findings.push(
          buildFinding({
            sourceFile,
            node,
            title: 'AST: TLS verification disabled',
            category: 'Unsafe APIs',
            severity: 'critical',
            description: 'AST analysis found TLS certificate verification disabled.',
            recommendation: 'Keep certificate verification enabled and fix certificate trust issues directly.',
            evidence: getLine(content, node.loc?.start?.line)
          })
        );
      }
    }
  });

  return findings;
}

module.exports = { scanJavaScriptAst };
