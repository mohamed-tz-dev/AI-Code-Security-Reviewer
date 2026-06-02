const path = require('path');

const RULES = [
  {
    id: 'hardcoded-aws-access-key',
    title: 'Hardcoded AWS access key',
    category: 'Hardcoded secrets',
    severity: 'critical',
    pattern: /AKIA[0-9A-Z]{16}/,
    recommendation: 'Remove the key from source code, rotate it immediately, and load credentials from a secret manager or environment variables.'
  },
  {
    id: 'hardcoded-private-key',
    title: 'Private key committed to source',
    category: 'Hardcoded secrets',
    severity: 'critical',
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    recommendation: 'Remove the private key from the repository, rotate affected credentials, and store private keys outside source control.'
  },
  {
    id: 'hardcoded-token-assignment',
    title: 'Possible hardcoded secret',
    category: 'Hardcoded secrets',
    severity: 'high',
    pattern: /(api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"]{12,}['"]/i,
    recommendation: 'Move secrets to environment variables or a secret manager and rotate any exposed values.'
  },
  {
    id: 'sql-string-concatenation',
    title: 'Possible SQL injection through string concatenation',
    category: 'SQL Injection',
    severity: 'high',
    pattern: /(select|insert|update|delete).{0,120}(\+|\$\{|%s|format\()/i,
    recommendation: 'Use parameterized queries or prepared statements instead of building SQL with user-controlled strings.'
  },
  {
    id: 'command-exec',
    title: 'Possible command injection sink',
    category: 'Command injection',
    severity: 'high',
    pattern: /\b(exec|execSync|spawn|spawnSync|system|shell_exec|passthru|popen|subprocess\.Popen|os\.system)\s*\(/,
    recommendation: 'Avoid shell execution for user-controlled input. Use allowlisted arguments and APIs that do not invoke a shell.'
  },
  {
    id: 'dangerous-eval',
    title: 'Dynamic code execution',
    category: 'Unsafe APIs',
    severity: 'high',
    pattern: /\b(eval|Function)\s*\(/,
    recommendation: 'Remove dynamic code execution or replace it with a safe parser or explicit command mapping.'
  },
  {
    id: 'dom-xss-inner-html',
    title: 'Potential DOM XSS through innerHTML',
    category: 'XSS',
    severity: 'medium',
    pattern: /\.innerHTML\s*=/,
    recommendation: 'Use safe text APIs such as textContent or sanitize trusted HTML with a proven sanitizer.'
  },
  {
    id: 'xss-dangerously-set-inner-html',
    title: 'Potential React XSS sink',
    category: 'XSS',
    severity: 'medium',
    pattern: /dangerouslySetInnerHTML/,
    recommendation: 'Avoid raw HTML rendering. If unavoidable, sanitize content before rendering.'
  },
  {
    id: 'jwt-without-expiry',
    title: 'JWT signing may miss expiry',
    category: 'Authentication issues',
    severity: 'medium',
    pattern: /jwt\.sign\s*\([^)]*\)/,
    recommendation: 'Ensure JWTs include short expirations, audience, issuer, and strong signing secrets.'
  },
  {
    id: 'disabled-tls-verification',
    title: 'TLS certificate verification disabled',
    category: 'Unsafe APIs',
    severity: 'critical',
    pattern: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"])/,
    recommendation: 'Keep TLS certificate verification enabled and fix certificate trust issues directly.'
  }
];

function shouldSkipRuleForFile(ruleId, relativePath) {
  const extension = path.extname(relativePath).toLowerCase();

  if (ruleId === 'jwt-without-expiry') {
    return !['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(extension);
  }

  return false;
}

function scanFileWithStaticRules(sourceFile, content) {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];

    for (const rule of RULES) {
      if (shouldSkipRuleForFile(rule.id, sourceFile.relativePath)) {
        continue;
      }

      if (!rule.pattern.test(line)) {
        continue;
      }

      findings.push({
        title: rule.title,
        category: rule.category,
        severity: rule.severity,
        filePath: sourceFile.relativePath,
        lineStart: lineIndex + 1,
        lineEnd: lineIndex + 1,
        description: `Static analysis matched rule ${rule.id}. Review the code path to confirm whether user-controlled data reaches this sink or secret value.`,
        recommendation: rule.recommendation,
        evidence: line.trim().slice(0, 500),
        confidence: 0.7
      });
    }
  }

  return findings;
}

module.exports = { scanFileWithStaticRules };
