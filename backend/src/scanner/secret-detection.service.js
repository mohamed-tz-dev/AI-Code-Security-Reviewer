const { mapToOwaspCategory } = require('./owasp-map');

const SECRET_PATTERNS = [
  {
    id: 'hardcoded-api-secret',
    title: 'Possible hardcoded API secret',
    severity: 'high',
    category: 'Hardcoded secrets',
    pattern: /(api[_-]?key|app[_-]?secret|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*['"][^'\"]{16,120}['"]/i,
    recommendation: 'Move hardcoded credentials to secure environment variables or a secret vault and rotate exposed secrets.'
  },
  {
    id: 'hardcoded-github-token',
    title: 'Possible GitHub personal access token',
    severity: 'high',
    category: 'Hardcoded secrets',
    pattern: /gh[pousr]_[A-Za-z0-9_]{20,}/,
    recommendation: 'Remove this token from source control and rotate the secret immediately.'
  },
  {
    id: 'hardcoded-slack-token',
    title: 'Possible Slack token',
    severity: 'high',
    category: 'Hardcoded secrets',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/,
    recommendation: 'Remove the Slack token from repository files and store it in a secrets manager.'
  },
  {
    id: 'hardcoded-aws-key',
    title: 'Possible AWS credential',
    severity: 'critical',
    category: 'Hardcoded secrets',
    pattern: /\b(AKIA|ASIA|ACCA|AGPA|AIDA|ANPA|AROA|AIPA)[0-9A-Z]{16}\b/,
    recommendation: 'Do not commit AWS access keys. Use IAM roles, instance profiles, or environment-based credentials instead.'
  },
  {
    id: 'hardcoded-private-key',
    title: 'Possible private key material',
    severity: 'critical',
    category: 'Hardcoded secrets',
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    recommendation: 'Remove private keys from source control and store them securely in an external key vault.'
  }
];

function scanFileWithSecretPatterns(sourceFile, content) {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];

    for (const rule of SECRET_PATTERNS) {
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
        description: `Secret detection matched rule ${rule.id}. Confirm whether this value is sensitive data and remove it from source control.`,
        recommendation: rule.recommendation,
        evidence: line.trim().slice(0, 500),
        confidence: 0.78,
        owasp_category: mapToOwaspCategory(rule.category, rule.title)
      });
    }
  }

  return findings;
}

module.exports = { scanFileWithSecretPatterns };
