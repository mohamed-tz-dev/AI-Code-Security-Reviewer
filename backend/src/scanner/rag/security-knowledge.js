const SECURITY_KNOWLEDGE = [
  {
    id: 'sql-injection-parameterization',
    title: 'SQL Injection: parameterized queries',
    categories: ['SQL Injection'],
    keywords: ['sql', 'query', 'select', 'insert', 'update', 'delete', 'where', 'db.query'],
    guidance:
      'SQL queries must not be built by concatenating user-controlled values. Prefer prepared statements or parameterized query APIs.'
  },
  {
    id: 'xss-output-encoding',
    title: 'XSS: unsafe HTML sinks',
    categories: ['XSS'],
    keywords: ['innerHTML', 'dangerouslySetInnerHTML', 'document.write', 'html', 'sanitize'],
    guidance:
      'Raw HTML sinks require strict sanitization. Prefer textContent or framework-safe rendering for untrusted content.'
  },
  {
    id: 'command-injection-shell',
    title: 'Command Injection: shell execution',
    categories: ['Command injection'],
    keywords: ['exec', 'spawn', 'shell', 'child_process', 'os.system', 'subprocess'],
    guidance:
      'Avoid passing user input to shell commands. Use allowlisted arguments and APIs that do not invoke a shell.'
  },
  {
    id: 'secret-management',
    title: 'Hardcoded Secrets: credential handling',
    categories: ['Hardcoded secrets'],
    keywords: ['secret', 'token', 'password', 'apiKey', 'private key', 'credential'],
    guidance:
      'Secrets should not be committed to source code. Rotate exposed credentials and load them from environment variables or a secret manager.'
  },
  {
    id: 'jwt-session-hardening',
    title: 'Authentication: JWT hardening',
    categories: ['Authentication issues'],
    keywords: ['jwt', 'sign', 'token', 'session', 'login', 'auth'],
    guidance:
      'JWTs should include short expiration, issuer, audience, and strong signing keys. Avoid weak hardcoded secrets.'
  },
  {
    id: 'tls-verification',
    title: 'Unsafe APIs: TLS verification',
    categories: ['Unsafe APIs'],
    keywords: ['rejectUnauthorized', 'NODE_TLS_REJECT_UNAUTHORIZED', 'https', 'certificate', 'tls'],
    guidance:
      'Disabling TLS certificate verification enables man-in-the-middle attacks. Keep verification enabled.'
  }
];

module.exports = { SECURITY_KNOWLEDGE };
