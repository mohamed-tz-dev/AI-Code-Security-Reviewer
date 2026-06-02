const OWASP_TOP_10 = {
  INJECTION: 'A01: Injection',
  AUTHENTICATION: 'A02: Broken Authentication',
  SENSITIVE_DATA: 'A03: Sensitive Data Exposure',
  INSECURE_DESIGN: 'A04: Insecure Design',
  SECURITY_MISCONFIGURATION: 'A05: Security Misconfiguration',
  VULNERABLE_COMPONENTS: 'A06: Vulnerable and Outdated Components',
  IDENTIFICATION_AUTHENTICATION: 'A07: Identification and Authentication Failures',
  SOFTWARE_INTEGRITY: 'A08: Software and Data Integrity Failures',
  LOGGING_MONITORING: 'A09: Security Logging and Monitoring Failures',
  SSRF: 'A10: Server-Side Request Forgery (SSRF)'
};

function mapToOwaspCategory(category = '', title = '') {
  const normalized = `${category || ''} ${title || ''}`.toLowerCase();

  if (/sql|injection|xss|csrf|command|ssrf|shell|unsafe api/.test(normalized)) {
    return OWASP_TOP_10.INJECTION;
  }

  if (/jwt|auth|authentication|authorize|login|session|token|credentials/.test(normalized)) {
    return OWASP_TOP_10.AUTHENTICATION;
  }

  if (/secret|token|password|credential|private key|api key|certificate|sensitive data|hardcoded/.test(normalized)) {
    return OWASP_TOP_10.SENSITIVE_DATA;
  }

  if (/misconfig|tls|certificate verification|security configuration|cors|header|unsafe apis?/.test(normalized)) {
    return OWASP_TOP_10.SECURITY_MISCONFIGURATION;
  }

  if (/dependency|library|package|outdated|lockfile|vulnerable component|known vulnerability|software component/.test(normalized)) {
    return OWASP_TOP_10.VULNERABLE_COMPONENTS;
  }

  if (/integrity|supply chain|signed package|package integrity|git commit/.test(normalized)) {
    return OWASP_TOP_10.SOFTWARE_INTEGRITY;
  }

  if (/logging|audit|monitor|trace|alert|review/.test(normalized)) {
    return OWASP_TOP_10.LOGGING_MONITORING;
  }

  if (/ssrf/.test(normalized)) {
    return OWASP_TOP_10.SSRF;
  }

  return OWASP_TOP_10.SECURITY_MISCONFIGURATION;
}

module.exports = { OWASP_TOP_10, mapToOwaspCategory };
