const severityWeights = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1
};

function calculateSecurityScore(vulnerabilities) {
  const penalty = vulnerabilities.reduce((total, vulnerability) => {
    return total + (severityWeights[vulnerability.severity] || 0);
  }, 0);

  return Math.max(0, 100 - penalty);
}

module.exports = { calculateSecurityScore };
