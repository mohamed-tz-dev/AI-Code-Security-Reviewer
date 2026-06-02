function buildFindingKey(finding) {
  if (finding.lineStart || finding.lineEnd) {
    return [
      finding.category,
      finding.filePath,
      finding.lineStart || '',
      finding.lineEnd || ''
    ].join('|');
  }

  return [
    finding.category,
    finding.filePath,
    finding.lineStart || '',
    finding.lineEnd || '',
    finding.title.replace(/^\[AI\]\s*/, '').toLowerCase()
  ].join('|');
}

function dedupeFindings(findings) {
  const seen = new Set();
  const deduped = [];

  for (const finding of findings) {
    const key = buildFindingKey(finding);

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
}

module.exports = { dedupeFindings };
