const { SECURITY_KNOWLEDGE } = require('./security-knowledge');

function tokenize(value) {
  return new Set(
    String(value)
      .toLowerCase()
      .split(/[^a-z0-9_.-]+/)
      .filter((token) => token.length > 2)
  );
}

function scoreDocument(document, queryTokens, categories) {
  let score = 0;

  for (const keyword of document.keywords) {
    if (queryTokens.has(keyword.toLowerCase())) {
      score += 3;
    }
  }

  for (const category of document.categories) {
    if (categories.has(category)) {
      score += 5;
    }
  }

  return score;
}

function retrieveSecurityContext(chunks, findings, limit = 4) {
  const query = [
    ...chunks.map((chunk) => `${chunk.filePath}\n${chunk.content}`),
    ...findings.map((finding) => `${finding.category} ${finding.title} ${finding.evidence || ''}`)
  ].join('\n');
  const queryTokens = tokenize(query);
  const categories = new Set(findings.map((finding) => finding.category));

  return SECURITY_KNOWLEDGE
    .map((document) => ({
      ...document,
      score: scoreDocument(document, queryTokens, categories)
    }))
    .filter((document) => document.score > 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, limit)
    .map(({ score: _score, ...document }) => document);
}

module.exports = { retrieveSecurityContext };
