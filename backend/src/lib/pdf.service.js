function escapePdfText(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\r?\n/g, ' ');
}

function wrapText(text, maxLength = 92) {
  const words = String(text ?? '').split(/\s+/).filter(Boolean);
  const lines = [];
  let currentLine = '';

  for (const word of words) {
    if (`${currentLine} ${word}`.trim().length > maxLength) {
      if (currentLine) lines.push(currentLine);
      currentLine = word;
    } else {
      currentLine = `${currentLine} ${word}`.trim();
    }
  }

  if (currentLine) lines.push(currentLine);
  return lines.length > 0 ? lines : [''];
}

function buildPdfContent(lines) {
  let y = 760;
  const content = ['BT', '/F1 11 Tf'];

  for (const line of lines) {
    if (y < 40) break;
    content.push(`50 ${y} Td (${escapePdfText(line)}) Tj`);
    y -= 16;
    content.push(`-50 -${760 - y} Td`);
  }

  content.push('ET');
  return content.join('\n');
}

function createSimplePdf(lines) {
  const content = buildPdfContent(lines);
  const objects = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
    `5 0 obj\n<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream\nendobj\n`
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [0];

  for (const object of objects) {
    offsets.push(Buffer.byteLength(pdf));
    pdf += object;
  }

  const xrefOffset = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';

  for (let index = 1; index < offsets.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, '0')} 00000 n \n`;
  }

  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(pdf, 'utf8');
}

const { env } = require('../config/env');

function createScanReportPdf(scan) {
  const severityCounts = scan.vulnerabilities.reduce(
    (counts, vulnerability) => {
      counts[vulnerability.severity] = (counts[vulnerability.severity] || 0) + 1;
      return counts;
    },
    {}
  );

  const lines = [
    'AI Code Security Reviewer',
    'Enterprise Security Assessment',
    '',
    `Project: ${scan.project_name}`,
    `Status: ${scan.status}`,
    `Security score: ${scan.security_score ?? '-'} / 100`,
    `Source: ${scan.source_type}`,
    `Owner: ${scan.user_email || scan.user_id || 'unknown'}`,
    `Created: ${scan.created_at}`,
    `Completed: ${scan.completed_at || '-'}`,
    `Organization: ${scan.organization_id || 'none'}`,
    `Team: ${scan.team_id || 'none'}`,
    '',
    'Executive summary:',
    `- Total findings: ${scan.vulnerabilities.length}`,
    `- Critical: ${severityCounts.critical || 0}`,
    `- High: ${severityCounts.high || 0}`,
    `- Medium: ${severityCounts.medium || 0}`,
    `- Low: ${severityCounts.low || 0}`,
    `- Info: ${severityCounts.info || 0}`,
    ''
  ];

  if (scan.ai_recommendations) {
    lines.push('Top AI recommendations:');
    for (const recommendation of scan.ai_recommendations.split(/\r?\n/).filter(Boolean)) {
      lines.push(`- ${recommendation}`);
    }
    lines.push('');
  }

  lines.push('Platform configuration:');
  lines.push(`- AI analysis enabled: ${env.aiAnalysisEnabled ? 'yes' : 'no'}`);
  lines.push(`- AI provider: ${env.aiProvider}`);
  lines.push(`- Model integration key: ${env.aiProvider === 'openai' ? 'OPENAI_API_KEY' : env.aiProvider === 'ollama' ? 'OLLAMA_API_KEY / OLLAMA_BASE_URL' : 'GROQ_CLOUD_API_KEY'}`);
  lines.push('');
  lines.push('Report notes:');
  lines.push('- This PDF summarizes scan results and platform configuration.');
  lines.push('- Interactive chat sessions, user settings pages, and live UI history are not included in this export.');
  lines.push('- Use the application dashboard for user settings, chat history, and integration setup pages.');
  lines.push('');

  lines.push('Detailed findings:');
  lines.push('');

  for (const finding of scan.vulnerabilities) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`File: ${finding.file_path}${finding.line_start ? `:${finding.line_start}` : ''}`);
    lines.push(...wrapText(`Description: ${finding.description}`));
    lines.push(...wrapText(`Recommendation: ${finding.recommendation}`));
    if (finding.ai_why) {
      lines.push(...wrapText(`Why: ${finding.ai_why}`));
    }
    if (finding.attack_scenario) {
      lines.push(...wrapText(`Attack scenario: ${finding.attack_scenario}`));
    }
    if (finding.secure_patch) {
      lines.push(...wrapText(`Secure patch: ${finding.secure_patch}`));
    }
    if (finding.evidence) {
      lines.push(...wrapText(`Evidence: ${finding.evidence}`));
    }
    lines.push('');
  }

  return createSimplePdf(lines);
}

module.exports = { createScanReportPdf };
