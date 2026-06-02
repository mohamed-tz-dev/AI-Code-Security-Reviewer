const { z } = require('zod');

const { env } = require('../config/env');

const aiFindingSchema = z.object({
  title: z.string().min(1).max(160),
  category: z.enum([
    'SQL Injection',
    'XSS',
    'Hardcoded secrets',
    'Command injection',
    'Unsafe APIs',
    'Authentication issues'
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  filePath: z.string().min(1),
  lineStart: z.number().int().positive().nullable(),
  lineEnd: z.number().int().positive().nullable(),
  description: z.string().min(1).max(1200),
  recommendation: z.string().min(1).max(1200),
  evidence: z.string().max(500).nullable(),
  confidence: z.number().min(0).max(1),
  why: z.string().max(1200).optional(),
  attackScenario: z.string().max(1200).optional(),
  securePatch: z.string().max(1200).optional()
});

const aiResponseSchema = z.object({
  vulnerabilities: z.array(aiFindingSchema).max(50),
  topRecommendations: z.array(z.string().max(200)).max(5).optional()
});

const responseJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['vulnerabilities'],
  properties: {
    vulnerabilities: {
      type: 'array',
      maxItems: 50,
      items: {
        type: 'object',
        additionalProperties: false,
        required: [
          'title',
          'category',
          'severity',
          'filePath',
          'lineStart',
          'lineEnd',
          'description',
          'recommendation',
          'evidence',
          'confidence'
        ],
        properties: {
          title: { type: 'string' },
          category: {
            type: 'string',
            enum: [
              'SQL Injection',
              'XSS',
              'Hardcoded secrets',
              'Command injection',
              'Unsafe APIs',
              'Authentication issues'
            ]
          },
          severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'info']
          },
          filePath: { type: 'string' },
          lineStart: { type: ['integer', 'null'] },
          lineEnd: { type: ['integer', 'null'] },
          description: { type: 'string' },
          recommendation: { type: 'string' },
          evidence: { type: ['string', 'null'] },
          confidence: { type: 'number', minimum: 0, maximum: 1 },
          why: { type: 'string' },
          attackScenario: { type: 'string' },
          securePatch: { type: 'string' }
        }
      }
    },
    topRecommendations: {
      type: 'array',
      maxItems: 5,
      items: { type: 'string', maxLength: 200 }
    }
  }
};

function isAiAnalysisConfigured() {
  if (!env.aiAnalysisEnabled) {
    return false;
  }

  if (env.aiProvider === 'openai') {
    return Boolean(env.openAiApiKey);
  }

  if (env.aiProvider === 'ollama') {
    return Boolean(env.ollamaBaseUrl && env.ollamaModel);
  }

  if (env.aiProvider === 'groq') {
    return Boolean(env.groqApiKey && env.groqModel);
  }

  return false;
}

function buildAiPrompt(chunks, securityContexts = []) {
  const files = chunks
    .map((chunk) => {
      const truncationNote = chunk.truncated
        ? '\nNOTE: This file was truncated for review.'
        : '';

      return `FILE: ${chunk.filePath}${truncationNote}\n${chunk.content}`;
    })
    .join('\n\n---\n\n');
  const retrievedContext = securityContexts.length > 0
    ? securityContexts
        .map((context) => {
          return `- ${context.title}: ${context.guidance}`;
        })
        .join('\n')
    : '- No additional retrieved context.';

  return `
Review these repository files for real, exploitable application security issues.

Focus only on:
- SQL Injection
- XSS
- Hardcoded secrets
- Command injection
- Unsafe APIs
- Authentication issues

For each finding, provide:
- why this is a vulnerability,
- a likely attack scenario,
- a secure remediation or implementation,
- a concrete secure patch example when possible.

Rules:
- Do not invent findings.
- Do not report style, maintainability, dependency, or generic best-practice issues.
- Do not include secrets in full; redact long secret-like evidence.
- Use the provided line numbers when possible.
- Return only findings supported by visible code.
- Add a root field named topRecommendations containing the top 5 repository-wide security improvements.

Retrieved security knowledge:
${retrievedContext}

Repository files:

${files}
`.trim();
}

function extractResponseText(responseBody) {
  if (typeof responseBody.output_text === 'string') {
    return responseBody.output_text;
  }

  const message = responseBody.output?.find((item) => item.type === 'message');
  const textContent = message?.content?.find((item) => item.type === 'output_text');

  return textContent?.text || '';
}

function extractJsonObject(text) {
  const trimmed = text.trim();

  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    return trimmed;
  }

  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');

  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
    throw new Error('AI provider did not return a JSON object.');
  }

  return trimmed.slice(firstBrace, lastBrace + 1);
}

function normalizeAiFindings(parsedResponse, allowedFilePaths) {
  return parsedResponse.vulnerabilities
    .filter((finding) => allowedFilePaths.has(finding.filePath))
    .map((finding) => ({
      title: `[AI] ${finding.title}`,
      category: finding.category,
      severity: finding.severity,
      filePath: finding.filePath,
      lineStart: finding.lineStart,
      lineEnd: finding.lineEnd,
      description: finding.description,
      recommendation: finding.recommendation,
      evidence: finding.evidence ? finding.evidence.slice(0, 500) : null,
      confidence: finding.confidence,
      why: finding.why || null,
      attackScenario: finding.attackScenario || null,
      securePatch: finding.securePatch || null
    }));
}

async function analyzeWithOllama(chunks, securityContexts) {
  const headers = {
    'Content-Type': 'application/json'
  };

  if (env.ollamaApiKey) {
    headers.Authorization = `Bearer ${env.ollamaApiKey}`;
  }

  const response = await fetch(`${env.ollamaBaseUrl}/api/chat`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: env.ollamaModel,
      stream: false,
      format: 'json',
      options: {
        temperature: 0.1,
        num_ctx: 1024,
        num_predict: 3000
      },
      messages: [
        {
          role: 'system',
          content:
            'You are a senior application security reviewer. Return only valid JSON matching this shape: {"vulnerabilities":[{"title":"string","category":"SQL Injection|XSS|Hardcoded secrets|Command injection|Unsafe APIs|Authentication issues","severity":"critical|high|medium|low|info","filePath":"string","lineStart":1,"lineEnd":1,"description":"string","recommendation":"string","evidence":"string or null","confidence":0.7,"why":"string","attackScenario":"string","securePatch":"string"}],"topRecommendations":["string"]}. If there are no findings, return {"vulnerabilities":[],"topRecommendations":[]}. '
        },
        {
          role: 'user',
          content: buildAiPrompt(chunks, securityContexts)
        }
      ]
    })
  });

  if (!response.ok) {
    const errorBody = await response.text();
    const genericError = `Ollama analysis failed: ${response.status} ${errorBody.slice(0, 300)}`;
    if (response.status === 404 && /model .* not found/i.test(errorBody)) {
      throw new Error(
        `${genericError}. The configured OLLAMA_MODEL "${env.ollamaModel || 'unset'}" was not found. Install or pull the model locally, or update the model name in settings.`
      );
    }
    throw new Error(genericError);
  }

  const responseBody = await response.json();
  const responseText = responseBody.message?.content || responseBody.response || '';
  return JSON.parse(extractJsonObject(responseText));
}

async function getAvailableGroqModels() {
  const response = await fetch('https://api.groq.com/openai/v1/models', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${env.groqApiKey}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    return [];
  }

  const responseBody = await response.json();
  return Array.isArray(responseBody.data)
    ? responseBody.data.map((item) => item.id || item.name).filter(Boolean)
    : [];
}

async function analyzeWithGroq(chunks, securityContexts) {
  const executeRequest = async (modelName) => {
    return await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.groqApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: modelName,
        messages: [
          {
            role: 'system',
            content:
              'You are a senior application security reviewer. Return only valid JSON matching this shape: {"vulnerabilities":[{"title":"string","category":"SQL Injection|XSS|Hardcoded secrets|Command injection|Unsafe APIs|Authentication issues","severity":"critical|high|medium|low|info","filePath":"string","lineStart":1,"lineEnd":1,"description":"string","recommendation":"string","evidence":"string or null","confidence":0.7,"why":"string","attackScenario":"string","securePatch":"string"}],"topRecommendations":["string"]}. If there are no findings, return {"vulnerabilities":[],"topRecommendations":[]}. '
          },
          {
            role: 'user',
            content: buildAiPrompt(chunks, securityContexts)
          }
        ],
        temperature: 0.1,
        max_tokens: 3000
      })
    });
  };

  let response = await executeRequest(env.groqModel);
  if (!response.ok) {
    const errorBody = await response.text();
    const genericError = `GroqCloud analysis failed: ${response.status} ${errorBody.slice(0, 300)}`;
    if (response.status === 401 || response.status === 403) {
      throw new Error(`${genericError}. Check GROQ_CLOUD_API_KEY and ensure the key is valid for GroqCloud.`);
    }
    if (
      response.status === 404 &&
      (/model .* not found/i.test(errorBody) || /does not exist/i.test(errorBody))
    ) {
      const availableModels = await getAvailableGroqModels();
      const preferredModels = [
        env.groqModel,
        'openai/gpt-oss-20b',
        'groq/compound',
        'llama-3.1-8b-instant',
        'llama-3.3-70b-versatile'
      ].filter(Boolean);
      const alternativeModel = preferredModels.find((name) => availableModels.includes(name) && name !== env.groqModel);
      if (alternativeModel) {
        response = await executeRequest(alternativeModel);
        if (response.ok) {
          const responseBody = await response.json();
          const groqText = responseBody.choices?.[0]?.message?.content || '';
          if (!groqText) {
            throw new Error('GroqCloud analysis failed: no text output returned.');
          }
          return JSON.parse(extractJsonObject(groqText));
        }
      }
      throw new Error(
        `${genericError}. The configured GROQ_CLOUD_MODEL "${env.groqModel || 'unset'}" was not found. Available models: ${availableModels.join(', ') || 'none'}.`
      );
    }
    throw new Error(genericError);
  }

  const responseBody = await response.json();
  const groqText = responseBody.choices?.[0]?.message?.content || '';

  if (!groqText) {
    throw new Error('GroqCloud analysis failed: no text output returned.');
  }

  return JSON.parse(extractJsonObject(groqText));
}

async function analyzeWithOpenAi(chunks, securityContexts) {
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.openAiApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: env.openAiModel,
      instructions:
        'You are a senior application security reviewer. Produce concise, evidence-backed vulnerability findings as structured JSON.',
      input: buildAiPrompt(chunks, securityContexts),
      max_output_tokens: 3000,
      text: {
        format: {
          type: 'json_schema',
          name: 'security_findings',
          strict: true,
          schema: responseJsonSchema
        }
      }
    })
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`OpenAI analysis failed: ${response.status} ${errorBody.slice(0, 300)}`);
  }

  const responseBody = await response.json();
  const responseText = extractResponseText(responseBody);
  return JSON.parse(extractJsonObject(responseText));
}

async function analyzeChunksWithAi(chunks, securityContexts = []) {
  if (!isAiAnalysisConfigured() || chunks.length === 0) {
    return { vulnerabilities: [], topRecommendations: [] };
  }

  const parsedJson = env.aiProvider === 'ollama'
    ? await analyzeWithOllama(chunks, securityContexts)
    : env.aiProvider === 'groq'
      ? await analyzeWithGroq(chunks, securityContexts)
      : await analyzeWithOpenAi(chunks, securityContexts);

  const parsedResponse = aiResponseSchema.parse(parsedJson);
  const allowedFilePaths = new Set(chunks.map((chunk) => chunk.filePath));

  return {
    vulnerabilities: normalizeAiFindings(parsedResponse, allowedFilePaths),
    topRecommendations: parsedResponse.topRecommendations || []
  };
}

module.exports = {
  analyzeChunksWithAi,
  isAiAnalysisConfigured
};
