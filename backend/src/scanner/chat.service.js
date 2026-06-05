const { env } = require('../config/env');

function isChatConfigured() {
  return env.aiAnalysisEnabled && (
    (env.aiProvider === 'openai' && env.openAiApiKey) ||
    (env.aiProvider === 'ollama' && env.ollamaBaseUrl && env.ollamaModel) ||
    (env.aiProvider === 'groq' && env.groqApiKey && env.groqModel)
  );
}

function buildChatPrompt(question, scan) {
  const summary = scan
    ? [
        `Project: ${scan.project_name}`,
        `Status: ${scan.status}`,
        `Security score: ${scan.security_score ?? 'unknown'}`,
        `Findings: ${scan.vulnerabilities?.length ?? 0}`,
        scan.vulnerabilities && scan.vulnerabilities.length > 0
          ? scan.vulnerabilities
              .slice(0, 10)
              .map((item, index) =>
                `  ${index + 1}. ${item.severity.toUpperCase()} - ${item.title} (${item.filePath}${item.lineStart ? `:${item.lineStart}` : ''})\n      Recommendation: ${item.recommendation || 'No recommendation provided.'}`
              )
              .join('\n')
          : '  No findings available.'
      ].join('\n')
    : 'No scan selected.';

  return `You are an expert application security reviewer.

Use the following scan summary to answer the user question concisely and accurately.

${summary}

Question: ${question}

When answering, do the following:
- Be precise and keep the response short.
- Reference scan findings only when the question is about the scan.
- If the question is general, answer with general security guidance.
- Use plain English and avoid vague claims.

Answer:`;
}

function extractResponseText(responseBody) {
  if (!responseBody) {
    return '';
  }

  if (typeof responseBody.output_text === 'string') {
    return responseBody.output_text;
  }

  const output = responseBody.output || [];
  if (Array.isArray(output) && output.length > 0) {
    const first = output[0];
    if (first?.content) {
      return first.content
        .map((item) => item?.text || '')
        .filter(Boolean)
        .join('\n');
    }
  }

  if (typeof responseBody.response === 'string') {
    return responseBody.response;
  }

  if (typeof responseBody.text === 'string') {
    return responseBody.text;
  }

  return '';
}

async function askWithOpenAi(prompt) {
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.openAiApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: env.openAiModel,
      input: prompt,
      max_output_tokens: 800,
      temperature: 0.2
    })
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`OpenAI chat failed: ${response.status} ${errorBody.slice(0, 300)}`);
  }

  const responseBody = await response.json();
  return extractResponseText(responseBody).trim();
}

async function askWithOllama(prompt) {
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
      messages: [
        {
          role: 'system',
          content: 'You are an expert application security reviewer.'
        },
        {
          role: 'user',
          content: prompt
        }
      ]
    })
  });

  if (!response.ok) {
    const errorBody = await response.text();
    const genericError = `Ollama chat failed: ${response.status} ${errorBody.slice(0, 300)}`;
    if (response.status === 404 && /model .* not found/i.test(errorBody)) {
      throw new Error(
        `${genericError}. The configured OLLAMA_MODEL "${env.ollamaModel || 'unset'}" was not found. Install or pull the model locally, or update the model name in settings.`
      );
    }
    throw new Error(genericError);
  }

  const responseBody = await response.json();
  return extractResponseText(responseBody).trim();
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

async function askWithGroq(prompt) {
  const preferredModels = [
    env.groqModel,
    'openai/gpt-oss-20b',
    'groq/compound',
    'llama-3.1-8b-instant',
    'llama-3.3-70b-versatile'
  ].filter(Boolean);

  const executeRequest = async (modelName) => {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
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
            content: 'You are an expert application security reviewer.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.2,
        max_tokens: 800
      })
    });

    return response;
  };

  let response = await executeRequest(env.groqModel);
  if (!response.ok) {
    const errorBody = await response.text();
    const genericError = `GroqCloud chat failed: ${response.status} ${errorBody.slice(0, 300)}`;

    if (response.status === 401 || response.status === 403) {
      throw new Error(`${genericError}. Check GROQ_CLOUD_API_KEY and ensure the key is valid for GroqCloud.`);
    }

    if (
      response.status === 404 &&
      (/model .* not found/i.test(errorBody) || /does not exist/i.test(errorBody))
    ) {
      const availableModels = await getAvailableGroqModels();
      const alternativeModel = preferredModels.find((name) => availableModels.includes(name) && name !== env.groqModel);
      if (alternativeModel) {
        response = await executeRequest(alternativeModel);
        if (response.ok) {
          const responseBody = await response.json();
          return responseBody.choices?.[0]?.message?.content?.trim() || '';
        }
      }

      throw new Error(
        `${genericError}. The configured GROQ_CLOUD_MODEL "${env.groqModel || 'unset'}" was not found. Available models: ${availableModels.join(', ') || 'none'}.`
      );
    }

    throw new Error(genericError);
  }

  const responseBody = await response.json();
  return responseBody.choices?.[0]?.message?.content?.trim() || '';
}

async function askQuestion(question, scan) {
  if (!isChatConfigured()) {
    const error = new Error('AI chat is not configured for this platform. Ask an admin to enable AI_ANALYSIS_ENABLED and set an AI provider API key.');
    error.statusCode = 503;
    error.expose = true;
    throw error;
  }

  const prompt = buildChatPrompt(question, scan);

  if (env.aiProvider === 'openai') {
    return askWithOpenAi(prompt);
  }

  if (env.aiProvider === 'ollama') {
    return askWithOllama(prompt);
  }

  if (env.aiProvider === 'groq') {
    return askWithGroq(prompt);
  }

  throw new Error('Unsupported AI provider.');
}

module.exports = { askQuestion, isChatConfigured };
