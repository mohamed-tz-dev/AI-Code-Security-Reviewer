const { z } = require('zod');
const { env } = require('../../config/env');

const updateSettingsSchema = z.object({
  aiProvider: z.enum(['openai', 'ollama', 'groq']).optional(),
  aiAnalysisEnabled: z.boolean().optional(),
  openAiModel: z.string().min(1).optional(),
  ollamaBaseUrl: z.string().url().optional(),
  ollamaModel: z.string().min(1).optional(),
  groqModel: z.string().min(1).optional(),
  aiMaxFiles: z.coerce.number().int().positive().optional(),
  aiMaxCharsPerFile: z.coerce.number().int().positive().optional()
});

function getSettings(_req, res) {
  res.json({
    settings: {
      aiProvider: env.aiProvider,
      aiAnalysisEnabled: env.aiAnalysisEnabled,
      openAiModel: env.openAiModel,
      ollamaBaseUrl: env.ollamaBaseUrl,
      ollamaModel: env.ollamaModel,
      groqModel: env.groqModel,
      aiMaxFiles: env.aiMaxFiles,
      aiMaxCharsPerFile: env.aiMaxCharsPerFile,
      clerkAuthEnabled: env.clerkAuthEnabled
    }
  });
}

function updateSettings(req, res) {
  const payload = updateSettingsSchema.parse(req.body);

  if (payload.aiProvider) {
    env.aiProvider = payload.aiProvider;
  }

  if (typeof payload.aiAnalysisEnabled === 'boolean') {
    env.aiAnalysisEnabled = payload.aiAnalysisEnabled;
  }

  if (payload.openAiModel) {
    env.openAiModel = payload.openAiModel;
  }

  if (payload.ollamaBaseUrl) {
    env.ollamaBaseUrl = payload.ollamaBaseUrl.replace(/\/$/, '');
  }

  if (payload.ollamaModel) {
    env.ollamaModel = payload.ollamaModel;
  }

  if (payload.groqModel) {
    env.groqModel = payload.groqModel;
  }

  if (payload.aiMaxFiles) {
    env.aiMaxFiles = payload.aiMaxFiles;
  }

  if (payload.aiMaxCharsPerFile) {
    env.aiMaxCharsPerFile = payload.aiMaxCharsPerFile;
  }

  res.json({
    settings: {
      aiProvider: env.aiProvider,
      aiAnalysisEnabled: env.aiAnalysisEnabled,
      openAiModel: env.openAiModel,
      ollamaBaseUrl: env.ollamaBaseUrl,
      ollamaModel: env.ollamaModel,
      groqModel: env.groqModel,
      aiMaxFiles: env.aiMaxFiles,
      aiMaxCharsPerFile: env.aiMaxCharsPerFile,
      clerkAuthEnabled: env.clerkAuthEnabled
    }
  });
}

module.exports = { getSettings, updateSettings };
