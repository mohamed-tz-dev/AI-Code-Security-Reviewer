const path = require('path');
const { z } = require('zod');

const envBoolean = z
  .union([z.boolean(), z.string()])
  .optional()
  .transform((value) => {
    if (typeof value === 'boolean') {
      return value;
    }

    return value === 'true';
  });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  UPLOAD_DIR: z.string().default('./storage/uploads'),
  WORKSPACE_DIR: z.string().default('./storage/workspaces'),
  MAX_UPLOAD_MB: z.coerce.number().int().positive().default(50),
  CLERK_AUTH_ENABLED: envBoolean.default(false),
  CLERK_PUBLISHABLE_KEY: z.string().optional(),
  CLERK_SECRET_KEY: z.string().optional(),
  AUTH_SESSION_SECRET: z.string().min(16).default('change-this-local-secret'),
  ADMIN_EMAIL: z.string().email().optional(),
  ADMIN_PASSWORD: z.string().optional(),
  AI_PROVIDER: z.enum(['openai', 'ollama', 'groq']).default('openai'),
  OPENAI_API_KEY: z.string().optional(),
  OPENAI_MODEL: z.string().default('gpt-4o-mini'),
  OLLAMA_BASE_URL: z.string().url().default('http://localhost:11434'),
  OLLAMA_MODEL: z.string().optional(),
  OLLAMA_API_KEY: z.string().optional(),
  GROQ_CLOUD_API_KEY: z.string().optional(),
  GROQ_CLOUD_MODEL: z.string().default('openai/gpt-oss-20b'),
  AI_ANALYSIS_ENABLED: envBoolean.default(false),
  AI_MAX_FILES: z.coerce.number().int().positive().default(20),
  AI_MAX_CHARS_PER_FILE: z.coerce.number().int().positive().default(12000),
  SEMGREP_ENABLED: envBoolean.default(false),
  GITHUB_DEFAULT_ACCESS_TOKEN: z.string().optional(),
  GITHUB_WEBHOOK_SECRET: z.string().optional(),
  SEMGREP_CONFIG: z.string().default('auto'),
  SEMGREP_TIMEOUT_MS: z.coerce.number().int().positive().default(60000)
});

const parsed = envSchema.parse(process.env);

const rootDir = path.resolve(__dirname, '..', '..');

const env = {
  nodeEnv: parsed.NODE_ENV,
  port: parsed.PORT,
  databaseUrl: parsed.DATABASE_URL,
  redisUrl: parsed.REDIS_URL,
  uploadDir: path.resolve(rootDir, parsed.UPLOAD_DIR),
  workspaceDir: path.resolve(rootDir, parsed.WORKSPACE_DIR),
  maxUploadMb: parsed.MAX_UPLOAD_MB,
  clerkAuthEnabled: parsed.CLERK_AUTH_ENABLED,
  clerkPublishableKey: parsed.CLERK_PUBLISHABLE_KEY,
  clerkSecretKey: parsed.CLERK_SECRET_KEY,
  authSessionSecret: parsed.AUTH_SESSION_SECRET,
  adminEmail: parsed.ADMIN_EMAIL,
  adminPassword: parsed.ADMIN_PASSWORD,
  aiProvider: parsed.AI_PROVIDER,
  openAiApiKey: parsed.OPENAI_API_KEY,
  openAiModel: parsed.OPENAI_MODEL,
  ollamaBaseUrl: parsed.OLLAMA_BASE_URL.replace(/\/$/, ''),
  ollamaModel: parsed.OLLAMA_MODEL || '',
  ollamaApiKey: parsed.OLLAMA_API_KEY,
  groqApiKey: parsed.GROQ_CLOUD_API_KEY,
  groqModel: parsed.GROQ_CLOUD_MODEL,
  aiAnalysisEnabled: parsed.AI_ANALYSIS_ENABLED,
  aiMaxFiles: parsed.AI_MAX_FILES,
  aiMaxCharsPerFile: parsed.AI_MAX_CHARS_PER_FILE,
  semgrepEnabled: parsed.SEMGREP_ENABLED,
  githubDefaultAccessToken: parsed.GITHUB_DEFAULT_ACCESS_TOKEN,
  githubWebhookSecret: parsed.GITHUB_WEBHOOK_SECRET,
  semgrepConfig: parsed.SEMGREP_CONFIG,
  semgrepTimeoutMs: parsed.SEMGREP_TIMEOUT_MS
};

module.exports = { env };
