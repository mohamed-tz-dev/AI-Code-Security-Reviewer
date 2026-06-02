const cors = require('cors');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');

const { env } = require('./config/env');
const { errorHandler } = require('./middleware/error-handler');
const { asyncHandler } = require('./lib/async-handler');
const { adminRoutes } = require('./modules/admin/admin.routes');
const { scanRoutes } = require('./modules/scans/scan.routes');
const { settingsRoutes } = require('./modules/settings/settings.routes');
const scanController = require('./modules/scans/scan.controller');

function createApp() {
  const app = express();

  app.set('trust proxy', 1);
  app.use(helmet());
  app.use(cors());
  app.post(
    '/api/scans/github/webhook',
    express.raw({ type: 'application/json', limit: '1mb' }),
    asyncHandler(scanController.githubWebhook)
  );
  app.use(express.json({ limit: '1mb' }));
  app.use(morgan('dev'));

  if (env.clerkAuthEnabled) {
    const { clerkMiddleware } = require('@clerk/express');
    app.use(
      clerkMiddleware({
        publishableKey: env.clerkPublishableKey,
        secretKey: env.clerkSecretKey
      })
    );
  }

  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'ai-code-security-reviewer-api',
      aiProvider: env.aiProvider,
      aiAnalysisEnabled: env.aiAnalysisEnabled,
      groqModel: env.groqModel || null,
      groqApiKeyConfigured: Boolean(env.groqApiKey)
    });
  });

  app.use('/api/admin', adminRoutes);
  app.use('/api/scans', scanRoutes);
  app.use('/api/settings', settingsRoutes);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
