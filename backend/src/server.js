require('dotenv').config();

const { createApp } = require('./app');
const { env } = require('./config/env');
const { checkService } = require('./config/service-check');
const { pool } = require('./db/pool');

async function startServer() {
  const databaseCheck = await checkService('PostgreSQL', env.databaseUrl);
  if (!databaseCheck.isReachable) {
    throw new Error(
      `PostgreSQL is offline at ${databaseCheck.host}:${databaseCheck.port}. Run "docker compose up -d" from the backend folder.`
    );
  }

  await pool.query('select 1');

  const app = createApp();
  app.listen(env.port, () => {
    console.log(`API listening on http://localhost:${env.port}`);
    console.log(
      `AI provider=${env.aiProvider}, aiAnalysisEnabled=${env.aiAnalysisEnabled}, groqModel=${env.groqModel || 'unset'}, groqApiKeySet=${Boolean(env.groqApiKey)}`
    );
  });
}

startServer().catch((error) => {
  console.error(`Failed to start API server: ${error.message}`);
  process.exit(1);
});
