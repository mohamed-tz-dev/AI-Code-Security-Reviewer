const IORedis = require('ioredis');
const { env } = require('../config/env');

function createRedisConnection() {
  const connection = new IORedis(env.redisUrl, {
    maxRetriesPerRequest: null
  });

  connection.on('error', (error) => {
    if (error.code === 'ECONNREFUSED') {
      console.error(`Redis is offline at ${env.redisUrl}. Run "docker compose up -d" from the backend folder.`);
      return;
    }

    console.error('Redis connection error:', error.message);
  });

  return connection;
}

module.exports = { createRedisConnection };
