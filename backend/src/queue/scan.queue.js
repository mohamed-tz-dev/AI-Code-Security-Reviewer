const { Queue } = require('bullmq');
const { SCAN_QUEUE_NAME } = require('./constants');
const { createRedisConnection } = require('./redis');

const scanQueue = new Queue(SCAN_QUEUE_NAME, {
  connection: createRedisConnection(),
  defaultJobOptions: {
    attempts: 2,
    backoff: {
      type: 'exponential',
      delay: 5000
    },
    removeOnComplete: 100,
    removeOnFail: 100
  }
});

module.exports = { SCAN_QUEUE_NAME, scanQueue };
