require('dotenv').config();

const { env } = require('../src/config/env');
const { checkService } = require('../src/config/service-check');
const { spawnSync } = require('child_process');

const PYTHON_COMMANDS = ['python', 'python3', 'py'];
const SEMGREP_COMMANDS = [['semgrep'], ['python', '-m', 'semgrep'], ['python3', '-m', 'semgrep'], ['py', '-3', '-m', 'semgrep']];

function findPythonCommand() {
  for (const command of PYTHON_COMMANDS) {
    const result = spawnSync(command, ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });

    if (result.status === 0) {
      return command;
    }
  }

  return null;
}

function findSemgrepCommand() {
  for (const command of SEMGREP_COMMANDS) {
    const result = spawnSync(command[0], [...command.slice(1), '--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });

    if (result.status === 0) {
      return true;
    }
  }

  return false;
}

async function checkPython() {
  const command = findPythonCommand();
  return {
    name: 'Python',
    host: 'local',
    port: 'N/A',
    isReachable: Boolean(command)
  };
}

async function checkSemgrep() {
  return {
    name: 'Semgrep',
    host: 'local',
    port: 'N/A',
    isReachable: findSemgrepCommand()
  };
}

async function main() {
  const checks = await Promise.all([
    checkService('PostgreSQL', env.databaseUrl),
    checkService('Redis', env.redisUrl),
    checkPython(),
    checkSemgrep()
  ]);

  let hasFailure = false;

  for (const check of checks) {
    const status = check.isReachable ? 'ok' : 'offline';
    console.log(`${check.name}: ${status} (${check.host}:${check.port})`);

    if (!check.isReachable) {
      hasFailure = true;
    }
  }

  if (hasFailure) {
    console.log('');
    console.log('Start local services from the backend folder:');
    console.log('docker compose up -d');
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
