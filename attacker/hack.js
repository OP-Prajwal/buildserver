'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const chalk = require('chalk');
const { spawnSync } = require('child_process');
const path = require('path');

const DOCKERHUB_USERNAME = process.env.DOCKERHUB_USERNAME;
const DOCKERHUB_REPO = process.env.DOCKERHUB_REPO || `${DOCKERHUB_USERNAME}/supplychainattest-app`;
const TAG = process.env.ATTACK_TAG || 'latest';
const TARGET_IMAGE = `${DOCKERHUB_REPO}:${TAG}`;
const MALICIOUS_DIR = path.join(__dirname, 'malicious-app');

function docker(args) {
  const r = spawnSync('docker', args, { stdio: 'inherit', encoding: 'utf8' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

async function main() {
  if (!DOCKERHUB_USERNAME) {
    console.error(chalk.red('❌ DOCKERHUB_USERNAME is not set.'));
    process.exit(1);
  }

  console.log(chalk.red(`[ATTACKER] Building malicious image...`));
  docker(['build', '-t', TARGET_IMAGE, MALICIOUS_DIR]);

  console.log(chalk.red(`[ATTACKER] Pushing malicious image to ${TARGET_IMAGE}...`));
  docker(['push', TARGET_IMAGE]);

  console.log(chalk.bgRed.white.bold('\n[ATTACKER] ATTACK SUCCESSFUL: Malicious image deployed!'));
}
main();
