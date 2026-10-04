'use strict';

const chalk = require('chalk');

const LEVELS = {
  system:  { label: 'SYSTEM ', badge: chalk.cyan.bold,        icon: '⚙' },
  info:    { label: 'INFO   ', badge: chalk.blue,              icon: 'ℹ' },
  success: { label: 'SUCCESS', badge: chalk.green.bold,        icon: '✔' },
  warn:    { label: 'WARN   ', badge: chalk.yellow.bold,       icon: '⚠' },
  error:   { label: 'ERROR  ', badge: chalk.red,               icon: '✖' },
  attack:  { label: 'ATTACK ', badge: chalk.bgRed.white.bold,  icon: '💀' },
  step:    { label: 'STEP   ', badge: chalk.magenta,           icon: '›' },
};

function log(level, message, meta = {}) {
  const { label, badge, icon } = LEVELS[level] ?? LEVELS.info;
  const ts = chalk.gray(new Date().toISOString());
  const metaStr = Object.keys(meta).length ? '  ' + chalk.gray(JSON.stringify(meta)) : '';
  process.stdout.write(`${ts} ${badge(`[${label}]`)} ${icon}  ${message}${metaStr}\n`);
  return { level, message, meta, timestamp: new Date().toISOString() };
}

module.exports = {
  system:  (msg, meta) => log('system', msg, meta),
  info:    (msg, meta) => log('info', msg, meta),
  success: (msg, meta) => log('success', msg, meta),
  warn:    (msg, meta) => log('warn', msg, meta),
  error:   (msg, meta) => log('error', msg, meta),
  attack:  (msg, meta) => log('attack', msg, meta),
  step:    (msg, meta) => log('step', msg, meta),
};
