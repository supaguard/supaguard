#!/usr/bin/env node

/**
 * SupaGuard Node.js Binary Wrapper
 * Enables instant zero-friction execution via `npx supaguard` and `npm install -g supaguard`.
 */

const { spawn } = require('child_process');
const path = require('path');

const cliPath = path.join(__dirname, 'supaguard');
const args = process.argv.slice(2);

const proc = spawn('python3', [cliPath, ...args], {
  stdio: 'inherit',
  env: process.env
});

proc.on('error', (err) => {
  if (err.code === 'ENOENT') {
    console.error('\x1b[31m[Error]\x1b[0m python3 was not found on your system.');
    console.error('Please ensure Python 3 is installed to run SupaGuard.');
  } else {
    console.error('\x1b[31m[Error]\x1b[0m Failed to spawn SupaGuard engine:', err.message);
  }
  process.exit(1);
});

proc.on('close', (code) => {
  process.exit(code || 0);
});
