#!/usr/bin/env node

/**
 * SupaGuard Node.js Binary Wrapper
 * Cross-Platform: macOS, Linux, and Windows (CMD & PowerShell).
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');

const cliPath = path.join(__dirname, 'supaguard');
const args = process.argv.slice(2);

function getPythonCommand() {
  const candidates = process.platform === 'win32' 
    ? ['python', 'py', 'python3']
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      execSync(`${cmd} --version`, { stdio: 'ignore' });
      return cmd;
    } catch (e) {
      // continue searching
    }
  }
  return process.platform === 'win32' ? 'python' : 'python3';
}

const pythonCmd = getPythonCommand();

const proc = spawn(pythonCmd, [cliPath, ...args], {
  stdio: 'inherit',
  env: process.env,
  shell: process.platform === 'win32'
});

proc.on('error', (err) => {
  if (err.code === 'ENOENT') {
    console.error('\x1b[31m[SupaGuard Error]\x1b[0m Python 3 was not found on your system.');
    console.error('Please ensure Python is installed and added to your system PATH.');
  } else {
    console.error('\x1b[31m[SupaGuard Error]\x1b[0m Execution error:', err.message);
  }
  process.exit(1);
});

proc.on('close', (code) => {
  process.exit(code || 0);
});
