'use strict';

// Runs the mock identity provider and the sample app together with prefixed
// output. `npm start`.

const { spawn } = require('node:child_process');
const path = require('node:path');

const root = path.join(__dirname, '..');

const processes = [
  { name: 'idp', colour: '\x1b[36m', script: 'mock-entra/server.js' },
  { name: 'app', colour: '\x1b[35m', script: 'sample-app/server.js' },
];

const children = processes.map(({ name, colour, script }) => {
  const child = spawn(process.execPath, [path.join(root, script)], {
    cwd: root,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const prefix = `${colour}[${name}]\x1b[0m`;
  const pipe = (stream, out) => {
    let buffer = '';
    stream.on('data', (chunk) => {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) out.write(`${prefix} ${line}\n`);
    });
  };
  pipe(child.stdout, process.stdout);
  pipe(child.stderr, process.stderr);

  child.on('exit', (code, signal) => {
    process.stdout.write(`${prefix} exited (${signal || code})\n`);
    shutdown(code ?? 1);
  });

  return child;
});

let shuttingDown = false;
function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const child of children) child.kill('SIGTERM');
  setTimeout(() => process.exit(code), 200).unref();
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
