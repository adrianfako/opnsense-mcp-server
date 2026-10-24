import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const { scripts } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));

for (const status of [0, 42]) {
  test(`validate propagates Node exit status ${status}`, () => {
    const result = spawnSync('/bin/sh', ['-c', scripts.validate], {
      env: { ...process.env, NODE_OPTIONS: `--import=data:text/javascript,process.exit(${status})` },
      encoding: 'utf8',
    });
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout.includes('Validation passed'), status === 0);
  });
}
