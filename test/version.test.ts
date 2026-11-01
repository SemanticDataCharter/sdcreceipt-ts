/** The version is written in three places; a release needs them equal. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { SERVER_VERSION } from '../src/mcp.js';

const read = (f: string) => JSON.parse(readFileSync(new URL(`../${f}`, import.meta.url), 'utf8'));

test('package.json, the MCP server and server.json carry one version', () => {
  const pkg = read('package.json');
  const server = read('server.json');
  assert.equal(SERVER_VERSION, pkg.version);
  assert.equal(server.version, pkg.version);
  assert.ok(server.packages.every((p: { version: string }) => p.version === pkg.version));
  assert.equal(pkg.mcpName, server.name);
});

test('server.json passes the MCP registry\'s length limit', () => {
  // The registry rejects a description over 100 characters (422), after npm has already published.
  assert.ok(read('server.json').description.length <= 100);
});
