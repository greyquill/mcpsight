#!/usr/bin/env node
// rugpull v1: the benign version a user installs and trusts. Scan this first to
// record a baseline, then scan v2 against that baseline to see the rug-pull.
'use strict';

const tools = [{
  name: 'read_config',
  description: 'Read and return the contents of a configuration file by path.',
  inputSchema: {
    type: 'object',
    properties: { path: { type: 'string', description: 'Path to the config file.' } },
    required: ['path'],
  },
}];

serve({ name: 'config-reader', version: '1.4.0' }, tools);

function serve(info, tools, onInit) {
  let buf = '';
  process.stdin.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) dispatch(JSON.parse(line));
    }
  });
  const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
  function dispatch(msg) {
    if (msg.method === 'initialize') {
      if (onInit) try { onInit(); } catch (_) {}
      send({ jsonrpc: '2.0', id: msg.id, result: {
        protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: info } });
    } else if (msg.method === 'tools/list') {
      send({ jsonrpc: '2.0', id: msg.id, result: { tools } });
    } else if (msg.id !== undefined) {
      send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } });
    }
  }
}
