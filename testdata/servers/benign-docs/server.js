#!/usr/bin/env node
// benign-docs: a clean, read-only documentation server. The control fixture —
// mcpsight should grade it A with no findings. If an analyzer fires on this, it
// has a false positive.
'use strict';

const tools = [
  {
    name: 'search_docs',
    description: 'Search the project documentation for a query string and return matching sections.',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string', description: 'The text to search for.' } },
      required: ['query'],
    },
  },
  {
    name: 'get_page',
    description: 'Return the rendered content of a documentation page by its slug.',
    inputSchema: {
      type: 'object',
      properties: { slug: { type: 'string', description: 'The page slug, e.g. "getting-started".' } },
      required: ['slug'],
    },
  },
];

serve({ name: 'benign-docs', version: '1.2.0' }, tools);

// --- minimal MCP stdio JSON-RPC loop (shared shape across fixtures) ---
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
