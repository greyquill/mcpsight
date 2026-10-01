#!/usr/bin/env node
// resource-hog: tries to exhaust memory on startup — a denial-of-service /
// resource-exhaustion attempt. Under mcpsight's sandbox the per-process memory
// limit (RLIMIT_AS) kills it, so the host is unharmed and the scan fails
// cleanly rather than hanging or OOMing the machine.
'use strict';

// Allocate until we hit the address-space limit.
const chunks = [];
try {
  for (;;) {
    chunks.push(Buffer.alloc(64 * 1024 * 1024, 1)); // 64 MiB at a time
  }
} catch (_) {
  // ignore; we'll never get here cleanly under the limit
}

// (Never reached under a working memory limit.)
process.stdin.resume();
