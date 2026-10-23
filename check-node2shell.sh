#!/usr/bin/env bash
# CVE-2026-111497 (node2shell) check: 0 = not vulnerable, 1 = vulnerable, 2 = can't tell

node <<'EOF'
const z = require('zlib'), cp = require('child_process'), cr = require('crypto');

const ver = process.versions.node;
const [ma] = ver.split('.').map(Number);

const FX = { 22: [23, 4], 24: [22, 1], 26: [12, 1] };
const f = FX[ma];
const eol = !f;

const hasC = z.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH !== undefined;

const sv = process.config && process.config.variables && process.config.variables.node_shared_brotli;
const shared = sv === true || sv === 1 || sv === 'true' || sv === '1';

function lib() {
  const candidates = [
    "dpkg-query -W -f='${Version}' libbrotli1 2>/dev/null",
    "rpm -q --qf '%{VERSION}' libbrotli 2>/dev/null",
    "rpm -q --qf '%{VERSION}' brotli 2>/dev/null",
    "apk info -v 2>/dev/null|grep -m1 -i brotli",
  ];
  for (const cmd of candidates) {
    try {
      const out = cp.execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      const m = out.match(/(\d+)\.(\d+)\.(\d+)/);
      if (m) return [+m[1], +m[2], +m[3]];
    } catch (e) {}
  }
  return null;
}

function isFixed(v) {
  if (!v) return null;
  const [a, b, c] = v;
  if (a > 1) return true;
  if (a === 1 && b === 0) return c >= 10;
  if (a === 1 && b === 1) return c >= 1;
  if (a === 1 && b >= 2) return b > 2 || c >= 1;
  return false;
}

try {
  z.brotliDecompressSync(z.brotliCompressSync(Buffer.from('x'.repeat(4096))));
} catch (e) {}

for (let i = 0; i < 50000; i++) {
  let b = (i & 1) ? cr.randomBytes(1 + (i % 300)) : z.brotliCompressSync(cr.randomBytes(64));
  if (!(i & 1)) {
    for (let j = 0; j <= i % 8; j++) {
      b[Math.floor(Math.random() * b.length)] ^= 0xff;
    }
  }
  try {
    z.brotliDecompressSync(b);
  } catch (e) {}
}

let verdict, code, why;

if (shared) {
  const v = lib();
  const r = isFixed(v);
  if (r === true) {
    verdict = 'NOT VULNERABLE';
    code = 0;
    why = 'shared libbrotli ' + v.join('.') + ' patched';
  } else if (r === false) {
    verdict = 'VULNERABLE';
    code = 1;
    why = 'shared libbrotli ' + v.join('.') + ' needs >=1.0.10/1.1.1/1.2.1';
  } else {
    verdict = 'UNDETERMINED';
    code = 2;
    why = 'shared-brotli build, cannot read OS libbrotli - scan the image';
  }
} else if (hasC) {
  verdict = 'NOT VULNERABLE';
  code = 0;
  why = 'bundled Brotli, patch constant present';
} else {
  verdict = 'VULNERABLE';
  code = 1;
  why = 'bundled Brotli, patch missing' + (eol ? ' (EOL line, no fix)' : '');
}

console.log('\nNode ' + ver + ' | ' + (shared ? 'shared libbrotli' : 'bundled Brotli') + ' | patch constant ' + (hasC ? 'present' : 'MISSING'));
console.log('>>> VERDICT: ' + verdict + ' <<< (' + why + ')\n');
process.exit(code);
EOF

echo "exit=$?"
