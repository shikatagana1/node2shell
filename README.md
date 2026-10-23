# node2shell

Checks if a Node.js install is vulnerable to **CVE-2026-111497** ("Node2Shell"),
a critical Brotli decompression vulnerability in Node.js.

**Vulnerable:** Node 22 < 22.23.4, Node 24 < 24.22.1, Node 26 < 26.12.1, and
any EOL major line (no fix available).
**Fixed:** Node 22 >= 22.23.4, Node 24 >= 24.22.1, Node 26 >= 26.12.1.

Looks at the Node version, whether the patched decoder constant is present,
and whether brotli is bundled or linked against the system libbrotli (checks
dpkg/rpm/apk for the package version in that case). Also throws some
malformed/corrupted brotli input at `brotliDecompressSync` to see if
anything blows up on this process.

## Usage

```
./check-node2shell.sh
```

or just:

```
node check-node2shell.js
```

## Exit codes

- `0` - not vulnerable
- `1` - vulnerable
- `2` - can't tell (shared libbrotli, couldn't read the OS package version -
  check the image manually)

Read-only, doesn't touch anything. Only run against systems you're allowed
to test.
