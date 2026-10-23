# node2shell

Checks if a Node.js install is vulnerable to the Brotli decompression bug
(aka "Node2Shell").

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
