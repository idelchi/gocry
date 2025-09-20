#!/bin/bash
# shellcheck disable=all

# jscpd:ignore-start

set -euo pipefail

trap 'echo "🚨🚨 Tests failed! 🚨🚨"' ERR

if ! command -v gogen &> /dev/null; then
  curl -sSL https://raw.githubusercontent.com/idelchi/gogen/refs/heads/main/install.sh | sh -s -- -v v0.0.0 -d ~/.local/bin
fi

go install -buildvcs=false .

# Create and move to temporary directory
TMPDIR=$(mktemp -d)

trap 'rm -rf "$TMPDIR"' EXIT
cd "${TMPDIR}"

# Generate encryption key
export GOCRY_KEY=$(gogen key --length 32)
export GOCRY_QUIET=true
export GOCRY_DETERMINISTIC=false

echo "Starting test [Undeterministic, File mode]..."
# File mode
cat >test.sh <<'EOF'
echo "Hello, I am a file!"
EOF

# Test undeterministic encryption/decryption
gocry encrypt test.sh >test.sh.enc

gocry decrypt test.sh.enc >test.sh.dec
[[ -f "test.sh.dec" ]] || (echo '❌ test [File mode]: Decrypted file was not created' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test [File mode]: File content changed' && exit 1)

echo "Starting test [Undeterministic, Line mode]..."
# Line mode
cat >test.sh <<'EOF'
echo "Hello, I am a file!"
echo "This line is secret!" ### DIRECTIVE: ENCRYPT
EOF

# Test undeterministic encryption/decryption
gocry -m line encrypt test.sh >test.sh.enc

gocry -m line decrypt test.sh.enc >test.sh.dec
[[ -f "test.sh.dec" ]] || (echo '❌ test [Line mode]: Decrypted file was not created' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test [Line mode]: File content changed' && exit 1)

echo "Starting test [Undeterministic, file mode]..."
# Undeterministic encryption
cat >test.sh <<'EOF'
<content>
<secret> ### DIRECTIVE: ENCRYPT
EOF

# Test undeterministic encryption/decryption
gocry encrypt test.sh >test.sh.enc1
gocry encrypt test.sh >test.sh.enc2
gocry encrypt test.sh >test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 && (echo '❌ test [Undeterministic, file mode]: File content did not change' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 && (echo '❌ test [Undeterministic, file mode]: File content did not change' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 && (echo '❌ test [Undeterministic, file mode]: File content did not change' && exit 1)

echo "Starting test [Undeterministic, line mode]..."
# Test undeterministic encryption/decryption
gocry -m line encrypt test.sh >test.sh.enc1
gocry -m line encrypt test.sh >test.sh.enc2
gocry -m line encrypt test.sh >test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 && (echo '❌ test [Undeterministic, line mode]: File content did not change' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 && (echo '❌ test [Undeterministic, line mode]: File content did not change' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 && (echo '❌ test [Undeterministic, line mode]: File content did not change' && exit 1)

rm -f test.sh test.sh.enc1 test.sh.enc2 test.sh.enc3 test.sh.enc test.sh.dec

echo "All tests passed! 🎉"

# jscpd:ignore-end
