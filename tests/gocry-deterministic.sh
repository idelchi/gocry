#!/bin/bash
# shellcheck disable=all

# jscpd:ignore-start

set -euo pipefail

trap 'echo "🚨🚨 Tests failed! 🚨🚨"' ERR

echo "Running deterministic tests..."

if ! command -v gogen &>/dev/null; then
  echo "gogen not found, installing..."
  mkdir -p ~/.local/bin
  export PATH="$HOME/.local/bin:$PATH"
  curl -sSL https://raw.githubusercontent.com/idelchi/gogen/refs/heads/main/install.sh | sh -s -- -v v0.0.0 -d ~/.local/bin
fi

echo "Installing gocry..."
go install -buildvcs=false .

# Create and move to temporary directory
TMPDIR=$(mktemp -d)

trap 'rm -rf "$TMPDIR"' EXIT
cd "${TMPDIR}"

# Generate encryption key
echo "Generating encryption key with length 64..."
export GOCRY_KEY=$(gogen key --length 64)
export GOCRY_QUIET=true

echo "Starting test [Deterministic, File mode]..."
# File mode
cat >test.sh <<'EOF'
echo "Hello, I am a file!"
EOF

# Test deterministic encryption/decryption
cat test.sh | gocry encrypt test.sh >test.sh.enc

cat test.sh.enc | gocry decrypt test.sh.enc >test.sh.dec
[[ -f "test.sh.dec" ]] || (echo '❌ test [File mode]: Decrypted file was not created' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test [File mode]: File content changed' && exit 1)

echo "Starting test [Deterministic, Line mode]..."
# Line mode
cat >test.sh <<'EOF'
echo "Hello, I am a file!"
echo "This line is secret!" ### DIRECTIVE: ENCRYPT
EOF

# Test deterministic encryption/decryption
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc

cat test.sh.enc | gocry -m line decrypt test.sh.enc >test.sh.dec
[[ -f "test.sh.dec" ]] || (echo '❌ test [Line mode]: Decrypted file was not created' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test [Line mode]: File content changed' && exit 1)

echo "Starting test [Deterministic, file mode]..."
# Deterministic encryption
cat >test.sh <<'EOF'
<content>
<secret> ### DIRECTIVE: ENCRYPT
EOF

# Test deterministic encryption/decryption
cat test.sh | gocry encrypt test.sh >test.sh.enc1
cat test.sh | gocry encrypt test.sh >test.sh.enc2
cat test.sh | gocry encrypt test.sh >test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 || (echo '❌ test [Deterministic, file mode]: File content changed' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 || (echo '❌ test [Deterministic, file mode]: File content changed' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 || (echo '❌ test [Deterministic, file mode]: File content changed' && exit 1)

echo "Starting test [Deterministic, line mode]..."
# Test deterministic encryption/decryption
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc1
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc2
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 || (echo '❌ test [Deterministic, line mode]: File content changed' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 || (echo '❌ test [Deterministic, line mode]: File content changed' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 || (echo '❌ test [Deterministic, line mode]: File content changed' && exit 1)

rm -f test.sh test.sh.enc1 test.sh.enc2 test.sh.enc3 test.sh.enc test.sh.dec

echo "All tests passed! 🎉"

# jscpd:ignore-end
