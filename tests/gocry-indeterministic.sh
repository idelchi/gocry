#!/bin/bash
# shellcheck disable=all

# jscpd:ignore-start

set -euo pipefail

trap 'echo "🚨🚨 Tests failed! 🚨🚨"' ERR

echo "Running indeterministic tests..."

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
echo "Generating encryption key with length 32..."
export GOCRY_KEY=$(gogen key --length 32)
export GOCRY_QUIET=true
export GOCRY_DETERMINISTIC=false

echo "Starting test [Indeterministic, File mode]..."
# File mode
cat >test.sh <<'EOF'
echo "Hello, I am a file!"
EOF

# Test indeterministic encryption/decryption
cat test.sh | gocry encrypt test.sh >test.sh.enc

cat test.sh.enc | gocry decrypt test.sh.enc >test.sh.dec
[[ -f "test.sh.dec" ]] || (echo '❌ test [File mode]: Decrypted file was not created' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test [File mode]: File content changed' && exit 1)

echo "Starting test [Indeterministic, Line mode]..."
# Line mode
cat >test.sh <<'EOF'
echo "Hello, I am a file!"
echo "This line is secret!" ### DIRECTIVE: ENCRYPT
EOF

# Test indeterministic encryption/decryption
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc

cat test.sh.enc | gocry -m line decrypt test.sh.enc >test.sh.dec
[[ -f "test.sh.dec" ]] || (echo '❌ test [Line mode]: Decrypted file was not created' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test [Line mode]: File content changed' && exit 1)

echo "Starting test [Indeterministic, file mode]..."
# Indeterministic encryption
cat >test.sh <<'EOF'
<content>
<secret> ### DIRECTIVE: ENCRYPT
EOF

# Test indeterministic encryption/decryption
cat test.sh | gocry encrypt test.sh >test.sh.enc1
cat test.sh | gocry encrypt test.sh >test.sh.enc2
cat test.sh | gocry encrypt test.sh >test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 && (echo '❌ test [Indeterministic, file mode]: File content did not change' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 && (echo '❌ test [Indeterministic, file mode]: File content did not change' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 && (echo '❌ test [Indeterministic, file mode]: File content did not change' && exit 1)

echo "Starting test [Indeterministic, line mode]..."
# Test indeterministic encryption/decryption
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc1
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc2
cat test.sh | gocry -m line encrypt test.sh >test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 && (echo '❌ test [Indeterministic, line mode]: File content did not change' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 && (echo '❌ test [Indeterministic, line mode]: File content did not change' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 && (echo '❌ test [Indeterministic, line mode]: File content did not change' && exit 1)

rm -f test.sh test.sh.enc1 test.sh.enc2 test.sh.enc3 test.sh.enc test.sh.dec

echo "All tests passed! 🎉"

# jscpd:ignore-end
