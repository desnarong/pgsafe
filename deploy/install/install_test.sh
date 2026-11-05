#!/bin/sh
# Tests install.sh against a local GoReleaser snapshot. Run inside a Linux container
# by `make install-test` with the repo at /src (read-only) and dist/ at /dist.
set -eu

INSTALL=/src/deploy/install/install.sh
DIST=${DIST:-/dist}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

version=$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' "${DIST}/metadata.json")
[ -n "$version" ] || fail "no version in ${DIST}/metadata.json (run release-check first)"
echo "== $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"') $(uname -m), pgsafe ${version}"

# 1. explicit install dir
PGSAFE_DOWNLOAD_BASE="file://${DIST}" PGSAFE_VERSION="v${version}" PGSAFE_INSTALL_DIR=/tmp/t1 sh "$INSTALL"
/tmp/t1/pgsafe --version | tee /tmp/t1.out
grep -q "pgsafe ${version} " /tmp/t1.out || fail "unexpected --version output"

# 2. default install dir (root → /usr/local/bin), then on PATH
PGSAFE_DOWNLOAD_BASE="file://${DIST}/" PGSAFE_VERSION="${version}" sh "$INSTALL"
pgsafe --version | grep -q "pgsafe ${version} " || fail "pgsafe not installed in /usr/local/bin"

# 3. tampered checksum must fail and install nothing
mkdir /tmp/bad
cp "${DIST}"/*.tar.gz "${DIST}/checksums.txt" /tmp/bad/
sed -i 's/^[0-9a-f]\{8\}/00000000/' /tmp/bad/checksums.txt
if PGSAFE_DOWNLOAD_BASE=file:///tmp/bad PGSAFE_VERSION="${version}" PGSAFE_INSTALL_DIR=/tmp/t3 sh "$INSTALL" 2>/tmp/t3.err; then
	fail "install succeeded with a tampered checksums.txt"
fi
grep -q "sha256 mismatch" /tmp/t3.err || fail "tampered case failed for the wrong reason: $(cat /tmp/t3.err)"
[ ! -e /tmp/t3/pgsafe ] || fail "tampered binary was installed"
echo "tampered checksum rejected: $(tail -n 1 /tmp/t3.err)"

# 4. tampered archive must fail too
cp "${DIST}/checksums.txt" /tmp/bad/checksums.txt
printf 'x' >>"/tmp/bad/pgsafe_${version}_linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz"
if PGSAFE_DOWNLOAD_BASE=file:///tmp/bad PGSAFE_VERSION="${version}" PGSAFE_INSTALL_DIR=/tmp/t4 sh "$INSTALL" 2>/dev/null; then
	fail "install succeeded with a tampered archive"
fi
[ ! -e /tmp/t4/pgsafe ] || fail "tampered archive was installed"

# 5. clear errors
if PGSAFE_DOWNLOAD_BASE="file://${DIST}" sh "$INSTALL" 2>/tmp/t5.err; then fail "missing PGSAFE_VERSION accepted"; fi
grep -q "needs PGSAFE_VERSION" /tmp/t5.err || fail "unclear error: $(cat /tmp/t5.err)"

echo "install-test ok"
