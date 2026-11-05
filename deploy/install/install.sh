#!/bin/sh
# pgsafe installer — served at https://get.pgsafe.dev
#
#   curl -fsSL https://get.pgsafe.dev | sh
#   curl -fsSL https://get.pgsafe.dev | PGSAFE_VERSION=1.2.3 PGSAFE_INSTALL_DIR=$HOME/bin sh
#
# Downloads a release from GitHub (desnarong/pgsafe), verifies its sha256 against
# checksums.txt, verifies checksums.txt with cosign (keyless) when cosign is installed,
# and installs the pgsafe binary.
#
# Environment:
#   PGSAFE_VERSION        version to install, e.g. 1.2.3 or v1.2.3 (default: latest release)
#   PGSAFE_INSTALL_DIR    target directory (default: /usr/local/bin, else ~/.local/bin)
#   PGSAFE_DOWNLOAD_BASE  directory holding the archives + checksums.txt (http(s):// or file://);
#                         overrides GitHub, needs PGSAFE_VERSION
#   PGSAFE_SKIP_COSIGN=1  do not verify the signature even if cosign is installed
set -eu

REPO="desnarong/pgsafe"
# Identity of the release workflow that signs checksums.txt (see .github/workflows/release.yml).
COSIGN_IDENTITY_RE="^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v"
COSIGN_ISSUER="https://token.actions.githubusercontent.com"

say() { printf 'pgsafe-install: %s\n' "$*" >&2; }
die() {
	say "error: $*"
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

# fetch URL DEST — http(s) via curl or wget, file:// by copying.
fetch() {
	case "$1" in
	file://*)
		cp "${1#file://}" "$2" 2>/dev/null || die "cannot read ${1}"
		;;
	*)
		if have curl; then
			curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" || die "download failed: $1"
		elif have wget; then
			wget -q -O "$2" "$1" || die "download failed: $1"
		else
			die "need curl or wget"
		fi
		;;
	esac
}

# latest_version — tag of the newest release, from the releases/latest redirect.
latest_version() {
	url="https://github.com/${REPO}/releases/latest"
	if have curl; then
		loc=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url") || die "cannot reach $url"
	elif have wget; then
		loc=$(wget -S --spider "$url" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r')
	else
		die "need curl or wget"
	fi
	tag=${loc##*/tag/}
	if [ -z "$tag" ] || [ "$tag" = "$loc" ]; then
		die "cannot find the latest release of ${REPO} (set PGSAFE_VERSION)"
	fi
	printf '%s\n' "$tag"
}

sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		die "need sha256sum or shasum to verify the download"
	fi
}

detect_os() {
	case "$(uname -s)" in
	Linux) echo linux ;;
	Darwin) echo darwin ;;
	*) die "unsupported OS: $(uname -s) (pgsafe ships for Linux and macOS; on Windows use WSL2 or the Docker image ghcr.io/${REPO})" ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported architecture: $(uname -m) (pgsafe ships for amd64 and arm64)" ;;
	esac
}

writable_dir() {
	[ -d "$1" ] && [ -w "$1" ] && return 0
	[ ! -e "$1" ] && mkdir -p "$1" 2>/dev/null && [ -w "$1" ]
}

main() {
	os=$(detect_os)
	arch=$(detect_arch)

	version=${PGSAFE_VERSION:-latest}
	base=${PGSAFE_DOWNLOAD_BASE:-}
	if [ "$version" = latest ]; then
		[ -z "$base" ] || die "PGSAFE_DOWNLOAD_BASE needs PGSAFE_VERSION"
		version=$(latest_version)
	fi
	version=${version#v}
	case "$version" in
	*[!0-9A-Za-z.+-]* | '') die "invalid PGSAFE_VERSION: ${version}" ;;
	esac
	[ -n "$base" ] || base="https://github.com/${REPO}/releases/download/v${version}"
	base=${base%/}

	archive="pgsafe_${version}_${os}_${arch}.tar.gz"
	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t pgsafe)
	trap 'rm -rf "$tmp"' EXIT INT HUP TERM

	say "downloading pgsafe ${version} (${os}/${arch})"
	fetch "${base}/${archive}" "${tmp}/${archive}"
	fetch "${base}/checksums.txt" "${tmp}/checksums.txt"

	if [ "${PGSAFE_SKIP_COSIGN:-0}" != 1 ] && have cosign; then
		fetch "${base}/checksums.txt.sig" "${tmp}/checksums.txt.sig"
		fetch "${base}/checksums.txt.pem" "${tmp}/checksums.txt.pem"
		cosign verify-blob \
			--certificate "${tmp}/checksums.txt.pem" \
			--signature "${tmp}/checksums.txt.sig" \
			--certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
			--certificate-oidc-issuer "$COSIGN_ISSUER" \
			"${tmp}/checksums.txt" >/dev/null 2>&1 || die "cosign signature verification of checksums.txt FAILED"
		say "cosign signature ok"
	else
		say "cosign not installed: skipping signature check (sha256 is still verified)"
	fi

	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f {print $1}' "${tmp}/checksums.txt")
	[ -n "$want" ] || die "${archive} is not listed in checksums.txt"
	got=$(sha256_of "${tmp}/${archive}")
	[ "$want" = "$got" ] || die "sha256 mismatch for ${archive}: expected ${want}, got ${got}"
	say "sha256 ok"

	mkdir "${tmp}/x"
	tar -xzf "${tmp}/${archive}" -C "${tmp}/x" pgsafe || die "cannot extract ${archive}"

	dir=${PGSAFE_INSTALL_DIR:-}
	if [ -z "$dir" ]; then
		dir=/usr/local/bin
		if ! writable_dir "$dir"; then
			dir="${HOME:?HOME is not set}/.local/bin"
			writable_dir "$dir" || die "cannot write /usr/local/bin or ${dir}; set PGSAFE_INSTALL_DIR"
		fi
	else
		writable_dir "$dir" || die "cannot write ${dir} (run with sudo or choose another PGSAFE_INSTALL_DIR)"
	fi

	# Write next to the target, then rename: never leaves a half-written binary.
	cp "${tmp}/x/pgsafe" "${dir}/.pgsafe.new"
	chmod 0755 "${dir}/.pgsafe.new"
	mv -f "${dir}/.pgsafe.new" "${dir}/pgsafe"
	say "installed ${dir}/pgsafe"

	case ":${PATH:-}:" in
	*":${dir}:"*) ;;
	*) say "note: ${dir} is not on PATH; add it, e.g. export PATH=\"${dir}:\$PATH\"" ;;
	esac
}

main "$@"
