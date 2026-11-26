#!/usr/bin/env bash
# Build the release protector, emit checksums and an SBOM, and sign the
# checksum file only when an explicit local signing key is configured.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    exit 1
fi

out="target/release-artifacts"
rm -rf "$out"
mkdir -p "$out"

cargo build --release -p sirus-protector >/dev/null
version="$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)"
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
dirty="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
artifact="$out/sirus-$version-$(uname -s)-$(uname -m)"
cp target/release/sirus "$artifact"
chmod 755 "$artifact"
source_archive="$out/sirus-$version-source.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "$source_archive" \
    Cargo.toml Cargo.lock README.md RELEASE.md CHANGELOG.md \
    crates scripts docs bench fuzz/Cargo.toml fuzz/fuzz_targets

{
    printf 'version=%s\n' "$version"
    printf 'commit=%s\n' "$commit"
    printf 'dirty_files=%s\n' "$dirty"
    printf 'rustc=%s\n' "$(rustc --version 2>/dev/null || echo unavailable)"
    printf 'cargo=%s\n' "$(cargo --version 2>/dev/null || echo unavailable)"
    printf 'cc=%s\n' "$(cc --version 2>/dev/null | head -1 || echo unavailable)"
    printf 'lld=%s\n' "$(ld.lld --version 2>/dev/null | head -1 || echo unavailable)"
    printf 'host=%s\n' "$(uname -a)"
} >"$out/MANIFEST.txt"

python3 - "$out/sbom.json" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

path = Path(sys.argv[1])
metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1"]))
components = []
for package in sorted(metadata["packages"], key=lambda item: item["name"]):
    if package.get("source") is None:
        components.append(
            {
                "type": "library",
                "name": package["name"],
                "version": package["version"],
                "properties": [{"name": "path", "value": package["manifest_path"]}],
            }
        )
document = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "Sirus",
            "version": Path("Cargo.toml").read_text().split('version = "', 1)[1].split('"', 1)[0],
        }
    },
    "components": components,
}
path.write_text(json.dumps(document, indent=2) + "\n")
PY

(
    cd "$out"
    sha256sum "$(basename "$artifact")" "$(basename "$source_archive")" MANIFEST.txt sbom.json >SHA256SUMS
)

if [[ -n "${SIRUS_SIGNING_KEY:-}" ]]; then
    gpg --batch --yes --armor --detach-sign --local-user "$SIRUS_SIGNING_KEY" \
        "$out/SHA256SUMS"
    echo "signed=yes key=$SIRUS_SIGNING_KEY"
elif [[ "${SIRUS_REQUIRE_SIGNATURE:-0}" == "1" ]]; then
    echo "SIRUS_REQUIRE_SIGNATURE=1 but SIRUS_SIGNING_KEY is unset" >&2
    exit 1
else
    echo "signed=no (set SIRUS_SIGNING_KEY to sign SHA256SUMS)"
fi

echo "PASS release artifacts"
cat "$out/SHA256SUMS"
