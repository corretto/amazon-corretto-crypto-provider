#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Assembles Maven Central Portal upload bundles from the sign job's output directory.

Writes one zip per artifact (non-FIPS and FIPS) in Maven repository layout. Each file comes with its
detached GPG signature and md5/sha1/sha256/sha512 checksums. The sign job runs this instead of
Gradle so that no unpinned build tooling runs on the runner that can read the signing secrets.

Usage: portal_bundle.py SIGNED_DIR OUT_DIR
"""

import hashlib
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

GROUP_PATH = "software/amazon/cryptools"
ARTIFACT_IDS = ("AmazonCorrettoCryptoProvider", "AmazonCorrettoCryptoProvider-FIPS")
REQUIRED_SUFFIXES = (".pom", ".jar", "-sources.jar", "-javadoc.jar", "-linux-x86_64.jar", "-linux-aarch_64.jar")
CHECKSUMS = ("md5", "sha1", "sha256", "sha512")


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    version: str

    @property
    def prefix(self) -> str:
        return f"{self.artifact_id}-{self.version}"

    @property
    def repo_dir(self) -> str:
        return f"{GROUP_PATH}/{self.artifact_id}/{self.version}"


def find_artifacts(signed_dir: Path) -> list[Artifact]:
    """Finds each artifact by its POM, which the build job names <artifactId>-<version>.pom."""
    found = []
    for artifact_id in ARTIFACT_IDS:
        pattern = re.compile(rf"^{re.escape(artifact_id)}-(\d[^-]*)\.pom$")
        versions = [m.group(1) for p in signed_dir.iterdir() if (m := pattern.match(p.name))]
        if len(versions) != 1:
            sys.exit(f"error: expected one {artifact_id} POM in {signed_dir}, found {versions}")
        found.append(Artifact(artifact_id, versions[0]))
    return found


def artifact_files(signed_dir: Path, artifact: Artifact) -> list[Path]:
    """Every file that belongs to this artifact, excluding signatures. The FIPS artifactId carries
    -FIPS ahead of the version, so matching on the full prefix keeps the two artifacts apart."""
    files = sorted(
        p for p in signed_dir.iterdir()
        if p.name.startswith(artifact.prefix) and p.name[len(artifact.prefix)] in "-."
        and not p.name.endswith(".asc")
    )
    names = {p.name for p in files}
    missing = [artifact.prefix + s for s in REQUIRED_SUFFIXES if artifact.prefix + s not in names]
    unsigned = [p.name for p in files if not p.with_name(p.name + ".asc").exists()]
    if missing or unsigned:
        sys.exit(f"error: {artifact.prefix}: missing {missing}, no signature for {unsigned}")
    return files


def write_bundle(signed_dir: Path, artifact: Artifact, out_dir: Path) -> Path:
    bundle = out_dir / f"central-bundle-{artifact.prefix}.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in artifact_files(signed_dir, artifact):
            data = path.read_bytes()
            entry = f"{artifact.repo_dir}/{path.name}"
            zf.writestr(entry, data)
            zf.write(path.with_name(path.name + ".asc"), entry + ".asc")
            for algorithm in CHECKSUMS:
                zf.writestr(f"{entry}.{algorithm}", hashlib.new(algorithm, data).hexdigest())
    return bundle


def main(argv: list[str]) -> None:
    if len(argv) != 3:
        sys.exit(__doc__)
    signed_dir, out_dir = Path(argv[1]), Path(argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    for artifact in find_artifacts(signed_dir):
        print(write_bundle(signed_dir, artifact, out_dir))


if __name__ == "__main__":
    main(sys.argv)
