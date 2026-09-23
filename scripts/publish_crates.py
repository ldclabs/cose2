#!/usr/bin/env python3
"""Publish missing workspace versions in dependency order; safe to rerun."""

import argparse
import json
from pathlib import Path
import subprocess
import time
import tomllib
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent


def is_published(name: str, version: str) -> bool:
    url = f"https://crates.io/api/v1/crates/{quote(name, safe='')}/{quote(version, safe='')}"
    request = Request(url, headers={"User-Agent": "cose2-release (github.com/ldclabs/cose2)"})
    try:
        with urlopen(request, timeout=30) as response:
            published = json.load(response)["version"]
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    if published["crate"] != name or published["num"] != version:
        raise ValueError(f"unexpected crates.io response for {name}@{version}")
    return True


def publish(name: str, version: str, dry_run: bool = False) -> None:
    for attempt in range(1, 6):
        # Recheck after a failed upload: the registry may have accepted it even
        # if cargo did not observe success. Never treat a registry error as 404.
        if is_published(name, version):
            print(f"Skipping {name}@{version}: already published", flush=True)
            return
        print(f"Publishing {name}@{version} (attempt {attempt}/5)", flush=True)
        if dry_run:
            return
        result = subprocess.run(["cargo", "publish", "--locked", "-p", name], cwd=ROOT)
        if result.returncode == 0:
            return
        if attempt < 5:
            time.sleep(20)
    raise RuntimeError(f"failed to publish {name}@{version}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="check versions without publishing")
    args = parser.parse_args()
    for manifest in [ROOT / "Cargo.toml", ROOT / "sd-cwt/Cargo.toml"]:
        with manifest.open("rb") as source:
            package = tomllib.load(source)["package"]
        publish(package["name"], package["version"], args.dry_run)


if __name__ == "__main__":
    main()
