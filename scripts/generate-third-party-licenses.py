#!/usr/bin/env python3
"""Regenerate the Cargo dependency license inventory from Cargo.lock."""

import json
from pathlib import Path
import subprocess
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "THIRD_PARTY_LICENSES.md"


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> None:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            cwd=ROOT,
            text=True,
        )
    )
    packages = sorted(
        (package for package in metadata["packages"] if package["source"]),
        key=lambda package: (package["name"].lower(), package["version"], package["source"]),
    )
    rows = []
    for package in packages:
        license_name = package.get("license")
        if not license_name:
            raise SystemExit(
                f"{package['name']} {package['version']} has no license expression; review its license_file manually"
            )
        name = package["name"]
        version = package["version"]
        source = package["source"]
        if source.startswith("registry+"):
            url = f"https://crates.io/crates/{quote(name)}/{quote(version)}"
        else:
            url = package.get("repository") or source.removeprefix("git+").split("#", 1)[0]
        rows.append(f"| [{cell(name)} {cell(version)}]({url}) | {cell(license_name)} |")

    content = "\n".join(
        [
            "# Third-party Cargo licenses",
            "",
            "Generated from the full workspace resolution in `Cargo.lock` with",
            "`python scripts/generate-third-party-licenses.py` (`cargo metadata --locked`).",
            "This includes target-specific, build-time, and development dependencies; a",
            "particular binary may use only a subset. Tervano's own crates are excluded.",
            "License expressions are package metadata, not a legal review. Follow each",
            "package link for its full license text and any additional notices.",
            "",
            f"Resolved third-party packages: {len(rows)}.",
            "",
            "| Package | Declared license |",
            "|---|---|",
            *rows,
            "",
        ]
    )
    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT} ({len(rows)} packages)")


if __name__ == "__main__":
    main()
