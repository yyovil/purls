#!/usr/bin/env python3
"""
Resolve SBOM components to their Nix source file via `meta.position`.

This does not read `meta.position` from the SBOM itself. Instead, it maps each
component back to a likely nixpkgs attribute and asks Nix for that attribute's
`meta.position`, which points at the defining Nix file and line.

Examples:
  python3 extract_meta_position.py sbom.json
  python3 extract_meta_position.py sbom.json --format csv
  python3 extract_meta_position.py sbom.json --include-root --skip-missing
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "sbom_path",
        nargs="?",
        default="sbom.json",
        help="Path to CycloneDX SBOM JSON (default: sbom.json)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "csv", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--include-root",
        action="store_true",
        help="Include metadata.component in addition to top-level components",
    )
    parser.add_argument(
        "--skip-missing",
        action="store_true",
        help="Skip components that could not be resolved to a Nix source file",
    )
    return parser.parse_args()


def load_sbom(path: Path) -> Mapping[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"Unable to read '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in '{path}': {exc}") from exc


def iter_components(doc: Mapping[str, Any], include_root: bool) -> Iterable[Mapping[str, Any]]:
    if include_root:
        root = doc.get("metadata", {}).get("component")
        if isinstance(root, Mapping):
            yield root

    for component in doc.get("components", []):
        if isinstance(component, Mapping):
            yield component


def unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def heuristic_attr_paths(component_name: str, component_version: str) -> list[str]:
    candidates = [component_name]

    if component_name == "bash":
        candidates.extend(["bashNonInteractive", "runtimeShellPackage"])

    if component_name == "nss-cacert":
        candidates.append("cacert")

    python_module_match = re.match(r"^python3\.(\d+)-(.+)$", component_name)
    if python_module_match:
        python_minor = python_module_match.group(1)
        module_name = python_module_match.group(2)
        candidates.extend(
            [
                f"python3Packages.{module_name}",
                f"python3{python_minor}Packages.{module_name}",
            ]
        )
        if "-" in module_name:
            underscored = module_name.replace("-", "_")
            candidates.extend(
                [
                    f"python3Packages.{underscored}",
                    f"python3{python_minor}Packages.{underscored}",
                ]
            )

    python_interpreter_match = re.match(r"^python3-(\d+)\.(\d+)\.", component_name)
    if python_interpreter_match:
        major = python_interpreter_match.group(1)
        minor = python_interpreter_match.group(2)
        candidates.extend(["python3", f"python{major}{minor}"])

    version_suffix_match = re.match(r"^(.+)-(\d[0-9A-Za-z._-]*)$", component_name)
    if version_suffix_match:
        candidates.append(version_suffix_match.group(1))

    # If the component version is available, try the plain package name as well.
    if component_version:
        candidates.append(component_name.removesuffix(f"-{component_version}"))

    return unique(candidates)


def search_to_attr_path(search_key: str) -> str:
    parts = search_key.split(".")
    if len(parts) >= 3 and parts[0] in {"legacyPackages", "packages"}:
        return ".".join(parts[2:])
    return search_key


@lru_cache(maxsize=None)
def search_attr_paths(component_name: str) -> list[str]:
    regex = f"^{re.escape(component_name)}$"
    proc = subprocess.run(
        ["nix", "search", "nixpkgs", regex, "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        return []

    first_line = proc.stdout.splitlines()[0]
    try:
        data = json.loads(first_line)
    except json.JSONDecodeError:
        return []

    return unique(search_to_attr_path(key) for key in data)


def nix_expr_for_attr_path(attr_path: str) -> str:
    path_json = json.dumps(attr_path.split("."))
    return f"""
let
  pkgs = import <nixpkgs> {{}};
  lib = pkgs.lib;
  path = builtins.fromJSON ''{path_json}'';
  getAttrPath = remaining: value:
    if remaining == [] then value
    else getAttrPath (builtins.tail remaining) (builtins.getAttr (builtins.head remaining) value);
  pkg = getAttrPath path pkgs;
  rawName = if pkg ? name then pkg.name else null;
  version = if pkg ? version then pkg.version else null;
  strippedName =
    if rawName != null && version != null && lib.hasSuffix ("-" + version) rawName
    then lib.removeSuffix ("-" + version) rawName
    else rawName;
  meta = if pkg ? meta then pkg.meta else {{}};
in {{
  attrPath = lib.concatStringsSep "." path;
  name = rawName;
  strippedName = strippedName;
  pname = if pkg ? pname then pkg.pname else null;
  version = version;
  metaPosition = meta.position or null;
}}
""".strip()


@lru_cache(maxsize=None)
def resolve_attr_path(attr_path: str) -> dict[str, Any] | None:
    proc = subprocess.run(
        ["nix-instantiate", "--eval", "--strict", "--json", "-E", nix_expr_for_attr_path(attr_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def split_meta_position(meta_position: str | None) -> tuple[str, str]:
    if not meta_position:
        return "", ""

    match = re.match(r"^(.*):([0-9]+)$", meta_position)
    if not match:
        return meta_position, ""
    return match.group(1), match.group(2)


def match_score(
    component_name: str,
    component_version: str,
    attr_path: str,
    resolved: Mapping[str, Any],
    from_search: bool,
) -> tuple[int, int]:
    score = 0

    if attr_path == component_name:
        score += 80
    if resolved.get("strippedName") == component_name:
        score += 60
    if resolved.get("name") == component_name:
        score += 60
    if resolved.get("pname") == component_name:
        score += 50
    if component_version and resolved.get("version") == component_version:
        score += 25
    if from_search:
        score -= 5

    # Prefer shallower attr paths when multiple candidates resolve.
    depth_penalty = attr_path.count(".")
    return (score, -depth_penalty)


def resolve_component(component: Mapping[str, Any]) -> dict[str, str]:
    component_name = str(component.get("name", ""))
    component_version = str(component.get("version", ""))

    def choose_best(candidates: Iterable[tuple[str, bool]]) -> tuple[tuple[int, int], dict[str, Any]] | None:
        best_match: tuple[tuple[int, int], dict[str, Any]] | None = None
        for attr_path, from_search in unique_candidate_pairs(candidates):
            resolved = resolve_attr_path(attr_path)
            if not resolved:
                continue
            position = resolved.get("metaPosition")
            if not position:
                continue
            score = match_score(component_name, component_version, attr_path, resolved, from_search)
            if best_match is None or score > best_match[0]:
                best_match = (score, resolved)
        return best_match

    heuristic_candidates = [(attr_path, False) for attr_path in heuristic_attr_paths(component_name, component_version)]
    best = choose_best(heuristic_candidates)

    if best is None:
        search_candidates = [(attr_path, True) for attr_path in search_attr_paths(component_name)]
        best = choose_best(search_candidates)

    if best is None:
        return {
            "name": component_name,
            "version": component_version,
            "bom-ref": str(component.get("bom-ref", "")),
            "attr_path": "",
            "file": "",
            "line": "",
            "meta.position": "",
        }

    resolved = best[1]
    meta_position = str(resolved.get("metaPosition", ""))
    file_path, line = split_meta_position(meta_position)
    return {
        "name": component_name,
        "version": component_version,
        "bom-ref": str(component.get("bom-ref", "")),
        "attr_path": str(resolved.get("attrPath", "")),
        "file": file_path,
        "line": line,
        "meta.position": meta_position,
    }


def unique_candidate_pairs(values: Iterable[tuple[str, bool]]) -> list[tuple[str, bool]]:
    seen: set[str] = set()
    result: list[tuple[str, bool]] = []
    for attr_path, from_search in values:
        if attr_path in seen:
            continue
        seen.add(attr_path)
        result.append((attr_path, from_search))
    return result


def main() -> int:
    args = parse_args()
    doc = load_sbom(Path(args.sbom_path))
    rows = []

    for component in iter_components(doc, include_root=args.include_root):
        row = resolve_component(component)
        if args.skip_missing and not row["meta.position"]:
            continue
        rows.append(row)

    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    fieldnames = ["name", "version", "attr_path", "file", "line", "meta.position", "bom-ref"]
    if args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        return 0

    if not rows:
        print("No components found.")
        return 0

    for row in rows:
        print(
            "\t".join(
                [
                    row["name"],
                    row["attr_path"],
                    row["file"],
                    row["line"],
                ]
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
