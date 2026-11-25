#!/usr/bin/env python3
"""
json_automatic_mapper.py

Combines previously-exported rule JSON files into one file for the coverage
report.

The source is a YAML detection-rule repository, exported by
detection-repo-export.py into:

    <detection_repo.output_root>/<category>/Rules_json/*.json

The combined file is grouped by CATEGORY:

    {
      "email":    {"detection_repo": [rule, ...]},
      "endpoint": {"detection_repo": [rule, ...]},
      ...
    }

generate_coverage_html.py consumes {group: {source: [rules]}} without caring
what the group means -- the per-rule pill just reads "endpoint / detection_repo".

Usage:
    python3 json_automatic_mapper.py --config config.yaml \
        --output rules/_all_rules_combined.json
"""

import argparse
import json
import os
import sys

import yaml

# Generated/meta files that live alongside rule files but aren't rules
# themselves -- skip these when reading a directory.
SKIP_PREFIXES = ("_index", "_all_rules_combined")


def log(msg, err=False):
    print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def load_rules_from_dir(directory):
    rules = []
    if not os.path.isdir(directory):
        log(f"WARNING: directory not found, skipping: {directory}")
        return rules

    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".json"):
            continue
        if any(fname.startswith(p) for p in SKIP_PREFIXES):
            continue
        fpath = os.path.join(directory, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            try:
                rules.append(json.load(f))
            except json.JSONDecodeError as e:
                log(f"WARNING: skipping unparsable file {fpath}: {e}", err=True)
    return rules


def build_detection_repo(config):
    """
    Discovers categories from the export output root -- whatever
    detection-repo-export.py wrote is what gets combined, so a new category
    folder in the detection repo flows through with no config change.
    """
    repo_cfg = config.get("detection_repo") or {}
    output_root = repo_cfg.get("output_root", "rules/detection_repo")

    if not os.path.isdir(output_root):
        log(f"WARNING: detection repo export root not found: {output_root}", err=True)
        return {}

    combined = {}
    for category in sorted(os.listdir(output_root)):
        cat_dir = os.path.join(output_root, category)
        if not os.path.isdir(cat_dir) or category.startswith("."):
            continue
        rules_dir = os.path.join(cat_dir, "Rules_json")
        if not os.path.isdir(rules_dir):
            continue
        rules = load_rules_from_dir(rules_dir)
        if rules:
            combined[category] = {"detection_repo": rules}
    return combined


def main():
    parser = argparse.ArgumentParser(
        description="Combine exported rule JSON files, grouped by detection-repo category."
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--output", required=True, help="Path to write the combined JSON")
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Write the combined file even when no rules were found (default: fail)",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    combined = build_detection_repo(config)

    total = sum(len(rules) for sources in combined.values() for rules in sources.values())

    if total == 0 and not args.allow_empty:
        log("ERROR: no rules found to combine -- refusing to write an empty combined file.", err=True)
        log("       (this would silently produce a 0% coverage report)", err=True)
        sys.exit(1)

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, sort_keys=True, ensure_ascii=False)

    log(f"combined rules for {len(combined)} group(s):")
    for name, sources in combined.items():
        parts = ", ".join(f"{src}={len(rules)}" for src, rules in sources.items())
        log(f"  {name}: {parts if parts else 'no sources'}")
    log(f"total {total} rule(s)")
    log(f"written to {args.output}")


if __name__ == "__main__":
    main()