#!/usr/bin/env python3
"""
automatic.py

Runs the detection-repo export (detection-repo-export.py), then combines
the resulting rule JSON files into one file via json_automatic_mapper.py.
Categories are discovered from the detection repo's folder names --
nothing here is hardcoded.

Usage:
    python3 automatic.py --config config.yaml \
        --combined-output rules/_all_rules_combined.json

Expects detection-repo-export.py and json_automatic_mapper.py to live in
the same directory as this script.
"""

import argparse
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Only source: the shared YAML detection repo, grouped by category.
EXPORT_SCRIPTS = [
    "detection-repo-export.py",
]


def log(msg, err=False):
    """Always flush -- CI has no TTY, so unflushed prints arrive out of order."""
    print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def run_script(script_name, config_path, allow_missing=False):
    """
    Runs one child script. Returns True on success, False on failure.
    A missing script is a failure unless allow_missing is True.
    """
    script_path = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.isfile(script_path):
        if allow_missing:
            log(f"WARNING: {script_path} not found, skipping")
            return True
        log(f"!!! MISSING SCRIPT: {script_path}", err=True)
        return False

    log(f"--- running {script_name} ---")
    # -u on the child too, so its output interleaves correctly with ours.
    result = subprocess.run(
        [sys.executable, "-u", script_path, "--config", config_path]
    )
    if result.returncode != 0:
        log(f"!!! FAILED: {script_name} (exit {result.returncode})", err=True)
        return False

    log(f"--- ok: {script_name} ---")
    return True


def main():
    parser = argparse.ArgumentParser(description="Run the detection-repo export, then combine results.")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument(
        "--combined-output",
        default="rules/_all_rules_combined.json",
        help="Path to write the combined JSON produced by json_automatic_mapper.py",
    )
    parser.add_argument(
        "--allow-missing-scripts",
        action="store_true",
        help="Treat a missing export script as a skip instead of a failure",
    )
    parser.add_argument(
        "--skip-combine-on-error",
        action="store_true",
        help="Do not run json_automatic_mapper.py if any export step failed "
             "(prevents building a combined file from stale on-disk rules)",
    )
    args = parser.parse_args()

    export_scripts = list(EXPORT_SCRIPTS)

    config_path = os.path.abspath(args.config)
    if not os.path.isfile(config_path):
        log(f"!!! config not found: {config_path}", err=True)
        sys.exit(2)

    log(f"config      : {config_path}")
    log(f"working dir : {os.getcwd()}")
    log(f"output      : {os.path.abspath(args.combined_output)}")

    failed = []
    for script_name in export_scripts:
        if not run_script(script_name, config_path, allow_missing=args.allow_missing_scripts):
            failed.append(script_name)

    if failed and args.skip_combine_on_error:
        log(f"FAILED STEPS: {', '.join(failed)}", err=True)
        log("skipping combine step because an export failed (--skip-combine-on-error)", err=True)
        sys.exit(1)

    log("--- combining all exported rules ---")
    mapping_script = os.path.join(SCRIPT_DIR, "json_automatic_mapper.py")
    if not os.path.isfile(mapping_script):
        log(f"!!! MISSING SCRIPT: {mapping_script}", err=True)
        failed.append("json_automatic_mapper.py")
    else:
        out_dir = os.path.dirname(os.path.abspath(args.combined_output))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        combine_cmd = [
            sys.executable, "-u", mapping_script,
            "--config", config_path,
            "--output", args.combined_output,
        ]
        result = subprocess.run(combine_cmd)
        if result.returncode != 0:
            log(f"!!! FAILED: json_automatic_mapper.py (exit {result.returncode})", err=True)
            failed.append("json_automatic_mapper.py")

    if failed:
        log("", err=True)
        log("=" * 60, err=True)
        log(f"FAILED STEPS: {', '.join(failed)}", err=True)
        log("=" * 60, err=True)
        sys.exit(1)

    log("automatic.py finished successfully")


if __name__ == "__main__":
    main()