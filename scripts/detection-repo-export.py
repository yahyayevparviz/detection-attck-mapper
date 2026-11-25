#!/usr/bin/env python3
"""
detection-repo-export.py

Reads detection rules out of a YAML detection-rule repository and writes
one normalised JSON file per rule, which json_automatic_mapper.py and
generate_coverage_html.py consume.

Source layout (one YAML file per rule, category = the folder under
"detections/"; category names are free-form and discovered at runtime):

    detections/
      endpoint/     identity/     network/     web/     ...

Each rule file carries a "metadata:" block:

    metadata:
      id: "WEB-WAF-001"
      name: "Web Shell Command Execution"
      description: "..."
      date: "2026-08-26"
      version: "0.1.0"
      status: "active"
      deployment:
        stage: "test"             # test | prod  (omit block => prod)
        test_since: "2026-07-20"
        test_period_days: 14      # optional, defaults to 14
      mitre:
      - tactic: "Initial Access"
        tactic_id: "TA0001"
        technique: "Exploit Public-Facing Application"
        technique_id: "T1190"
      - tactic: "Execution"
        tactic_id: "TA0002"
        technique: "Command and Scripting Interpreter: Unix Shell"
        technique_id: "T1059.004"

    => mitre_attack: ["TA0001:T1190", "TA0002:T1059.004"]

mitre is a LIST, one item per tactic/technique mapping. Rule files may sit
at any depth under their category folder (e.g.
detections/email/gateway/vendor_x/<rule>.yaml); the category is the
first folder under "detections/".

The older single-block form is still accepted: ONE mitre block with
comma-separated values.
They pair left to right -- nth tactic with nth technique -- and a field
holding a single value covers every pair:

      mitre:
        tactic: "Command and Control"
        tactic_id: "TA0011"
        technique: "Application Layer Protocol: DNS, Protocol Tunneling"
        technique_id: "T1071.004, T1572"

    => mitre_attack: ["TA0011:T1071.004", "TA0011:T1572"]

Output (one JSON per rule, plus an _index.json per category):

    rules/detection_repo/<category>/Rules_json/<rule>.json

Usage:
    python3 detection-repo-export.py --config config.yaml
    python3 detection-repo-export.py --config config.yaml --repo-path ./detection-repo
    python3 detection-repo-export.py --config config.yaml --clone

Dependencies:
    pip install pyyaml
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import traceback

import yaml

DEFAULT_TEST_PERIOD_DAYS = 14


def log(msg, err=False):
    print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    repo_cfg = cfg.get("detection_repo")
    if not repo_cfg:
        raise ValueError(f"'{path}' has no top-level 'detection_repo' key")
    return repo_cfg


def sanitize_filename(name):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name)).strip("_")
    return cleaned or "unnamed_rule"


# ---------------------------------------------------------------------------
# MITRE normalisation
# ---------------------------------------------------------------------------

def _split_list(value):
    """
    "T1071.004, T1572"  -> ["T1071.004", "T1572"]
    "T1098"             -> ["T1098"]
    None / ""           -> []

    Already-a-list values are accepted too, so a repo that switches to real
    YAML lists later keeps working without a change here.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _broadcast(values, n, field, rule_id, warnings):
    """
    A field holding exactly one value covers every pair; a field holding n
    values pairs up left to right. Anything else is a malformed rule.
    """
    if len(values) == n:
        return values
    if len(values) == 1:
        return values * n
    warnings.append(
        f"[{rule_id}] mitre.{field} has {len(values)} value(s) but the rule maps "
        f"{n} technique(s); expected 1 or {n}"
    )
    return None


def normalize_mitre(mitre, rule_id, warnings):
    """
    Turns the mitre block into:
      - mitre_attack: ["TA00XX:T1XXX", ...]   (what the mapper/report consume)
      - mitre_pairs:  [{tactic, tactic_id, technique, technique_id}, ...]

    Handles both supported forms:
      1. one block with comma-separated values, paired left to right
      2. a LIST of blocks (used when an ATT&CK name itself contains a comma)

    Returns (mitre_attack, mitre_pairs).
    """
    # Form 2: a list of single-mapping blocks. Each block is normalised on its
    # own and the results concatenated, so a comma inside a name is harmless.
    if isinstance(mitre, (list, tuple)):
        all_attack, all_pairs = [], []
        for block in mitre:
            # List form = one mapping per item, so a name is never
            # comma-split (an ATT&CK name may itself contain a comma).
            if (isinstance(block, dict)
                    and "," not in str(block.get("tactic_id") or "")
                    and "," not in str(block.get("technique_id") or "")):
                block = dict(
                    block,
                    tactic=[str(block.get("tactic") or "")],
                    technique=[str(block.get("technique") or "")],
                )
            attack, pairs = normalize_mitre(block, rule_id, warnings)
            all_attack.extend(attack)
            all_pairs.extend(pairs)
        # De-duplicate while preserving order (the first pair stays first).
        seen = set()
        deduped_attack, deduped_pairs = [], []
        for entry, pair in zip(all_attack, all_pairs):
            if entry in seen:
                continue
            seen.add(entry)
            deduped_attack.append(entry)
            deduped_pairs.append(pair)
        return deduped_attack, deduped_pairs

    if not isinstance(mitre, dict):
        return [], []

    tactic_ids = _split_list(mitre.get("tactic_id"))
    technique_ids = _split_list(mitre.get("technique_id"))
    tactics = _split_list(mitre.get("tactic"))
    techniques = _split_list(mitre.get("technique"))

    if not tactic_ids or not technique_ids:
        if mitre:
            warnings.append(
                f"[{rule_id}] mitre block present but missing tactic_id and/or technique_id"
            )
        return [], []

    # The number of mappings is driven by the ID fields -- names are cosmetic
    # and a name containing a comma (e.g. "Application Layer Protocol: DNS")
    # must never change how many pairs we produce.
    n = max(len(tactic_ids), len(technique_ids))

    tactic_ids = _broadcast(tactic_ids, n, "tactic_id", rule_id, warnings)
    technique_ids = _broadcast(technique_ids, n, "technique_id", rule_id, warnings)
    if tactic_ids is None or technique_ids is None:
        return [], []

    # A name field should carry as many values as its _id field. Warn on a mismatch but still map the rule -- a wrong label is a
    # lot less costly than dropping real coverage over one.
    def pad(values, field):
        if len(values) == n or len(values) == 1:
            return (values * n) if len(values) == 1 else values
        if values:
            warnings.append(
                f"[{rule_id}] mitre.{field} has {len(values)} value(s) but the rule maps "
                f"{n} technique(s); labels may not line up"
            )
        return values + [""] * (n - len(values)) if len(values) < n else values[:n]

    tactics = pad(tactics, "tactic")
    techniques = pad(techniques, "technique")

    mitre_attack = []
    pairs = []
    for i in range(n):
        ta = tactic_ids[i].upper()
        tech = technique_ids[i].upper()
        if not re.fullmatch(r"TA\d{4}", ta):
            warnings.append(f"[{rule_id}] tactic_id {ta!r} is not in TA#### form")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tech):
            warnings.append(f"[{rule_id}] technique_id {tech!r} is not in T#### / T####.### form")
        mitre_attack.append(f"{ta}:{tech}")
        pairs.append(
            {
                "tactic": tactics[i] if i < len(tactics) else "",
                "tactic_id": ta,
                "technique": techniques[i] if i < len(techniques) else "",
                "technique_id": tech,
            }
        )

    return mitre_attack, pairs


# ---------------------------------------------------------------------------
# Deployment stage
# ---------------------------------------------------------------------------

def _parse_date(value):
    if not value:
        return None
    if isinstance(value, datetime.date):
        return value
    try:
        return datetime.date.fromisoformat(str(value).strip())
    except ValueError:
        return None


def resolve_deployment(metadata, rule_id, warnings, today=None):
    """
    Returns (stage, info_dict). Omitting the deployment block means prod.
    When stage is test, works out when the test window closes so the report
    can show which test rules have run past their clock.
    """
    today = today or datetime.date.today()
    deployment = metadata.get("deployment")

    if not isinstance(deployment, dict) or not deployment:
        return "prod", {"deployment_stage": "prod"}

    stage = str(deployment.get("stage") or "prod").strip().lower()
    if stage not in ("test", "prod"):
        warnings.append(f"[{rule_id}] unknown deployment.stage {stage!r}; treating as prod")
        stage = "prod"

    info = {"deployment_stage": stage}
    if stage != "test":
        return stage, info

    since = _parse_date(deployment.get("test_since"))
    if since is None:
        warnings.append(f"[{rule_id}] deployment.stage is test but test_since is missing/unparsable")
        return stage, info

    try:
        period = int(deployment.get("test_period_days", DEFAULT_TEST_PERIOD_DAYS))
    except (TypeError, ValueError):
        warnings.append(f"[{rule_id}] test_period_days is not a number; using {DEFAULT_TEST_PERIOD_DAYS}")
        period = DEFAULT_TEST_PERIOD_DAYS

    expires = since + datetime.timedelta(days=period)
    info.update(
        {
            "test_since": since.isoformat(),
            "test_period_days": period,
            "test_expires_on": expires.isoformat(),
            "test_expired": today > expires,
            "test_days_remaining": (expires - today).days,
        }
    )
    return stage, info


# ---------------------------------------------------------------------------
# Rule extraction
# ---------------------------------------------------------------------------

# Per-SIEM query blocks recognised at the top level of a rule file.
SIEM_BLOCKS = {
    "splunk": ("search", "search"),            # yaml key -> (query field, promoted name)
    "crowdstrike": ("search", "crowdstrike_search"),
    "qradar": ("aql", "qradar_aql"),
}

# Placeholder values used by a rule template; a rule still carrying them is
# an unfilled template, not a real detection.
TEMPLATE_IDS = {"XXX-XXX-000", "ID-XXX-000"}
TEMPLATE_NAMES = {"Detection Name"}


def is_template(metadata):
    rule_id = str(metadata.get("id") or "").strip()
    name = str(metadata.get("name") or "").strip()
    if rule_id in TEMPLATE_IDS or name in TEMPLATE_NAMES:
        return True
    # Placeholder MITRE values from the template.
    mitre = metadata.get("mitre")
    blocks = mitre if isinstance(mitre, (list, tuple)) else [mitre]
    for block in blocks:
        if isinstance(block, dict) and str(block.get("tactic_id") or "").strip().upper() == "TA0000":
            return True
    return False


def extract_rule_data(doc, category, rel_path, warnings):
    """
    Flattens one parsed YAML rule file into the record shape the rest of the
    pipeline expects. metadata.* is promoted to the top level (so `name` and
    `mitre_attack` are where the mapper looks); every other top-level key in
    the file is preserved under `detection` so the report can still show the
    query/logic.
    """
    metadata = doc.get("metadata") if isinstance(doc, dict) else None
    if not isinstance(metadata, dict):
        warnings.append(f"[{rel_path}] no 'metadata:' block; skipped")
        return None

    if is_template(metadata):
        log(f"  skipping template file: {rel_path}")
        return None

    rule_id = metadata.get("id") or rel_path
    # mitre normally lives under metadata; accept a top-level block too.
    mitre_block = metadata.get("mitre") or doc.get("mitre")
    mitre_attack, mitre_pairs = normalize_mitre(mitre_block, rule_id, warnings)
    stage, deployment_info = resolve_deployment(metadata, rule_id, warnings)

    record = {
        "id": metadata.get("id"),
        "name": metadata.get("name") or metadata.get("id") or os.path.basename(rel_path),
        "description": metadata.get("description"),
        "author": metadata.get("author"),
        "date": str(metadata.get("date")) if metadata.get("date") is not None else None,
        "version": str(metadata.get("version")) if metadata.get("version") is not None else None,
        "status": metadata.get("status"),
        "severity": metadata.get("severity"),
        "category": category,
        "source_file": rel_path,
        "mitre_attack": mitre_attack,
        "mitre_pairs": mitre_pairs,
    }
    record.update(deployment_info)

    supported = metadata.get("supported_siems")
    if supported:
        record["supported_siems"] = supported if isinstance(supported, list) else [supported]

    # Promote each per-SIEM query to a top-level field so the report renders it
    # as a code block (its SEARCH_KEYS look at `search`/`query`), and record
    # each SIEM's schedule alongside.
    implemented = []
    for block_name, (query_key, promoted) in SIEM_BLOCKS.items():
        block = doc.get(block_name)
        if not isinstance(block, dict):
            continue
        query = block.get(query_key)
        if query and str(query).strip():
            record[promoted] = query
            implemented.append(block_name)
        schedule = block.get("schedule")
        if isinstance(schedule, dict):
            if schedule.get("cron"):
                record.setdefault(f"{block_name}_cron", schedule["cron"])
            for extra_key in ("earliest_time", "latest_time", "lookback"):
                if schedule.get(extra_key):
                    record.setdefault(f"{block_name}_{extra_key}", schedule[extra_key])

    if implemented:
        record["implemented_in"] = implemented

    # Anything else the rule file carries at the top level (response steps,
    # references, tuning notes...) rides along so the report can show it.
    extras = {
        k: v for k, v in doc.items()
        if k not in ("metadata", "mitre") and k not in SIEM_BLOCKS
    }
    if extras:
        record["detection"] = extras

    # Keep any metadata keys we did not explicitly promote.
    known = {
        "id", "name", "description", "author", "date", "version", "status",
        "deployment", "mitre", "severity", "supported_siems",
    }
    leftover = {k: v for k, v in metadata.items() if k not in known}
    if leftover:
        record["metadata_extra"] = leftover

    return record


def discover_categories(detections_dir):
    if not os.path.isdir(detections_dir):
        raise RuntimeError(f"detections directory not found: {detections_dir}")
    return sorted(
        d for d in os.listdir(detections_dir)
        if os.path.isdir(os.path.join(detections_dir, d)) and not d.startswith(".")
    )


def load_category_rules(detections_dir, category, warnings):
    """Walks a category folder recursively; one rule per .yml/.yaml file."""
    root = os.path.join(detections_dir, category)
    rules = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in sorted(filenames):
            if not fname.lower().endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(fpath, detections_dir)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
            except yaml.YAMLError as e:
                warnings.append(f"[{rel_path}] YAML parse error: {e}")
                continue
            if doc is None:
                warnings.append(f"[{rel_path}] file is empty; skipped")
                continue
            record = extract_rule_data(doc, category, rel_path, warnings)
            if record:
                rules.append(record)
    return rules


def save_rules(rules, output_dir, category):
    os.makedirs(output_dir, exist_ok=True)
    index = []
    seen = {}
    for rule in rules:
        base = sanitize_filename(rule.get("id") or rule.get("name"))
        # Two rules with the same id would otherwise overwrite each other.
        seen[base] = seen.get(base, 0) + 1
        fname = f"{base}.json" if seen[base] == 1 else f"{base}__{seen[base]}.json"
        with open(os.path.join(output_dir, fname), "w", encoding="utf-8") as f:
            json.dump(rule, f, indent=2, ensure_ascii=False)
        index.append(
            {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "file": fname,
                "stage": rule.get("deployment_stage"),
                "source_file": rule.get("source_file"),
            }
        )

    with open(os.path.join(output_dir, "_index.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "category": category,
                "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "rule_count": len(rules),
                "rules": index,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )


def ensure_repo(repo_cfg, repo_path, do_clone):
    """
    CI clones the repo before running this script (see .gitlab-ci.yml). The
    --clone path is a convenience for running locally.
    """
    if os.path.isdir(os.path.join(repo_path, ".git")) or os.path.isdir(repo_path):
        return repo_path

    if not do_clone:
        raise RuntimeError(
            f"repo path not found: {repo_path}\n"
            f"       clone it first, or re-run with --clone"
        )

    repo_url = repo_cfg.get("repo_url")
    if not repo_url:
        raise RuntimeError("--clone requested but detection_repo.repo_url is not set in the config")

    token_env = repo_cfg.get("token_env")
    token = os.environ.get(token_env) if token_env else None
    url = repo_url
    if token:
        token = token.strip()
        url = repo_url.replace("https://", f"https://oauth2:{token}@", 1)

    branch = repo_cfg.get("branch")
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, repo_path]

    log(f"cloning {repo_url} -> {repo_path}")
    # Never echo the resolved URL; it carries the token.
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = (result.stderr or "").replace(token, "***") if token else (result.stderr or "")
        raise RuntimeError(f"git clone failed (exit {result.returncode}): {stderr.strip()}")
    return repo_path


def main():
    parser = argparse.ArgumentParser(
        description="Export detection rules from a YAML detection repo, grouped by category."
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--repo-path", help="Path to a detection-repo checkout (overrides config local_path)")
    parser.add_argument("--output-root", help="Where to write per-category rule JSON (overrides config)")
    parser.add_argument("--clone", action="store_true", help="git clone the repo if the path is missing")
    parser.add_argument(
        "--exclude-test",
        action="store_true",
        help="Skip rules whose deployment.stage is test",
    )
    args = parser.parse_args()

    repo_cfg = load_config(args.config)

    repo_path = os.path.abspath(args.repo_path or repo_cfg.get("local_path") or "detection-repo")
    output_root = args.output_root or repo_cfg.get("output_root") or "rules/detection_repo"
    detections_subdir = repo_cfg.get("detections_subdir", "detections")
    exclude_test = args.exclude_test or not repo_cfg.get("include_test_stage", True)

    repo_path = ensure_repo(repo_cfg, repo_path, args.clone)
    detections_dir = os.path.join(repo_path, detections_subdir)

    categories = discover_categories(detections_dir)
    log(f"detection repo : {repo_path}")
    log(f"categories     : {', '.join(categories) if categories else '(none found)'}")

    warnings = []
    total = 0
    skipped_test = 0

    for category in categories:
        rules = load_category_rules(detections_dir, category, warnings)
        if exclude_test:
            before = len(rules)
            rules = [r for r in rules if r.get("deployment_stage") != "test"]
            skipped_test += before - len(rules)

        out_dir = os.path.join(output_root, category, "Rules_json")
        save_rules(rules, out_dir, category)
        total += len(rules)

        test_count = sum(1 for r in rules if r.get("deployment_stage") == "test")
        expired = sum(1 for r in rules if r.get("test_expired"))
        suffix = f" ({test_count} in test, {expired} past their test window)" if test_count else ""
        log(f"[{category}] exported {len(rules)} rule(s){suffix} -> {out_dir}")

    if exclude_test and skipped_test:
        log(f"skipped {skipped_test} test-stage rule(s) (--exclude-test)")

    log(f"total: {total} rule(s) across {len(categories)} category/categories")

    if warnings:
        log("", err=True)
        log(f"{len(warnings)} warning(s):", err=True)
        for w in warnings:
            log(f"  {w}", err=True)

    if total == 0:
        log("ERROR: no rules exported -- is the repo checkout empty or the layout different?", err=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"ERROR ({type(e).__name__}): {e}", err=True)
        traceback.print_exc()
        sys.exit(1)