# detection-attck-mapper

Builds a self-contained **MITRE ATT&CK coverage report** (a single HTML file, no server
needed) from a repository of YAML detection rules.

```
YAML rule repo
  -> scripts/detection-repo-export.py   normalise each rule to JSON, per category
  -> scripts/json_automatic_mapper.py   combine into rules/_all_rules_combined.json
  -> scripts/generate_coverage_html.py  rules/coverage_report.html + rules/data.json
```

`scripts/automatic.py` runs the first two steps. The GitLab pipeline (`.gitlab-ci.yml`)
runs all three, optionally commits the refreshed report back, and publishes it with
GitLab Pages.

## Requirements

- Python 3.13 (3.9+ works)
- `pip install -r requirements.txt`

## Quick start (bundled example rules)

`examples/detection-repo/` contains 12 **synthetic** rules across 7 categories (one in
test stage, one deliberately without an ATT&CK mapping).

```bash
pip install -r requirements.txt
python3 scripts/detection-repo-export.py --config scripts/config.yaml --repo-path examples/detection-repo
python3 scripts/json_automatic_mapper.py --config scripts/config.yaml --output rules/_all_rules_combined.json
python3 scripts/generate_coverage_html.py --input rules/_all_rules_combined.json \
        --template scripts/index.html --output rules/coverage_report.html
```

Open `rules/coverage_report.html` in a browser.

## Rule format

One YAML file per rule under `detections/<category>/` (any depth). The category is the
first folder under `detections/` and is discovered automatically.

```yaml
metadata:
  id: "EDR-PRC-001"
  name: "Encoded PowerShell Command Execution"
  description: "..."
  severity: "medium"
  status: "active"
  deployment:              # optional; omitted => prod
    stage: "test"          # test | prod
    test_since: "2026-01-01"
    test_period_days: 14
  mitre:
    - tactic: "Execution"
      tactic_id: "TA0002"
      technique: "Command and Scripting Interpreter: PowerShell"
      technique_id: "T1059.001"
splunk:                    # optional per-SIEM query blocks
  search: 'index=edr process_name=powershell.exe ...'
crowdstrike:
  search: '...'
qradar:
  aql: '...'
```

Supported per-SIEM blocks: `splunk.search`, `crowdstrike.search`, `qradar.aql` (each
may carry a `schedule:` with `cron` / `earliest_time` / `latest_time` / `lookback`).
Any other top-level keys (e.g. `response`, `references`) are kept and shown in the
report. See the docstring of `scripts/detection-repo-export.py` for the full format,
including the older single-block comma-separated `mitre` form.

## Using your own rule repo

1. Edit `scripts/config.yaml` (`repo_url`, `branch`, `detections_subdir`).
2. In GitLab, set these CI/CD variables:

| Variable | Required | Purpose |
|---|---|---|
| `DETECTION_REPO_URL` | yes* | host/path of the rule repo, e.g. `gitlab.com/my-group/detection-repo.git` (cloned with `CI_JOB_TOKEN`). *If unset, the bundled examples are used. |
| `DETECTION_REPO_BRANCH` | no | branch to clone (default `main`) |
| `CI_PUSH_TOKEN` | no | project access token (Developer, `write_repository`) to commit the refreshed report back |
| `CUSTOM_CA_CERT` | no | File-type variable with an extra CA certificate (e.g. TLS inspection proxy) |

3. Allow this project in the rule repo: **Settings → CI/CD → Job token permissions**.
4. Create a pipeline schedule (CI/CD → Schedules). The jobs run on `schedule` and manual
   `web` pipelines only.

Locally you can also let the exporter clone for you:

```bash
export DETECTION_REPO_TOKEN=<read token>
python3 scripts/detection-repo-export.py --config scripts/config.yaml --clone
```

## Notes

- `scripts/mitre_technique_names.json` maps technique IDs to names; per-tactic technique
  totals live in `TACTIC_TECHNIQUE_TOTALS` in `generate_coverage_html.py`. Refresh both
  from MITRE's `enterprise-attack.json` when ATT&CK releases a new version.
- `scripts/index.html` is the report template; its `EMBEDDED_DATA` line is replaced with
  the generated dataset at build time.
