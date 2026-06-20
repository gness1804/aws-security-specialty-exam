# Phase 4 scripts

Run from an activated venv with `boto3` installed. All scripts use named AWS
profiles (`--profile`), never embedded credentials, and never print secret values.
Creating/destructive actions default to dry-run; pass `--apply` to act. Run them
**from this directory** (the S3 Object Lock script reads a policy file via a path
relative to the repo root).

| Script | What it does | Destructive? |
|--------|--------------|--------------|
| `setup_waf_alb.py` | 4.1: WAF v2 Web ACL (managed XSS+SQLi groups + custom XSS rule), associates it with an ALB | Creates (`--apply`); `--teardown` removes |
| `setup_org_cloudtrail.py` | 4.2: multi-region trail with log-file validation to a CloudTrail-only bucket (`--org-trail` for org mode) | Creates (`--apply`); `--teardown` removes trail |
| `setup_s3_object_lock.py` | 4.3: NEW versioned bucket with Object Lock (COMPLIANCE default) + deny-delete policy | Creates (`--apply`); `--teardown` removes policy only |
| `athena_security_queries.sql` | 4.4: reference DDL + security queries (CloudTrail + Flow Logs) | No (SQL reference) |
| `setup_athena_security.py` | 4.4: creates the `security_audit` DB + projected CloudTrail table, runs the denied-API query | Creates (`--apply`); `--teardown` drops DB/tables |
| `setup_cw_metric_alarms.py` | 4.5: CloudTrail→CW Logs + root-usage/IAM-change metric filters + alarms + SNS | Creates (`--apply`); `--teardown` removes |

## Typical Phase 4 session

```bash
source ../../.venv/bin/activate      # adjust path to your venv

# 4.1 — WAF on an ALB (pass an existing internet-facing ALB ARN)
python setup_waf_alb.py --alb-arn <ALB_ARN> --profile scs-member --apply

# 4.2 — tamper-evident CloudTrail (single-account + validation by default)
python setup_org_cloudtrail.py --bucket scs-trail-<ACCT> --profile scs-member --apply

# 4.3 — WORM log bucket (keep retention SHORT for the lab)
python setup_s3_object_lock.py --bucket scs-worm-<ACCT> --retention-days 1 \
    --profile scs-member --apply

# 4.4 — Athena over CloudTrail
python setup_athena_security.py --cloudtrail-bucket scs-trail-<ACCT> \
    --results-bucket scs-athena-<ACCT> --profile scs-member --apply --run-query

# 4.5 (Stretch) — metric filters + alarms (needs the 4.2 trail to exist)
python setup_cw_metric_alarms.py --profile scs-member --apply --notify-email you@example.com
```

## Teardown (run at end of session — WAF, ALB, extra trails, Athena all bill)

```bash
python setup_cw_metric_alarms.py --profile scs-member --teardown --apply
python setup_athena_security.py --results-bucket scs-athena-<ACCT> --profile scs-member --teardown --apply
python setup_org_cloudtrail.py --profile scs-member --teardown --apply
python setup_waf_alb.py --alb-arn <ALB_ARN> --profile scs-member --teardown --apply
python setup_s3_object_lock.py --bucket scs-worm-<ACCT> --profile scs-member --teardown --apply
# then: delete the ALB/target group/test instance; empty + delete the Athena results
# bucket. COMPLIANCE-locked objects in the WORM bucket cannot be deleted until their
# retention expires -- that is the guarantee, not a bug.
python ../phase-1/teardown_check.py --profile scs-member   # cross-cutting sweep
```

## Safety notes (same rules as Phases 1–3)

- **No secrets to output.** These scripts handle resource ids, ARNs, and IAM policy
  documents only — no credentials, keys, or secret values are ever printed. The
  `--notify-email` value is passed to SNS, never echoed.
- **Dry-run by default.** Every creating/destructive path requires `--apply`.
- **Object Lock is deliberately hard to undo.** COMPLIANCE-mode retention cannot be
  shortened or bypassed by anyone (including root). Use a small `--retention-days`
  in the lab so test buckets free up quickly; `GOVERNANCE` mode is bypassable and
  fine if you want easy cleanup, but read D4.3 for why it's weaker.
