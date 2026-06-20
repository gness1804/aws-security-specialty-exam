# Phase 3 scripts

Run from an activated venv with `boto3` installed. All scripts use named AWS
profiles (`--profile`), never embedded credentials, and never print secret values.
Creating/destructive actions default to dry-run; pass `--apply` to act. The setup
scripts import the shared `_deploy.py` helper, so run them **from this directory**.

| Script | What it does | Destructive? |
|--------|--------------|--------------|
| `custom_sg_config_rule_lambda.py` | Lambda for 3.2: judges SGs for 22/3389 open to the world (read after B3.2) | No (library) |
| `guardduty_nacl_remediation_lambda.py` | Lambda for 3.3: blocks a finding's attacker IP at a NACL (read after B3.3) | No (library) |
| `_deploy.py` | Shared zip/role/function/permission helpers for the setup scripts | No (library) |
| `setup_config_remediation.py` | 3.1: Config recorder + delivery channel + managed rule + SSM auto-remediation | Creates (`--apply`); `--teardown` removes |
| `setup_custom_config_rule.py` | 3.2: deploys the custom-rule Lambda + custom Config rule | Creates (`--apply`); `--teardown` removes |
| `setup_guardduty_remediation.py` | 3.3: deploys the Lambda + EventBridge rule wiring | Creates (`--apply`); `--teardown` removes |
| `enable_securityhub_inspector.py` | 3.4: enables Security Hub (+FSBP) and Inspector | Enables (`--apply`); `--disable` turns off |

## Typical Phase 3 session

```bash
source ../../.venv/bin/activate      # adjust path to your venv

# 3.1 — Config + auto-remediation (dry-run first, then --apply)
python setup_config_remediation.py --delivery-bucket scs-config-<ACCT> \
    --profile scs-member --apply

# 3.2 — custom SG Config rule
python setup_custom_config_rule.py --profile scs-member --apply

# 3.3 — GuardDuty -> NACL remediation (needs a GuardDuty detector + a NACL id)
python setup_guardduty_remediation.py --nacl-id <ACL_ID> --profile scs-member --apply
aws guardduty create-sample-findings --detector-id <DETECTOR_ID> \
    --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" --profile scs-member

# 3.4 — Security Hub + Inspector
python enable_securityhub_inspector.py --profile scs-member --apply
```

## Teardown (run at end of session — these services bill continuously)

```bash
python setup_guardduty_remediation.py --profile scs-member --teardown --apply
python setup_custom_config_rule.py --profile scs-member --teardown --apply
python setup_config_remediation.py --profile scs-member --teardown --apply
python enable_securityhub_inspector.py --profile scs-member --disable --apply
# then: aws guardduty delete-detector ...; remove NACL deny entries; delete buckets
python ../phase-1/teardown_check.py --profile scs-member   # cross-cutting sweep
```

## Safety notes (same rules as Phases 1–2)

- **No secrets to output.** These scripts handle resource ids and IAM policy
  documents only — no credentials, keys, or secret values are ever printed.
- **Dry-run by default.** Every creating/destructive path requires `--apply`.
- **Idempotent where it counts.** Role/permission creation tolerates re-runs; the
  NACL Lambda skips IPs it has already denied.
