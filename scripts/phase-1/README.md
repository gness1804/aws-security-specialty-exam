# Phase 1 scripts

Run from an activated venv with `boto3` installed. All scripts use named AWS
profiles (`--profile`), never embedded credentials, and never print secrets.
Destructive/creating actions default to dry-run; pass `--apply` to act.

| Script | What it does | Destructive? |
|--------|--------------|--------------|
| `setup_cross_account_role.py` | Creates `CrossAccountAuditRole` in Account B with the MFA+IP trust policy | Creates (gated by `--apply`) |
| `assume_role_test.py` | Break/Fix harness: attempts the assume, prints ARN+expiry only | No (read-only) |
| `kms_lockout_demo.py` | Creates a demo CMK; safe by default, `--full-lockout` for the real lockout | Creates (gated by `--apply`) |
| `teardown_check.py` | End-of-session sweep for billable resources; `--apply` disables detectors | Report-only by default |

## Typical Phase 1 session

```bash
source ../../.venv/bin/activate      # adjust path to your venv

# 1.1 — create the cross-account role (dry-run first, then --apply)
python setup_cross_account_role.py --account-a <A_ID> --account-b <B_ID> \
    --user analyst --cidr "$(curl -s https://checkip.amazonaws.com)/32" \
    --profile scs-member
python setup_cross_account_role.py --account-a <A_ID> --account-b <B_ID> \
    --user analyst --cidr "$(curl -s https://checkip.amazonaws.com)/32" \
    --profile scs-member --apply

# 1.1 — test it (run with and without --mfa-serial to see the denial)
python assume_role_test.py --role-arn arn:aws:iam::<B_ID>:role/CrossAccountAuditRole \
    --profile scs-mgmt --mfa-serial arn:aws:iam::<A_ID>:mfa/analyst

# 1.2 — KMS: safe demo key first
python kms_lockout_demo.py --account-b <B_ID> --app-role AppEncryptRole \
    --profile scs-member --apply

# End of session
python teardown_check.py --profile scs-member
```

## Tearing down the cross-account role

Two CLI commands (the role has one attached managed policy):

```bash
aws iam detach-role-policy --role-name CrossAccountAuditRole \
    --policy-arn arn:aws:iam::aws:policy/SecurityAudit --profile scs-member && \
aws iam delete-role --role-name CrossAccountAuditRole --profile scs-member
```
