# Phase 2 scripts

Run from an activated venv with `boto3` installed. All scripts use named AWS
profiles (`--profile`), never embedded credentials, and never print secret values.
Creating/destructive actions default to dry-run; pass `--apply` to act.

| Script | What it does | Destructive? |
|--------|--------------|--------------|
| `secrets_rotation_lambda.py` | Reference rotation handler (the four-step contract). Deployed by the setup script; read it *after* sketching B2.1 yourself. | No (library) |
| `setup_secret_rotation.py` | Creates the demo secret + rotation Lambda + role + 30-day rotation | Creates (gated by `--apply`); `--teardown` removes |
| `enforce_s3_encryption.py` | Default SSE-KMS + bucket key + deny-unencrypted-PutObject policy; `--break` runs drill D2.3 | Modifies bucket (gated by `--apply`) |
| `macie_discovery.py` | Enables Macie, adds the SCSLAB custom identifier, creates a one-time discovery job | Creates (gated by `--apply`); `--disable` turns Macie off |

## Typical Phase 2 session

```bash
source ../../.venv/bin/activate      # adjust path to your venv

# 2.1 — rotation (dry-run first, then --apply)
python setup_secret_rotation.py --profile scs-member --region us-east-1
python setup_secret_rotation.py --profile scs-member --region us-east-1 --apply
aws secretsmanager rotate-secret --secret-id scs/phase2/demo --profile scs-member

# 2.3 — S3 encryption enforcement, then observe the deny drill
python enforce_s3_encryption.py --bucket <BUCKET> --kms-key-arn <CMK_ARN> \
    --profile scs-member --apply
python enforce_s3_encryption.py --bucket <BUCKET> --kms-key-arn <CMK_ARN> \
    --profile scs-member --break

# 2.4 — Macie (Stretch)
python macie_discovery.py --bucket <SEEDED_BUCKET> --profile scs-member --apply
```

## Teardown

```bash
python setup_secret_rotation.py --profile scs-member --teardown --apply
python macie_discovery.py --disable --profile scs-member --apply
```

The ALB, target group, and demo buckets from scenarios 2.2/2.3 are deleted with
the CLI commands in the lab's **Phase 2 teardown** section. Run
`python ../phase-1/teardown_check.py --profile scs-member` for the cross-cutting
sweep.

## Safety notes (same rules as Phase 1)

- **No secrets to output.** The rotation handler and setup script generate
  passwords with `GetRandomPassword` and pass them straight into the API — they are
  never logged or printed.
- **Dry-run by default.** Every creating/destructive path requires `--apply`.
- **Named profiles only.** No embedded credentials.
