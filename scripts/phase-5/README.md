# Phase 5 scripts

Run from an activated venv with `boto3` installed. All scripts use named AWS
profiles (`--profile`), never embedded credentials, and never print secret values.
Creating/destructive actions default to dry-run; pass `--apply` to act. Run them
**from this directory** (both scripts read policy files via paths relative to the
repo root).

| Script | What it does | Destructive? |
|--------|--------------|--------------|
| `setup_scp.py` | 5.1: creates + attaches the four lab SCPs to a target OU (refuses the org root by default) | Creates (`--apply`); `--teardown` removes |
| `setup_config_aggregator.py` | 5.2: Config aggregator (single-account or `--org`) + optional `--conformance-pack` | Creates (`--apply`); `--teardown` removes |

> **SCPs run from the management account** (`scs-mgmt`) — Organizations APIs live
> there. The Config aggregator runs from wherever the org-wide view should live
> (management/delegated-admin for `--org`, or `scs-member` for the single-account
> fallback).

## ⚠️ SCP safety — read before `--apply`

- **Attach to a dedicated lab OU only.** `setup_scp.py` **refuses the org root**
  (`r-xxxx`) unless you pass `--i-understand-root`. A deny SCP on the root hits every
  account at once.
- **The management account is your escape hatch.** SCPs never restrict it, so a bad
  guardrail on a member OU is always recoverable by detaching from the management
  account.
- **SCPs must be enabled** as a policy type on the org first; the script tells you if
  they aren't.

## Typical Phase 5 session

```bash
source ../../.venv/bin/activate      # adjust path to your venv

# 5.1 — SCPs (from the management account; target your LAB OU, not the root)
python setup_scp.py --target-ou ou-1234-abcd5678 --profile scs-mgmt --apply
# verify a denied region fails but a global service still works:
aws ec2 describe-vpcs --region eu-west-1 --profile scs-member   # expect AccessDenied
aws iam list-account-aliases --profile scs-member               # expect success

# 5.2 — Config aggregator + conformance pack (single-account fallback)
python setup_config_aggregator.py --profile scs-member --apply --conformance-pack
```

## Teardown (detach guardrails deliberately — a bad SCP left attached is the risk)

```bash
python setup_scp.py --target-ou ou-1234-abcd5678 --profile scs-mgmt --teardown --apply
python setup_config_aggregator.py --profile scs-member --teardown --apply
python ../phase-1/teardown_check.py --profile scs-member   # cross-cutting sweep
```

## Safety notes (same rules as Phases 1–4)

- **No secrets to output.** These scripts handle policy documents, ids, and ARNs
  only — no credentials, keys, or secret values are ever printed.
- **Dry-run by default.** Every creating/destructive path requires `--apply`.
- **SCP guardrails default to a named OU and refuse the root** — the one place a
  mistake is unrecoverable.
