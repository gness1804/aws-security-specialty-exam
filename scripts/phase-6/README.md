# Phase 6 scripts

Run from an activated venv with `boto3` installed. All scripts use named AWS
profiles (`--profile`), never embedded credentials, and never print secret values.

**These tools are READ-ONLY** — they evaluate/decode permissions and change nothing,
so unlike Phases 1–5 there is **no `--apply`/`--teardown`** and no cost. Run them from
this directory (the example paths to `policies/phase-6/` are relative to it).

| Script | What it does | Destructive? |
|--------|--------------|--------------|
| `run_policy_simulator.py` | 6.2: IAM Policy Simulator — `custom` (local policy JSON ± boundary) or `principal` (a real ARN). Prints EvalDecision, matched statements, missing context. | No (read-only) |
| `decode_authorization_message.py` | 6.2: decodes an AccessDenied **encoded authorization message** via `sts:DecodeAuthorizationMessage` into readable JSON. | No (read-only) |

## Typical Phase 6 session

```bash
source ../../.venv/bin/activate      # adjust path to your venv

# 6.2 — simulate the mixed test policy: expect allowed / explicitDeny / (MFA) implicitDeny
python run_policy_simulator.py custom \
    --policy ../../policies/phase-6/6.2-simulator-test-policy.json \
    --actions s3:GetObject,s3:DeleteBucket,ec2:StartInstances --profile scs-member

# add the boundary -> ec2:StartInstances becomes implicitDeny (intersection)
python run_policy_simulator.py custom \
    --policy ../../policies/phase-6/6.2-simulator-test-policy.json \
    --boundary ../../policies/phase-6/6.2-permission-boundary.json \
    --actions ec2:StartInstances --profile scs-member

# pass --mfa to supply aws:MultiFactorAuthPresent=true and watch StartInstances flip
python run_policy_simulator.py custom \
    --policy ../../policies/phase-6/6.2-simulator-test-policy.json \
    --actions ec2:StartInstances --mfa --profile scs-member

# decode a real denial blob (from an EC2 AccessDenied error)
python decode_authorization_message.py --message-file /tmp/blob.txt --profile scs-member
```

## Required permissions

- `iam:SimulateCustomPolicy`, `iam:SimulatePrincipalPolicy` (the simulator).
- `sts:DecodeAuthorizationMessage` (the decoder).

## Safety notes (same rules as Phases 1–5)

- **No secrets to output.** These scripts print policy decisions, ARNs, and decoded
  request context (account ids / resource ARNs) only — never credentials or keys.
- **Read-only.** Nothing here creates, modifies, or deletes a resource; there is no
  teardown because there is nothing to tear down.
