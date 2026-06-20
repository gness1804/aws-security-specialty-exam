---
github_issue: 2
---
# SCS-C03 course complete — all 6 phases + security review

## Working directory

`~/Desktop/aws-security-specialty-exam`

## Contents

**Date:** 2026-06-20
**Status:** COURSE COMPLETE. All six phases built, QA'd, validated by Graham, and
committed on branch `build-out-phases-3-6`. Cross-phase security review done.
Remaining work is Graham's manual PR/merge to `master` — agents must NOT merge or push.

## What this project is

A zero-video, action-first study course for the **AWS Certified Security – Specialty
(SCS-C03)** exam. ~80% hands-on / 20% reading. Active-recall format: labs **pose
challenges and stop**; answers live in `answers/phase-N-answers.md` (keyed B/V/D/C),
canonical policy JSON/YAML in `policies/phase-N/`, runnable dry-run Boto3 scripts in
`scripts/phase-N/`. Two accounts via Organizations (`scs-mgmt` = A, `scs-member` = B).

## Phases (all complete)

- **1 — IAM & KMS:** cross-account AssumeRole, KMS lockout/recovery, ViaService/context.
- **2 — Data protection:** Secrets Manager rotation, ACM/TLS, S3 SSE-KMS, Macie.
- **3 — Detection/remediation:** managed + custom Config rules, GuardDuty→NACL,
  Security Hub + Inspector, Detective.
- **4 — Perimeter & logging:** WAF (SQLi/XSS) on ALB, tamper-evident CloudTrail +
  log-file validation, S3 Object Lock WORM, Athena over CloudTrail/Flow Logs, CW
  metric-filter alarms. Commit `8228fca`.
- **5 — Governance:** four SCPs (region lock, protect detectives, require MFA, deny
  root) with lockout-safe tooling, Config aggregator + conformance pack, practice
  exam #1 protocol. Commit `f1d709f`.
- **6 — Validation:** RCA loop, IAM Policy Simulator + STS decode-authorization-message
  drills (read-only), timed exams #2/#3 + readiness gate. Commit `6f6ec94`.

Each phase: Opus QA (AWS-API correctness + security). One commit per phase, only after
Graham validated. Format/cost/teardown rules unchanged from the original scaffold.

## Security review (cross-phase, 2026-06-20)

Two Opus reviewers over all 24 scripts + 26 policies. **No Critical, no High.**
- **Secrets-to-output (house-rule Critical priority): CLEAN** across every script —
  no credentials/keys/tokens/secret-bearing SDK responses reach stdout/stderr/logs.
  `secrets_rotation_lambda.py` never logs secret values; error handlers print only AWS
  error code/message; `assume_role_test.py` deliberately suppresses key/token output.
- **No** hardcoded creds, **no** injection (no shell=True/os.system/eval/exec), named
  profiles throughout, dry-run + teardown gating present on destructive paths.
- Medium/Low findings are least-privilege tightening or deliberate teaching footguns
  (KMS lockout, IGNORE_SAMPLE=false, deny-delete-removable-by-root) already gated.

## Optional hardening follow-ups (NOT yet applied — Graham's call)

1. Add a pinned `requirements.txt` (e.g. `boto3==<ver>`) / lockfile — the one
   systemic gap both reviewers flagged (supply-chain). README currently says
   `pip install boto3` unpinned.
2. Phase 3: add `SourceAccount` (and ideally the Config rule ARN) to the custom
   Config-rule Lambda's invoke grant (`setup_custom_config_rule.py`) to prevent
   same-account event forgery; same pattern for the secret-rotation invoke grant.
3. Phase 4: validate `account` (12 digits) before it's interpolated into Athena DDL.
4. Phase 3/4: scope remediation-role `Resource` and the NACL Lambda's `ec2:*` actions
   below `*` for production use (lab-acceptable as-is).

These touch already-committed/validated phases and some are intentional pedagogy, so
they were left for Graham to approve rather than auto-applied.

## Next steps

1. **Graham:** open a manual PR for `build-out-phases-3-6` → `master` and merge.
   Agents must not merge or push.
2. Optionally apply the hardening follow-ups above (separate commit) before/after PR.
3. Todoist task `6gvfWPC8jHpWrg7R` ("build Phases 4-6") marked complete.

## Open offers

- Apply any of the hardening follow-ups on request.

## Acceptance criteria
