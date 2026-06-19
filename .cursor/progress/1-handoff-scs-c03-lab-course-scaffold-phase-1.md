# Handoff Scs C03 Lab Course Scaffold Phase 1

## Working directory

`~/Desktop/aws-security-specialty-exam`

## Contents

**Date:** 2026-06-18
**Status:** Scaffold + Phase 1 complete and committed (commit `78b64a0`). Awaiting Graham's review of the Phase 1 template before building Phases 3–8.

## What this project is

A zero-video, action-first study course for the **AWS Certified Security – Specialty (SCS-C03)** exam. Graham wants ~80% hands-on / 20% reading (per AWS guidance): deploy real architectures in a personal AWS sandbox, deliberately break them, write automation to fix them. He explicitly wants to avoid hundreds of hours of video (he used Adrian Cantrill's course for SAA and found it grueling). Deliverables = markdown lab guides + runnable Boto3/bash scripts.

## Decisions already locked (do NOT re-litigate)

1. **8-week spine**, extended from the original 6-week blueprint. Core-only (~5–6 hrs/wk) stretches to ~10–12 weeks; full pace ~9–10 hrs/wk.
2. **Difficulty tiers:** Core (in-scope, essential), Stretch (in-scope but harder — treat as default work, NOT optional), Enrichment (beyond exam scope — rare, flagged, skippable).
3. **Two real AWS accounts via Organizations** (`scs-mgmt` = Account A, `scs-member` = Account B). Not simulated.
4. **Gap-fill domains woven into the 8 weeks** (Security Hub, Macie, Inspector, Secrets Manager rotation, ACM/TLS, SCPs, Athena log analysis, VPC Flow Logs, CloudWatch alarms) — original blueprint under-covered Domains 2, 5, 6.
5. **Format:** per-phase markdown lab guides + a `scripts/` dir. Possible PDF render later via /make-pdf once content is final.
6. **Build cadence:** one phase per turn so Graham validates as we go.

## Repo structure (current)

- `README.md` — index, exam-domain coverage map, 8-week Core/Stretch tracker
- `cost-safety.md` — budget alarm setup + per-session teardown checklist
- `reading-list.md` — the 20% reading, time-boxed, mapped per phase
- `labs/phase-1-preventative-architecture.md` — DONE, the reference template
- `scripts/phase-1/` — README + setup_cross_account_role.py, assume_role_test.py, kms_lockout_demo.py, teardown_check.py
- `.gitignore`

## The lab template (Phase 1 is the reference — match it for all phases)

Each scenario: exam-domain tag → "why the exam cares" → prerequisites → **Build it** (console + CLI) → paste-ready JSON policies → **Break it / Fix it** drill → **Verify** → **Tear it down**. Each phase ends with a "what you should be able to answer cold" self-check.

## Script house rules (enforced; keep enforcing)

- No secrets ever printed to stdout/stderr/logs (no KMS material, access keys, secret values, tokens). Print resource IDs/ARNs only.
- Destructive/creating actions default to dry-run; require `--apply` and/or per-resource confirmation.
- Named AWS profiles only; no embedded credentials.
- Every destructive script has a paired teardown path.

QA pass (ian-backend-leader) on Phase 1 scripts: no secrets-leak violations. Fix applied: `teardown_check.py` now SUSPENDS GuardDuty (`update_detector(Enable=False)`) instead of `delete_detector`. False positive rejected: `describe_nat_gateways` correctly uses `Filter` (singular) — an EC2 API quirk; comment added so it's not "fixed" later.

## Next steps (in order)

1. **Wait for Graham's feedback on Phase 1** — depth/length, the per-scenario template, console-vs-CLI-vs-script balance. Do not build ahead until he confirms the template.
2. Once confirmed, build phases to match, one per turn:
   - **Phase 3 (Wk 3):** Secrets Manager rotation Lambda; ACM + TLS enforcement; S3 default encryption + deny-unencrypted-PutObject; Macie (Stretch).
   - **Phase 4–5 (Wk 4–5):** Config rule + SSM auto-remediation; custom Boto3 Lambda Config rule killing SSH/RDP 0.0.0.0/0 ingress; GuardDuty → EventBridge → Lambda → NACL block; Security Hub + Inspector; Detective (Stretch).
   - **Phase 6 (Wk 6):** WAF (XSS/SQLi) on ALB; org CloudTrail to isolated logging account + log-file validation; S3 deny-DeleteObject/Object Lock; Athena over CloudTrail + Flow Logs; CW metric-filter alarms (Stretch).
   - **Phase 7 (Wk 7):** SCPs (region lock, protect CloudTrail/GuardDuty, require MFA, deny root); Config aggregator + conformance pack; first timed practice exam.
   - **Phase 8 (Wk 8):** RCA drills (recreate every missed practice question in console; IAM Policy Simulator + CloudTrail error strings); final practice exams.
3. Each new phase: add `labs/phase-N-*.md` and `scripts/phase-N/` with matching README, and tick the README tracker.

## Open offers not yet actioned

- Security review of the Boto3 scripts (credential handling, no-secrets guarantee, policy-building injection surface) — offered, not yet run.
- Pre-commit hook via /pre-commit — not yet offered/created for this repo.

## Notes / gotchas

- This handoff is now a proper CFS document (created via `cfs i progress create`), not a hand-made file. Use `cfs i progress complete <id> --force` to close it.
- Graham's CLAUDE.md: never push to remote unless explicitly told; never commit to master/main except doc-only changes (this project qualifies). Offer security review on completing work.
- `rm -rf` is blocked by the deny list (good).

## Acceptance criteria
