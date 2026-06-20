---
github_issue: 1
---
# Handoff Scs C03 Lab Course Scaffold Phase 1

## Working directory

`~/Desktop/aws-security-specialty-exam`

## Contents

**Date:** 2026-06-19
**Status:** Phases 1–3 complete and validated by Graham. Paused before Phase 4 at
his request. Repo is now on GitHub (public).

## What this project is

A zero-video, action-first study course for the **AWS Certified Security –
Specialty (SCS-C03)** exam. ~80% hands-on / 20% reading: deploy real architectures
in a personal AWS sandbox, deliberately break them, write automation to fix them.
Deliverables = markdown lab guides + runnable Boto3/bash scripts. 8-week spine,
Core/Stretch/Enrichment difficulty tiers, two real AWS accounts via Organizations
(`scs-mgmt` = Account A, `scs-member` = Account B).

## Format decisions locked in this session (do NOT re-litigate)

1. **Active-recall format.** Labs **pose challenges and stop** — no answer beside
   the question. Answers live in `answers/phase-N-answers.md` keyed by IDs
   (B=Build, V=Verify, D=Drill, C=answer-cold, e.g. **B3.1**). Canonical policy
   JSON lives in `policies/phase-N/` as part of the answer key (referenced only
   from the answers doc, never shown in the lab body). Only **Prerequisite/setup**
   and **Teardown** give full inline steps (housekeeping, not exam concepts).
   One-line "Hint" teasers allowed inline; never the crux.
2. **Phases renumbered sequentially 1–6** (was a confusing 1/3/4/6/7/8 scheme).
   1=IAM/KMS (Wks1–2), 2=Data Protection (Wk3), 3=Detection/Remediation (Wks4–5),
   4=Perimeter/Logging (Wk6), 5=Governance (Wk7), 6=Validation (Wk8).
3. **CLI/script primary**, console called out only where the exam tests a
   console-specific behavior (Security Hub pane, Macie/GuardDuty findings).
4. **One commit per phase, only after Graham validates it.** Never bundle phases.
   (Saved to agent memory: `commit-per-phase`.)

## Repo / git state

- **GitHub:** https://github.com/gness1804/aws-security-specialty-exam (public).
  Scanned clean — only placeholder/example/TEST-NET values, no real IDs/keys.
- **`master`** = Phases 1–2 (fast-forward merged, pushed to GitHub). Default branch.
- **`build-out-phases-3-6`** = current working branch; Phase 3 committed here
  (`2a47ca5`) but **NOT yet merged to master or pushed**.
- Pre-commit hook runs ruff (format+check), gitleaks, and a CFS↔GitHub sync. That
  sync auto-created **GitHub issue #1** from THIS handoff doc.

## Done

- **Phase 1 — IAM & KMS** (restructured into the reference template): cross-account
  AssumeRole (MFA+IP / OrgID / permission boundary), KMS lockout + recovery,
  ViaService/encryption-context. Scripts in `scripts/phase-1/`.
- **Phase 2 — Data Protection** (`266f573`): Secrets Manager rotation (real
  reference Lambda, four-step contract, no secrets logged), ACM/TLS enforcement,
  S3 SSE-KMS + bucket key + deny-unencrypted-PutObject, Macie (Stretch).
- **Phase 3 — Detection & remediation** (`2a47ca5`): managed Config rule + SSM
  auto-remediation; custom Boto3 Config-rule Lambda (SSH/RDP 0.0.0.0/0); GuardDuty
  → EventBridge → Lambda → NACL block; Security Hub + Inspector; Detective
  (Stretch). Shared `scripts/phase-3/_deploy.py` helper.

Each phase passed QA (Opus security + AWS-API reviews on Phase 3).

## Next steps (in order)

1. **Build Phase 4 — Perimeter defense & logging integrity (Wk6)**, one phase per
   turn, matching the format above: WAF (XSS/SQLi) on ALB; org CloudTrail →
   isolated logging account + log-file validation; S3 deny-DeleteObject + Object
   Lock; Athena over CloudTrail + Flow Logs; CW metric-filter alarm on root
   login/IAM changes (Stretch). Add `labs/phase-4-*.md`, `answers/phase-4-*.md`,
   `policies/phase-4/`, `scripts/phase-4/`, tick the README tracker.
2. **Phase 5 — Governance (Wk7):** SCPs (region lock, protect CloudTrail/GuardDuty,
   require MFA, deny root); Config aggregator + conformance pack; practice exam #1.
3. **Phase 6 — Validation (Wk8):** RCA drills (Policy Simulator + CloudTrail error
   strings); final practice exams.
4. Each new phase: commit after Graham validates. Likely merge build-out-phases-3-6
   → master and push when he's ready.

## Script house rules (keep enforcing)

- No secrets to stdout/stderr/logs (resource IDs/ARNs only). Dry-run by default;
  `--apply` to act; paired teardown for every creating script. Named profiles only.
- ruff + gitleaks run in the pre-commit hook; run `ruff format` + `ruff check`
  before committing Python.

## Open offers not yet actioned

- **Security review** of the Boto3 scripts across all phases — offered originally,
  higher-leverage to run once more scripts exist (after Phase 4 or at the end).
- GitHub issue #1 (auto-created from this handoff) is public; Graham can have it
  closed if he prefers it not be.

## Acceptance criteria

<!-- DONE -->
