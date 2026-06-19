# AWS Certified Security – Specialty (SCS-C03): Lab-Centric Study Course

A zero-video, action-first study course. You will not memorize facts from slides.
You will deploy real architectures in a personal AWS sandbox, deliberately break
them, and write automation to detect and fix them. The exam rewards engineers who
have actually held these services in their hands — this course is built to make
you that engineer.

**Target split:** ~80% hands-on, ~20% reading (per AWS's own guidance).
**Duration:** 8 weeks at ~9–10 hrs/week. Core-only at ~5–6 hrs/week stretches to ~10–12 weeks.

---

## How to use this repo

```
README.md            <- you are here: index, domain map, 8-week tracker
cost-safety.md       <- READ THIS FIRST. Budget alarms + teardown discipline.
reading-list.md      <- the disciplined 20%: whitepapers + doc sections, time-boxed
labs/                <- one markdown lab guide per phase (step-by-step)
scripts/             <- runnable Boto3 + bash starters, each with --dry-run + teardown
```

Work through phases in order. Each lab guide follows the same template:

1. **Exam domain tag** — which SCS-C03 domain(s) this trains.
2. **Why the exam cares** — the question patterns this defends against.
3. **Prerequisites** — accounts, IAM, prior labs.
4. **Build it** — console + CLI step-by-step.
5. **Policies / code** — paste-ready JSON and Boto3.
6. **Break it / Fix it** — the drill that actually cements the learning.
7. **Verify** — how to prove it works (and how the exam would phrase the failure).
8. **Tear it down** — stop the billing, reset for the next lab.

### Lab difficulty tiers

| Tier | Meaning | Do it? |
|------|---------|--------|
| **Core** | In-scope and essential. Tested directly. | Always. |
| **Stretch** | In-scope but harder/deeper. Where the hard exam questions live. | Yes — treat as default work. |
| **Enrichment** | Beyond exam scope. Rare, clearly flagged. | Optional, skip under time pressure. |

---

## Exam domain coverage map

SCS-C03 has six domains. This is the official weighting and where each is trained in this course.

| # | Domain | Weight | Primarily trained in |
|---|--------|--------|----------------------|
| 1 | Threat Detection & Incident Response | 14% | Phase 4 (GuardDuty, Detective, EventBridge), Phase 8 (RCA) |
| 2 | Security Logging & Monitoring | 18% | Phase 6 (CloudTrail, Athena, Flow Logs, CW alarms) |
| 3 | Infrastructure Security | 20% | Phase 4–6 (Security groups/NACLs, WAF, VPC endpoints) |
| 4 | Identity & Access Management | 16% | Phase 1 (cross-account IAM), Phase 7 (SCPs) |
| 5 | Data Protection | 18% | Phase 1 (KMS), Phase 3 (Secrets Manager, ACM, Macie, S3) |
| 6 | Management & Security Governance | 14% | Phase 7 (SCPs, Config aggregators, Security Hub) |

---

## The 8-week plan (Core / Stretch tracker)

Check items off as you complete them. Stretch labs are in _italics_.

### Phase 1 — Preventative architecture: IAM & KMS (Weeks 1–2)
- [ ] 1.1 Cross-account IAM role: MFA + IP-restricted AssumeRole — **Core**
- [ ] _1.1b Add `aws:PrincipalOrgID` + permission boundary on the role — **Stretch**_
- [ ] 1.2 KMS CMK deliberate lockout + emergency recovery — **Core**
- [ ] _1.2b Multi-condition key grant (ViaService + encryption context) — **Stretch**_

### Phase 2 — (folded into Phase 1's two weeks; see Phase 1 guide)

### Phase 3 — Data protection gap-fill (Week 3)
- [ ] 3.1 Secrets Manager with automatic rotation (Lambda) — **Core**
- [ ] 3.2 ACM cert + enforce TLS on an ALB / S3 (HTTPS-only) — **Core**
- [ ] 3.3 S3 default encryption + bucket-key + deny-unencrypted-PutObject — **Core**
- [ ] _3.4 Macie sensitive-data discovery job on a seeded bucket — **Stretch**_

### Phase 4 — Detection & automated remediation (Weeks 4–5)
- [ ] 4.1 Config rule `s3-bucket-public-read-prohibited` + SSM auto-remediation — **Core**
- [ ] 4.2 Custom Boto3 Lambda Config rule: kill SSH/RDP 0.0.0.0/0 ingress — **Core**
- [ ] 4.3 GuardDuty -> EventBridge -> Lambda -> NACL block of malicious IP — **Core**
- [ ] 4.4 Security Hub as single pane of glass + Inspector findings — **Core**
- [ ] _4.5 Detective investigation of a GuardDuty finding — **Stretch**_

### Phase 5 — (folded into Phase 4's two weeks; see Phase 4 guide)

### Phase 6 — Perimeter defense & logging integrity (Week 6)
- [ ] 6.1 WAF Web ACL blocking XSS + SQLi on an ALB — **Core**
- [ ] 6.2 Org-wide CloudTrail to isolated logging account + log-file validation — **Core**
- [ ] 6.3 S3 bucket policy: deny `s3:DeleteObject` even to root (Object Lock) — **Core**
- [ ] 6.4 Athena queries over CloudTrail + VPC Flow Logs — **Core**
- [ ] _6.5 CloudWatch Logs metric filter + alarm on root login / IAM changes — **Stretch**_

### Phase 7 — Governance & guardrails (Week 7)
- [ ] 7.1 SCPs: deny region, deny disabling CloudTrail/GuardDuty, require MFA — **Core**
- [ ] 7.2 Config aggregator across the org + conformance pack — **Core**
- [ ] Begin timed full-length practice exam #1 — **Core**

### Phase 8 — Validation & exam mindset (Week 8)
- [ ] 8.1 Root-cause-analysis drill: recreate every missed question in console — **Core**
- [ ] 8.2 IAM Policy Simulator + CloudTrail error-string drills — **Core**
- [ ] Timed full-length practice exams #2 and #3, review to >85% — **Core**

---

## Prerequisites (do these before Phase 1)

1. **Two AWS accounts in an Organization.** A management account and at least one
   member account. The cross-account, SCP, and org-CloudTrail labs need this.
   See Phase 1 for the org-setup walkthrough. Most of this fits in Free Tier.
2. **Read `cost-safety.md` and set up the budget alarm.** Non-negotiable. Do it
   before you launch anything billable.
3. **AWS CLI v2 + Python 3.11+ with Boto3.** Use named profiles, never long-lived
   root keys. Recommended:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate && pip install boto3
   aws configure --profile scs-mgmt     # management account, IAM user with MFA
   aws configure --profile scs-member    # member account admin role
   ```
4. **Enable MFA on every IAM principal you create.** The exam assumes MFA
   everywhere, and Phase 1 depends on it.

---

## Reading discipline (the 20%)

Open `reading-list.md`. Each phase has 1–2 short assigned readings (an AWS
whitepaper section or a focused doc page). Read them _after_ the corresponding
lab, not before — you'll absorb far more once you've felt the service break.

---

## A note on cost and safety

Every script that changes or deletes resources ships with a `--dry-run` flag and a
paired teardown script. No script in this course prints secrets (API keys, KMS
key material, session tokens) to stdout or logs. If you ever see a script that
looks like it would, stop and flag it. See `cost-safety.md` for the teardown
checklist you run at the end of every session.
