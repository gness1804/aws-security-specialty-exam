# Phase 6 — Answer key (Validation & exam mindset)

Consult **after** attempting each challenge in `labs/phase-6-validation.md`. IDs
match the lab. Reference policies in `policies/phase-6/`; read-only tooling in
`scripts/phase-6/`.

---

## B6.1 — The RCA loop

The discipline: **every "didn't know" miss maps to exactly one phase/lab you rebuild.**
Use this mapping to route a miss to its drill.

| Miss topic (example) | Domain | Rebuild in |
|----------------------|--------|------------|
| Cross-account AssumeRole, MFA/IP/OrgID conditions | 4 | Phase 1.1 |
| KMS key policy lockout / grants / ViaService | 5 | Phase 1.2 |
| Secrets Manager rotation four-step contract | 5 | Phase 2.1 |
| S3 SSE-KMS / bucket key / deny-unencrypted | 5 | Phase 2.3 |
| Config managed rule + SSM auto-remediation | 1/6 | Phase 3.1 |
| Custom Config-rule Lambda / PutEvaluations | 1 | Phase 3.2 |
| GuardDuty → EventBridge → NACL response | 1/3 | Phase 3.3 |
| Security Hub ASFF / Inspector vs Config | 1/6 | Phase 3.4 |
| WAF layer-7 / SQLi-XSS / attachable resources | 3 | Phase 4.1 |
| CloudTrail validation / org trail / log-archive | 2 | Phase 4.2 |
| S3 Object Lock COMPLIANCE vs GOVERNANCE | 2/5 | Phase 4.3 |
| Athena partitioning / mgmt vs data events | 2 | Phase 4.4 |
| Metric filter → alarm → SNS pipeline | 2 | Phase 4.5 |
| SCP semantics / region lock / require-MFA | 4/6 | Phase 5.1 |
| Config aggregator / conformance pack | 6 | Phase 5.2 |
| Policy eval order / simulator / decode | 4 | Phase 6.2 |

The rule: **rebuild, don't re-read.** If re-testing the domain doesn't move the
number, your rebuild was too shallow — break the scenario harder.

---

## D6.1 — Self-check

- For every rebuilt scenario you should be able to state the **one sentence the exam
  is testing** (e.g. "an explicit deny in an SCP beats an allow in an identity
  policy"; "Object Lock COMPLIANCE can't be overridden by root"). If you can't, you
  rebuilt the mechanics but missed the *point*.
- **The phase that appears most in your RCA table is your real weak spot** — weight
  effort there even if your overall score looks fine, because the exam samples all
  domains and a single weak domain can sink a passing average.

---

## B6.2 — Policy Simulator + decode

1. **Simulate before you run.** The three fields:
   (a) **`EvalDecision`** — the outcome: `allowed`, `explicitDeny`, or
   `implicitDeny`; (b) **`MatchedStatements`** — *which* statement(s) drove the
   decision (the policy + Sid); (c) **`MissingContextValues`** — condition keys the
   request didn't supply (e.g. `aws:MultiFactorAuthPresent`), i.e. it might be denied
   only because a context value is absent. **`implicitDeny`** = "nothing allowed it"
   (no matching Allow anywhere); **`explicitDeny`** = "something actively forbade it"
   (a `Deny` statement or boundary). Tool: `scripts/phase-6/run_policy_simulator.py`.
2. **Boundary drill.** Identity policy allows, permission boundary doesn't →
   **`implicitDeny`** (the action falls outside the boundary's allowed set; the
   boundary grants nothing, it only caps). The effective permission is the
   **intersection**: an action must be allowed by **both** the identity policy **and**
   the boundary. (If the boundary contained an explicit `Deny`, you'd get
   `explicitDeny` instead.)
3. **Decode a real denial.** A denial message containing an **encoded authorization
   message** is decoded with
   **`aws sts decode-authorization-message --encoded-message <BLOB>`** (or
   `scripts/phase-6/decode_authorization_message.py`). The decoded JSON gives the
   **full request context** — principal, action, resource, the **matched/failed
   statements**, and which **policy type** denied — that the raw `AccessDenied` string
   hides. (Only some services include the encoded blob; it requires permission to call
   `sts:DecodeAuthorizationMessage`.)

---

## D6.2 — Break/Fix

1. **Read the message, name the layer:**
   - (a) "...no identity-based policy allows..." → **implicit deny** — nothing granted
     the action. Fix: add the allow. Confirm with the simulator (`implicitDeny`).
   - (b) "...explicit deny in a **service control policy**" → an **SCP** at the
     org/OU level denies it. Confirm in Organizations (the SCP attached to the
     account's OU). The simulator **won't** show this — SCPs aren't simulated.
   - (c) "...explicit deny in an **identity-based policy**" → a `Deny` statement on the
     principal's own IAM policy. Confirm via simulator `MatchedStatements`.
   - (d) "...no **resource-based policy** allows..." → cross-account/resource case
     where the **resource policy** (bucket policy, KMS key policy) didn't grant it.
   - (e) "...explicit deny in a **permissions boundary**" → the boundary forbids it.
     Confirm by simulating with the boundary attached.
2. **Simulator says `allowed`, reality says `AccessDenied`** — two reasons: (i) an
   **SCP denies it** and the simulator doesn't evaluate SCPs; (ii) a **runtime
   condition key** (e.g. `aws:SourceIp`, `aws:MultiFactorAuthPresent`,
   `aws:RequestedRegion`) wasn't satisfied/supplied at call time but wasn't modeled in
   the simulation. (Also: a resource policy you didn't include, or eventual-consistency
   lag on a just-changed policy.)
3. **No encoded authorization message** usually means the deny was a **plain IAM
   implicit/explicit deny** surfaced directly by the service (encoded messages
   accompany only *some* authorization decisions — common with EC2 and a number of
   other services, but not universal). Next step: go to the
   **Policy Simulator** or read the **identity/resource policies and SCPs** directly —
   you won't get a decode shortcut, so reason through the eval order.

---

## B6.3 — Exams #2 & #3

Same protocol as 5.3: fresh legitimate question sets (AWS Official Practice first;
see Phase 5.3's curated list), **65 questions / 170 minutes**, real conditions, score
**by domain**, RCA every miss. The key change from #1: **close the gaps from #2 with
the 6.1 rebuild loop before sitting #3** — #3 is your verdict, so don't take it cold.
Two *different* recent sets above the gate is the signal; one is noise.

---

## D6.3 — The readiness gate (rationale)

Book the real exam only when **all** hold:

- **≥ 85% overall on two different recent sets.** The real pass is a scaled
  **750/1000** (~75%-ish, but scaled — not a raw percentage). You want **margin**
  because exam-day conditions (nerves, harder/newer items, fatigue) cost points.
- **No domain below ~75%.** The exam samples all six domains; a 50% in one domain can
  sink an 85% average. The gate is per-domain, not just overall.
- **Misses are mostly "misread/time," not "didn't know."** Knowledge gaps mean you're
  not ready; test-craft errors mean you are, modulo pacing.
- **You finished with time to spare.** Pacing must be solved — running out of time is
  the most common avoidable failure.

If any check fails, the fix is **specific** (a named domain, or knowledge-vs-craft),
not a vague "study more."

---

## Answer-cold

- **C6.1** Effective decision = **(allowed by an SCP) AND (allowed by an identity
  and/or resource policy) AND (within any permission boundary) AND (no explicit Deny
  anywhere)**. An **explicit `Deny` at any layer always wins**; absent any Allow, the
  result is an **implicit deny**. SCP and boundary only *cap*; they never grant.
- **C6.2** The simulator returns **`EvalDecision`**
  (`allowed`/`explicitDeny`/`implicitDeny`), **`MatchedStatements`** (which statement
  decided), and **`MissingContextValues`** (unsupplied condition keys). It does **not**
  evaluate **SCPs** (organization policies).
- **C6.3** Take the **encoded authorization message** from the `AccessDenied` error
  and run **`aws sts decode-authorization-message --encoded-message <blob>`** (needs
  `sts:DecodeAuthorizationMessage`); the decoded JSON names the principal, action,
  resource, and the failing statement/policy type.
- **C6.4** **Implicit deny** = no policy explicitly allows the action (the default);
  tell: "no identity-based policy allows." **Explicit deny** = a `Deny` statement (in
  an identity/resource/SCP/boundary) actively blocks it; tell: "with an explicit deny
  in a [policy type]." Explicit always beats allow.
- **C6.5** Passing scaled score is **750/1000**. Personal gate: **≥ 85% on two
  different recent sets, no domain < ~75%, misses mostly test-craft not knowledge, and
  time to spare.**
