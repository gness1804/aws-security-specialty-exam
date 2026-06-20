# Phase 5 — Answer key (Governance & guardrails)

Consult **after** attempting each challenge in `labs/phase-5-governance.md`. IDs
match the lab. Policy JSON/YAML lives in `policies/phase-5/`; tooling in
`scripts/phase-5/`.

---

## B5.1 — The four canonical SCPs

**The one rule to internalize:** an SCP **never grants** anything. In a member
account, an action succeeds only if it is **allowed by an IAM policy AND not denied
by any SCP** (and not denied by a permission boundary or resource policy). An
**explicit `Deny` anywhere — SCP or IAM — always wins.** The default
**`FullAWSAccess`** SCP is an `Allow *` that keeps the org permissive until you add
denies (deny-list strategy) or replace it (allow-list strategy).

1. **Region lock.** Deny all actions where `aws:RequestedRegion` is not in your
   approved list, and **exempt global services** — IAM, STS, CloudFront, Route 53,
   Organizations, Support, WAF (global), etc. — because their endpoints are
   global/`us-east-1` and a naive region deny would break sign-in, role assumption,
   and DNS. The mechanism is a **`NotAction`** list (exempt those services from the
   deny) **combined with** the `aws:RequestedRegion` `StringNotEquals` condition. See
   `policies/phase-5/5.1-scp-region-lock.json`.
2. **Protect the detectives.** Deny `cloudtrail:StopLogging`,
   `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector`,
   `config:DeleteConfigurationRecorder`, `config:StopConfigurationRecorder`. Apply at
   the **OU level** so it covers every account at once and **even a full-admin user
   in a member account can't disable logging** — IAM in each account could be edited
   by that account's admin, but an SCP sits above them and can't be removed from
   inside the member account. The shipped policy also denies the *reconfigure*
   actions (`cloudtrail:UpdateTrail`/`PutEventSelectors`, `guardduty:UpdateDetector`,
   `config:DeleteConfigRule`, `securityhub:Disable*`) so an attacker can't neuter a
   control without outright "deleting" it. See
   `policies/phase-5/5.1-scp-protect-detectives.json`.
3. **Require MFA + deny root.** Deny a sensitive action set when
   `aws:MultiFactorAuthPresent` is `false`, using **`BoolIfExists`** — with plain
   `Bool`, requests from contexts where the key is *absent* (some service-to-service
   calls) would be treated as not-MFA and break; `BoolIfExists` only enforces when
   the key is present, the standard safe form. Deny the **root user** of member
   accounts via a condition on `aws:PrincipalArn` (the account root ARN) or
   `aws:PrincipalType`. This is safe in a **member** account because you administer it
   from elsewhere; you would **never** SCP-deny root on the **management account**,
   whose root is your ultimate recovery path (and SCPs don't apply to it anyway). See
   `policies/phase-5/5.1-scp-require-mfa.json` and `5.1-scp-deny-root.json`.

---

## V5.1 — verify

`aws ec2 describe-vpcs --region eu-west-1` returns **`AccessDenied`** (an explicit
**SCP** deny — the message references an explicit deny in a service control policy,
distinct from a plain IAM "no matching allow"). The **`iam list-account-aliases`**
call still succeeds because IAM is a **global service exempted** via `NotAction` in
the region-lock SCP — its requests aren't bound by `aws:RequestedRegion` the way
regional services are. The tell: regional calls in unapproved regions fail; global
calls keep working.

---

## D5.1 — Break/Fix

1. **`cloudtrail stop-logging` fails for a member admin** because the SCP's explicit
   `Deny` sits **above** IAM. Admin rights are an IAM `Allow *`; the SCP removes
   `cloudtrail:StopLogging` from the account's **maximum** permissions, and an
   explicit deny beats any allow. The admin can't remove the SCP either — it's
   attached from the management account, outside their control.
2. **`Deny *` on the OU.** The member account can still do **almost nothing** through
   normal principals — but **service-linked roles still function** (SCPs don't
   restrict them) and the **management account is unaffected**, so you **recover by
   detaching the SCP from the management account**. The same `Deny *` on the
   **management account** would be a non-event (SCPs don't apply there) — but the
   real lesson is the inverse: never rely on attaching guardrails to *root* while
   experimenting, and keep the management account clean as the escape hatch.
3. **Missing global-service exemption.** Sign-in/role-assumption and DNS break first:
   **STS `AssumeRole`** and **IAM** calls start returning AccessDenied because
   they're being evaluated against `aws:RequestedRegion` and their global endpoints
   don't match the approved regional list. The symptom to a user is sudden
   authentication/permission failures on things that have nothing to do with the
   region they're working in.

---

## B5.2 — Config aggregator + conformance pack

1. **Aggregator.** For an **organization aggregator**, source-account
   **authorization is automatic** (the org trust handles it) and the aggregator lives
   in the **management account or a delegated administrator** account. For the
   **cross-account, non-org** version, each **source account must create an
   `AggregationAuthorization`** granting the aggregator account+region permission to
   collect its data. Either way the aggregator is **read-only** — it doesn't change or
   evaluate anything.
2. **Conformance pack.** The YAML template contains a **set of Config rules** (managed
   and/or custom) plus optional **remediation** and parameters, deployed as **one
   unit** (backed by CloudFormation). It differs from attaching rules one-by-one in
   that it's **versioned, deployable org-wide as a single object, and tracked as one
   aggregate compliance score** — and an org conformance pack auto-deploys to new
   accounts. See `policies/phase-5/5.2-conformance-pack.yaml`.
3. **"Which accounts fail `s3-bucket-public-read-prohibited`?"** The
   **aggregate compliance view** (`get-aggregate-compliance-details-by-config-rule`)
   answers it across all accounts/regions at once. A single-account Config console
   only sees its **own** account, so it structurally can't report another account's
   compliance.

---

## V5.2 — verify

The aggregator returns compliance for **every member account and region** in one
query — a per-account console only sees itself. There's a **delivery lag**: the rule
evaluates in the source account first (change-triggered, usually a minute or two),
then the result propagates to the aggregator (typically a few minutes more), so
expect **single-digit minutes** end-to-end, not instant.

---

## D5.2 — Break/Fix

1. **Public bucket in member → aggregator NON_COMPLIANT.** Path: the **Config rule
   evaluates in the member account** (change-triggered off the configuration item),
   producing a compliance result there; the **org aggregator collects** that result
   into the management account's aggregate view. Expect a few minutes total (member
   evaluation + aggregation lag).
2. **12% non-compliant.** That's a **resource problem** surfaced by the rules — the
   aggregator and rules are working exactly as intended (they *found* the drift). You
   drill from the score using the **aggregate compliance details** (or Security Hub)
   down to the specific non-compliant **resource and account**, then remediate there.
3. **Delete a Config rule in one member account.** A **conformance pack reasserts the
   rule** — the pack owns its rules (CloudFormation-backed), so deleting a member's
   copy drifts the pack and it redeploys/flags it, rather than silently "healing" the
   score by ignoring it. That's the governance advantage of packs over ad-hoc rules:
   the desired-state set is **declared and enforced centrally**, not editable
   per-account without detection.

---

## B5.3 — Practice exam #1: curated sources + RCA loop

**Use legitimate sources only** (in rough order of value):

1. **AWS Official Practice Question Set — Security Specialty** (free on **AWS Skill
   Builder**, `skillbuilder.aws`) — closest to real wording.
2. **AWS Official Practice Exam** (the paid full-length one, when available via Skill
   Builder / Pearson VUE) — best for a true timed dry run.
3. **AWS SCS-C03 Exam Guide + sample questions (PDF)** — already in
   `reading-list.md`; the sample questions calibrate tone.
4. **Reputable third-party banks** (e.g. Tutorials Dojo / Jon Bonso, Whizlabs) — good
   *volume* and explanations; treat their wording as practice, not gospel.

**Avoid "exam dumps"** (brain-dump sites claiming real questions): they're often
**wrong**, they teach you confidently-incorrect answers, and using them violates the
AWS certification agreement.

**RCA table — fill one row per miss (and per lucky guess):**

| # | Question topic | Domain (1–6) | Why missed (didn't know / misread / time) | Fix (lab or reading) |
|---|----------------|--------------|--------------------------------------------|----------------------|
| 1 | e.g. SCP vs permission boundary eval order | 4 | didn't know | Phase 5.1 + IAM eval-logic reading |
| 2 | e.g. CloudTrail digest validation | 2 | misread | Phase 4.2 |

Score **by domain** against the README's six-domain map. Carry every "didn't know"
row into **Phase 6** as a hands-on re-lab.

---

## D5.3 — Self-check

- **A whole domain under ~70%** is your **Phase 6 priority** — re-lab that domain's
  scenarios before re-testing, don't just re-read.
- **"Didn't know" misses** are **knowledge gaps** → repeat the relevant lab/reading.
  **"Misread / ran out of time" misses** are **test-craft** → drill pacing
  (flag-and-move, eliminate two distractors fast). The two failure modes need
  different fixes; don't treat a timing problem as a knowledge problem.

---

## Answer-cold

- **C5.1** **No — an SCP grants nothing.** An action in a member account succeeds only
  if an **IAM policy allows it AND no SCP (or boundary/resource policy) denies it**;
  an explicit deny anywhere wins.
- **C5.2** SCPs do **not** affect the **management account**, and do **not** affect
  **service-linked roles** (the IAM service creates/uses those, and SCPs can't
  restrict them).
- **C5.3** Because global services (IAM, STS, CloudFront, Route 53, …) use
  global/`us-east-1` endpoints, a raw `aws:RequestedRegion` deny would break sign-in,
  role assumption, and DNS; **exempt them with `NotAction`** alongside the region
  condition.
- **C5.4** An **aggregator** gives a **read-only, multi-account/multi-region rollup**
  of Config compliance in one account; it does **not evaluate rules itself** — the
  rules still run in each source account.
- **C5.5** A **conformance pack** is a **collection of Config rules (+ optional
  remediation) deployed and tracked as a single unit** (YAML/CloudFormation),
  deployable org-wide; attaching rules individually gives you no single deployable,
  no shared score, and no auto-deploy to new accounts.
- **C5.6** **An explicit `Deny` always wins.** An SCP sits **above** the IAM identity
  policy as a permissions **ceiling** — the effective permission is the
  **intersection** of what the SCP allows and what IAM allows.
