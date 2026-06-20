# Phase 5 — Governance & guardrails (Week 7)

**Domains trained:** Domain 6 (Management & Security Governance, 14%) and Domain 4
(Identity & Access Management, 16%). This is where you stop securing *resources* and
start securing the *organization* — the controls that bind every account at once.

**The mindset shift:** Phases 1–4 secured things *inside* an account. Phase 5 moves
up a level: **guardrails that no account can escape**. An SCP is not a permission —
it's a ceiling. A Config aggregator is not a detector — it's the org-wide *view* of
every detector. The exam loves the distinction between a control that **grants** and
a control that **bounds**, and the order in which they're evaluated. By the end you
should be able to say, for any action in any member account, exactly which layer
(SCP / IAM / resource policy / permission boundary) would stop it and why.

This phase also begins your **exam validation**: a timed practice exam and the
root-cause loop that turns every miss into a lab. That loop *is* Phase 6.

---

## How this lab works

Same active-recall format. Build/Break-Fix sections **pose the task and stop** —
sketch your answer, then check `answers/phase-5-answers.md` (keyed **B5.1**,
**D5.2**, …), the files in `policies/phase-5/`, and the runnable tooling in
`scripts/phase-5/`. Prerequisite and Teardown are given in full.

> **The big warning for this phase:** SCPs can **lock you out**. A bad deny attached
> to the wrong place can break every account under it — including your ability to fix
> it. Everything here defaults to dry-run, attaches **only to a target OU you name**
> (never the org root automatically), and SCPs **never affect the management
> account**, which is your escape hatch. Read 5.1's safety box before `--apply`.

---

## Prerequisite

- An **AWS Organization** with **all features enabled** (not just consolidated
  billing) and **SCPs enabled** as a policy type. You enable SCPs from the
  **management account** (`scs-mgmt`, Account A).
- **A throwaway OU containing only the member account** (`scs-member`, Account B), so
  a guardrail mistake can't touch anything you care about. The 5.1 script can target
  any OU id you pass; **create a dedicated lab OU and move the member account into
  it** before applying anything.
- Run 5.1 with the **`scs-mgmt`** profile (org APIs live in the management account);
  run 5.2's aggregator from whichever account will hold the org-wide view (management
  or a delegated-admin account). The single-account fallback runs in `scs-member`.

> **Reading after the labs:** SCP strategy + Config aggregators/conformance packs
> (see `reading-list.md`, Phase 5).

---

## Scenario 5.1 — Service Control Policies: the four canonical guardrails  ·  **Core**

### Goal
Author and attach four SCPs to your **lab OU**: (a) **region lock** — deny actions
outside approved regions; (b) **protect the detectives** — deny disabling
CloudTrail/GuardDuty/Config; (c) **require MFA** for sensitive actions; (d) **deny
root** usage in member accounts. Then prove each one bites.

### Why the exam cares
SCPs are the spine of Domain 6 and they trip people up because of one idea: **an SCP
grants nothing — it only sets the maximum.** An action succeeds only if it's allowed
by **both** the SCP *and* an IAM policy (and any permission boundary, and any
resource policy). You must know: **SCPs don't affect the management account**;
**SCPs don't affect service-linked roles**; the default **`FullAWSAccess`** SCP is
what makes Organizations permissive until you restrict; **deny-list vs allow-list**
strategy; that a **region-lock** SCP must **exempt global services** (IAM, STS,
CloudFront, Route 53, etc.) or you'll break them; and the exact evaluation order
where an **explicit deny anywhere wins**.

### Build challenge · B5.1
1. **Region lock.** Write an SCP that denies all actions whose
   `aws:RequestedRegion` is **not** in your approved list — *but* doesn't break
   global services. Which services must you exempt, and what's the mechanism
   (`NotAction` vs a condition) you use to exempt them?
2. **Protect the detectives.** Write an SCP denying
   `cloudtrail:StopLogging`/`DeleteTrail`, `guardduty:DeleteDetector`, and
   `config:DeleteConfigurationRecorder`/`StopConfigurationRecorder`. Who should this
   apply to, and why does putting it at the OU level beat relying on IAM in each
   account?
3. **Require MFA + deny root.** Write a statement that denies a sensitive action set
   when `aws:MultiFactorAuthPresent` is false, and a separate statement that denies
   everything to the **root user** of member accounts. For the MFA condition, why
   `BoolIfExists` rather than `Bool`, and why is denying root in a *member* account
   safe when you'd never do it via SCP to the management account?

> Hint: an SCP is a filter on top of IAM. If IAM says yes and the SCP says nothing,
> the answer is *no* — unless a `FullAWSAccess` SCP is also attached. An explicit
> `Deny` in the SCP is final.

→ Reference: `answers/phase-5-answers.md` → **B5.1**. Policy JSON:
`policies/phase-5/5.1-scp-region-lock.json`,
`policies/phase-5/5.1-scp-protect-detectives.json`,
`policies/phase-5/5.1-scp-require-mfa.json`,
`policies/phase-5/5.1-scp-deny-root.json`. Tooling:
`scripts/phase-5/setup_scp.py --target-ou <OU_ID>` (dry-run first; **read the safety
box below**).

> ### SAFETY BOX — read before `--apply`
> - **Attach to your lab OU only.** Never attach a deny SCP to the org **root** while
>   learning — it hits every account at once. The script refuses the root id unless
>   you pass `--i-understand-root`.
> - **The management account is your escape hatch** — SCPs never restrict it, so you
>   can always detach a bad policy from there.
> - **Test region-lock with a cheap action** (e.g. `ec2 describe` in a denied
>   region) before trusting it; confirm global services (IAM/STS) still work.

### Verify · V5.1
```bash
# As the member account, in a region you did NOT approve -> expect AccessDenied:
aws ec2 describe-vpcs --region eu-west-1 --profile scs-member
# A global service should still work even from a "denied" region context:
aws iam list-account-aliases --profile scs-member
```
What error does the first command return, what *kind* of denial is it (which policy
layer), and why does the IAM call still succeed?
→ `answers/phase-5-answers.md` → **V5.1**

### Break it / Fix it · D5.1
1. With the **protect-the-detectives** SCP attached, try `aws cloudtrail
   stop-logging --name <trail>` as a member-account **admin**. It fails despite admin
   IAM rights. Explain precisely why admin isn't enough.
2. **Lockout drill (conceptual — don't actually do it to root):** you attach a
   `Deny *` SCP to the OU. What can the member account still do, and how do you
   recover? Why would the same mistake on the management account be unrecoverable via
   SCP — and what does that tell you about where to *never* attach guardrails?
3. The region-lock SCP accidentally omits the global-service exemption. What breaks
   first, and how would the symptom show up to a user (which calls suddenly fail)?

→ `answers/phase-5-answers.md` → **D5.1**

---

## Scenario 5.2 — Config aggregator + conformance pack  ·  **Core**

### Goal
Build an **aggregated** view of AWS Config compliance across the org (or, in the
single-account fallback, across regions), then deploy a **conformance pack** — a
bundle of Config rules shipped as one unit — and read org-wide compliance from one
place.

### Why the exam cares
Domain 6 again: the exam tests that a **configuration aggregator** gives you a
**read-only, multi-account/multi-region rollup** of Config data in one account
(management or **delegated administrator**), that source accounts must **authorize**
the aggregator (automatic for org aggregators), and that a **conformance pack** is a
**collection of Config rules + optional remediation packaged as a single
deployable** (a YAML template) you can roll out **org-wide** and track as one
compliance score. Know the line between **detection** (Config rules, from Phase 3)
and **governance/reporting** (aggregator + packs).

### Build challenge · B5.2
1. Create a **configuration aggregator**. For an **organization** aggregator, what
   authorization step is handled for you, and where must the aggregator account sit
   (management or delegated admin)? For the cross-account *non*-org version, what
   must each source account create?
2. Deploy a **conformance pack** from a template (start with an AWS sample pack, e.g.
   "Operational Best Practices for CIS" or a small custom one). What's in the
   template, and how is a conformance pack different from attaching the same rules
   one by one?
3. From the aggregator, answer: "which accounts have a **non-compliant**
   `s3-bucket-public-read-prohibited` (your Phase 3 rule)?" Which view gives you
   that, and why couldn't a single-account Config console answer it?

> Hint: the aggregator doesn't *evaluate* anything — the rules still run in each
> account/region. The aggregator just **collects and shows** their results centrally.

> **Prerequisite for the conformance pack:** AWS Config must already be **recording**
> in the account (the recorder + delivery channel from Phase 3.1). Config creates a
> service-managed S3 bucket for the pack automatically — you don't supply one for
> this lab.

→ Reference: `answers/phase-5-answers.md` → **B5.2**. Conformance pack template:
`policies/phase-5/5.2-conformance-pack.yaml`. Tooling:
`scripts/phase-5/setup_config_aggregator.py` (org or single-account modes).

### Verify · V5.2
```bash
aws configservice describe-configuration-aggregators --profile scs-mgmt
aws configservice get-aggregate-compliance-details-by-config-rule \
  --configuration-aggregator-name <NAME> --config-rule-name s3-bucket-public-read-prohibited \
  --account-id <MEMBER_ACCT> --aws-region us-east-1 --compliance-type NON_COMPLIANT \
  --profile scs-mgmt
```
What does the aggregator show that a per-account query cannot, and what's the lag
between a resource going non-compliant and it appearing in the aggregate view?
→ `answers/phase-5-answers.md` → **V5.2**

### Break it / Fix it · D5.2
1. Make a bucket public in the **member** account (as in Phase 3). How long until the
   aggregator in the **management** account reflects NON_COMPLIANT, and what's the
   data path that carries it there?
2. **Conceptual:** a conformance pack reports 12% non-compliant org-wide. Is that an
   aggregator problem, a Config-rule problem, or a *resource* problem — and which
   tool do you use to drill from the score to the offending resource?
3. **Conceptual:** you delete a Config **rule** in one member account. Does the
   conformance pack's score "heal" by ignoring it, or does the pack reassert the
   rule? What does that tell you about packs vs ad-hoc rules for governance?

→ `answers/phase-5-answers.md` → **D5.2**

---

## Scenario 5.3 — Timed practice exam #1 + the RCA loop  ·  **Core**

### Goal
Sit your **first full-length, timed** SCS-C03 practice exam under real conditions,
score it honestly, and convert every miss into a **root-cause entry** that becomes a
hands-on drill in Phase 6. This scenario is **protocol, not a lab to deploy** — the
discipline is the deliverable.

### Why this matters
The Specialty exam is 65 questions in 170 minutes, scenario-heavy, with answers that
are all "plausible." You don't fail on facts you never learned — you fail on facts
you **half**-learned and on **time**. A timed run surfaces both. The RCA loop is what
converts a score into a study plan.

### The protocol · B5.3
1. **Pick a legitimate source** (see the curated list in `answers/phase-5-answers.md`
   → **B5.3** — AWS's own Official Practice Question Set / Skill Builder first, then
   reputable third-party banks). Avoid "exam dumps" — they teach wrong answers and
   violate the exam agreement.
2. **Simulate real conditions:** 65 questions, **170 minutes**, one sitting, no
   notes, no pausing. Flag-and-move on anything over ~90 seconds.
3. **Score by domain**, not just overall. Use the six-domain map in the README. A 75%
   overall can hide a 50% in Domain 2 that will sink you.
4. **RCA every miss** (and every lucky guess) into the table format in
   `answers/phase-5-answers.md` → **B5.3**: question topic → which domain → *why* you
   missed it (didn't know / misread / time) → the **lab or reading** that fixes it.

### Self-check · D5.3
- Did any **whole domain** come in under ~70%? That domain is your Phase 6 priority.
- Were misses concentrated in **"didn't know"** (knowledge gap → re-lab/re-read) or
  **"misread/time"** (test-craft → practice pacing)? The fix differs.

→ Reference: curated sources + the RCA table template:
`answers/phase-5-answers.md` → **B5.3 / D5.3**.

---

## Phase 5 teardown

Full steps — housekeeping, not a drill. SCPs especially: **leaving a bad guardrail
attached is the dangerous state**, so detach deliberately.

- [ ] **SCPs:** detach each policy from the lab OU and delete it
      (`scripts/phase-5/setup_scp.py --target-ou <OU_ID> --teardown --apply`). Confirm
      the member account's normal access is restored. Optionally move the member
      account back out of the lab OU.
- [ ] **Config aggregator + conformance pack:** delete them
      (`scripts/phase-5/setup_config_aggregator.py --teardown --apply`). The
      per-account Config recorders/rules from Phase 3 are separate — leave or remove
      them per your Phase 3 teardown.
- [ ] Leave **SCPs as an org policy type enabled** if you want (it's free); only the
      attached policies cause behavior.
- [ ] Run `python scripts/phase-1/teardown_check.py --profile scs-member` for the sweep.

## What you should now be able to answer cold

Pure self-test — answers in `answers/phase-5-answers.md` → **Answer-cold**.

- **C5.1** Does an SCP grant permissions? State the exact rule for when an action in a
  member account succeeds.
- **C5.2** Name two principals/things an SCP does **not** affect.
- **C5.3** Why must a region-lock SCP exempt global services, and how do you exempt them?
- **C5.4** What does a Config **aggregator** do that a single-account Config view
  cannot, and does it evaluate rules itself?
- **C5.5** What is a conformance pack, and how does it differ from attaching the same
  rules individually?
- **C5.6** In policy evaluation, what always wins — and where does an SCP sit relative
  to an IAM identity policy?

When you can answer those without notes, you're ready for **Phase 6**.
