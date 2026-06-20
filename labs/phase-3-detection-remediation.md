# Phase 3 — Detection & automated remediation (Weeks 4–5)

**Domains trained:** Domain 1 (Threat Detection & Incident Response, 14%), Domain 3
(Infrastructure Security, 20%), with overlap into Domain 2 (the findings feed
monitoring). The biggest single block of the exam runs through this phase.

**The mindset shift:** Phases 1–2 *prevented* bad states. Phase 3 assumes one
slipped through and asks: *how fast does the system notice, and can it fix itself
without a human?* You'll build three detection-to-remediation loops — a managed
Config rule that auto-reverts a public bucket, a **custom** Config rule (your own
Lambda) that judges security groups, and an event-driven GuardDuty→NACL block —
then wire it all into a single pane of glass.

By the end you should be able to trace any finding from the moment a resource
drifts to the moment something corrects it, and name every component in between.

---

## How this lab works

Same active-recall format. Build/Break-Fix sections **pose the task and stop** —
sketch your answer, then check `answers/phase-3-answers.md` (keyed **B3.1**,
**D3.3**, …), the files in `policies/phase-3/`, and the runnable Lambdas + wiring
in `scripts/phase-3/`. Prerequisite and Teardown are given in full.

This is the heaviest scripting phase: **3.2** and **3.3** ship real Lambda
functions. Read each Lambda only *after* you've sketched its core logic yourself.

> **Cost warning:** GuardDuty, Config, Inspector, Security Hub, and Detective all
> bill continuously. Turn them on at the start of a session and run the teardown at
> the end. See `cost-safety.md`.

---

## Prerequisite

- Phases 1–2 complete; work in **Account B** (`scs-member`).
- One region throughout (`us-east-1` in examples). Config, GuardDuty, EventBridge,
  and the Lambdas must all live in the **same region** to wire together.
- A default VPC with at least one subnet and its NACL (for 3.3), and the ability to
  create a throwaway security group and S3 bucket.

> **Reading after the labs:** AWS Config + GuardDuty finding types + Security Hub
> (see `reading-list.md`, Phase 3).

---

## Scenario 3.1 — Managed Config rule + SSM auto-remediation  ·  **Core**

### Goal
Turn on AWS Config, attach the managed rule `s3-bucket-public-read-prohibited`,
and wire **automatic** remediation so a bucket that goes public is put back within
minutes — no human in the loop.

### Why the exam cares
Config is the backbone of Domain 6 governance and Domain 1 detection. The exam
tests: the **recorder + delivery channel** model, **change-triggered vs periodic**
rule evaluation, the difference between *detecting* drift (the rule) and *fixing*
it (an **SSM Automation document**), and that auto-remediation needs an **IAM role
that SSM assumes** with permission to perform the fix.

### Build challenge · B3.1
1. Enable the **configuration recorder** and a **delivery channel** to an S3
   bucket. What exactly does each of those two pieces do, and why do you need both?
2. Add the managed rule **`s3-bucket-public-read-prohibited`**. Is it
   change-triggered or periodic — and how can you tell from the rule's definition?
3. Attach **automatic remediation** using an SSM Automation document that removes
   public access (e.g. `AWS-DisableS3BucketPublicReadWrite` or a public-access-block
   document). Name the one IAM construct without which the remediation silently
   fails, and what it must be allowed to do.

> Hint: the rule and the fix are two separate services talking through Config's
> remediation configuration; the fix runs as *something else's* identity, not yours.

→ Reference: `answers/phase-3-answers.md` → **B3.1**. Tooling:
`scripts/phase-3/setup_config_remediation.py` (dry-run first).

### Verify · V3.1
```bash
aws configservice describe-compliance-by-config-rule \
  --config-rule-names s3-bucket-public-read-prohibited --profile scs-member
```
After you make a bucket public (below), what should this show, and roughly how long
until auto-remediation flips it back?
→ `answers/phase-3-answers.md` → **V3.1**

### Break it / Fix it · D3.1
1. Make a throwaway bucket public (add a public-read bucket policy or ACL). Watch
   the rule go **NON_COMPLIANT**, then watch remediation act. What's the end state
   of the bucket, and where do you see the remediation execution?
2. **Break remediation:** strip the remediation role's permission to modify the
   bucket, re-trigger. The rule still flags NON_COMPLIANT but the bucket stays
   public. Where does the failure surface, and why didn't Config "just fix it"?

→ `answers/phase-3-answers.md` → **D3.1**

---

## Scenario 3.2 — Custom Config rule (your own Lambda): no SSH/RDP from 0.0.0.0/0  ·  **Core**

### Goal
Write a **custom** AWS Config rule backed by a Lambda you author. It evaluates
every security group and marks any group **NON_COMPLIANT** if it allows ingress on
TCP 22 or 3389 from `0.0.0.0/0`.

### Why the exam cares
Custom Config rules are the exam's favorite "managed rule doesn't exist for this —
now what?" answer. You must know: the Lambda receives an **`invokingEvent`**
containing the **configuration item**, evaluates it, and reports back by calling
**`config:PutEvaluations`** with `COMPLIANT`/`NON_COMPLIANT`/`NOT_APPLICABLE`; that
**Config must have a resource policy / permission to invoke the Lambda**; and the
distinction between configuration-change-triggered and periodic custom rules.

### Build challenge · B3.2
1. **Sketch the evaluation logic first.** Given a security group's configuration
   item, how do you detect an ingress permission that opens 22 or 3389 to
   `0.0.0.0/0` (and `::/0`)? What compliance value do you return, and via which API
   call?
2. What does your Lambda return for a resource type that *isn't* a security group —
   and which compliance value expresses "this rule doesn't apply here"?
3. Identify the two IAM/permission pieces: what the Lambda's execution role needs,
   and the permission that lets **Config** invoke the Lambda.

> Hint: the result isn't a return value — it's an *API call* the Lambda makes back
> to Config, carrying the result token from the event.

→ Reference: `answers/phase-3-answers.md` → **B3.2**. The Lambda +
deploy/teardown: `scripts/phase-3/custom_sg_config_rule_lambda.py`,
`scripts/phase-3/setup_custom_config_rule.py` (read the Lambda after step 1).

### Break it / Fix it · D3.2
1. Create a security group with `0.0.0.0/0` → port 22 ingress. Trigger evaluation.
   What does the rule report, and what appears in the Lambda's CloudWatch logs?
2. Revoke that rule, leave only port 443 from `0.0.0.0/0`. Re-evaluate. Compliant
   or not — and does your logic correctly *not* flag 443?
3. **Conceptual:** your Lambda errors out on one resource. Does Config mark that
   resource COMPLIANT, NON_COMPLIANT, or something else? Why does that matter for a
   security control?

→ `answers/phase-3-answers.md` → **D3.2**

---

## Scenario 3.3 — GuardDuty → EventBridge → Lambda → NACL block  ·  **Core**

### Goal
Build an event-driven response: when GuardDuty raises a finding about a malicious
remote IP, an EventBridge rule fires a Lambda that adds a **deny entry to the
subnet NACL**, cutting the attacker off.

### Why the exam cares
This is *the* canonical AWS automated-response pattern, tested repeatedly. You must
know: GuardDuty publishes findings to **EventBridge** (detail-type
`GuardDuty Finding`), how to write an **event pattern** that matches by finding
type or severity, where the attacker IP lives in the finding JSON
(`detail.service.action...remoteIpDetails.ipAddressV4`), and **why a NACL** (subnet,
**stateless**, supports explicit *deny*) is the right tool to block an IP versus a
security group (which can't express deny).

### Build challenge · B3.3
1. Write the **EventBridge event pattern** that matches GuardDuty findings (start
   broad: all findings; then narrow to a severity floor). What `source` and
   `detail-type` do you match on?
2. **Sketch the Lambda.** Where in the finding JSON is the attacker's IPv4? When it
   adds a NACL deny entry, what two things must it manage to avoid collisions and
   stay idempotent (hint: NACL entries are ordered)?
3. **Design question:** why block at the **NACL**, not the security group? What
   property of NACLs makes "deny this one IP" expressible there but not in an SG?

> Hint: a security group is an *allow-list* — it has no concept of "deny." Blocking
> a specific bad IP while everything else stays open needs an explicit deny.

→ Reference: `answers/phase-3-answers.md` → **B3.3**. Lambda + wiring:
`scripts/phase-3/guardduty_nacl_remediation_lambda.py`,
`scripts/phase-3/setup_guardduty_remediation.py`.

### Verify · V3.3
Generate sample findings and confirm the loop fired without waiting for a real attack:
```bash
aws guardduty create-sample-findings --detector-id <DETECTOR_ID> \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" --profile scs-member
```
What should you check to confirm (a) the Lambda was invoked and (b) the NACL gained
a deny entry — and what IP will a *sample* finding contain?
→ `answers/phase-3-answers.md` → **V3.3**

### Break it / Fix it · D3.3
1. Remove the Lambda's permission to modify NACLs (`ec2:CreateNetworkAclEntry`).
   Re-fire a sample finding. Where does the failure show up, and does EventBridge
   retry?
2. Fire two findings with the **same** attacker IP. Does your Lambda add a second,
   conflicting NACL entry — and how should it handle the duplicate?
3. **Conceptual:** NACLs cap at a limited number of rules. What's the risk of a
   naive "one deny rule per bad IP" design at scale, and what's a better target for
   high-volume blocking?

→ `answers/phase-3-answers.md` → **D3.3**

---

## Scenario 3.4 — Security Hub single pane + Inspector  ·  **Core**

### Goal
Enable Security Hub as the aggregation point for GuardDuty, Config, and Inspector
findings, turn on a security standard, and enable Inspector to scan for CVEs.

### Why the exam cares
Domain 6 + Domain 1: you must know Security Hub **aggregates** findings in the
normalized **ASFF** format, runs **standards** (AWS FSBP, CIS, PCI) as automated
control checks, and supports **cross-region/cross-account aggregation**; and that
**Inspector** continuously scans **EC2, ECR images, and Lambda** for CVEs and
network reachability — it is *not* a config-compliance tool (that's Config).

### Build challenge · B3.4
1. Enable Security Hub and turn on the **AWS Foundational Security Best Practices**
   standard. Where do your Phase 3.1–3.3 findings (Config, GuardDuty) now appear,
   and in what common format?
2. Enable **Inspector**. Which three resource types does it scan, and what class of
   problem does it find that Config and GuardDuty do *not*?
3. **Console step (this is where the console earns its keep):** open the Security
   Hub findings view and the FSBP standard's control list. Identify one failed
   control and the resource it points to.

> Hint: Security Hub doesn't *find* much itself — it's the normalizer and
> single-pane that the other services report into.

→ Reference: `answers/phase-3-answers.md` → **B3.4**. Enable tooling:
`scripts/phase-3/enable_securityhub_inspector.py`.

### Break it / Fix it · D3.4
1. **Conceptual:** a GuardDuty finding and an Inspector finding both appear in
   Security Hub. Which one would tell you "this instance has a known-exploitable
   OpenSSL CVE," and which would tell you "this instance is talking to a known C2
   server"?
2. You want a failed FSBP control to stop nagging because it's a known accepted
   risk. What Security Hub feature do you use, and why is that safer than just
   ignoring it?

→ `answers/phase-3-answers.md` → **D3.4**

---

## Scenario 3.5 — Detective investigation of a GuardDuty finding  ·  **Stretch**

### Goal
Enable Amazon Detective and use its behavior graph to investigate the context
around a GuardDuty finding.

### Why the exam cares
Detective answers the IR question GuardDuty raises but doesn't: *is this normal for
this entity?* Know that Detective ingests **VPC Flow Logs, CloudTrail, and
GuardDuty findings** into a **behavior graph**, and that its value is **scoping an
investigation** (baselines, entity timelines) — not detection or remediation.

### Build challenge · B3.5
1. Enable Detective (it needs GuardDuty to have been on for a bit to be useful).
   What three data sources does it pull into the behavior graph?
2. From a GuardDuty finding, pivot into Detective. What question is Detective
   answering that GuardDuty alone cannot?

→ Reference: `answers/phase-3-answers.md` → **B3.5**.

### Break it / Fix it · D3.5
**Conceptual:** for each task, name the *one* service that owns it — GuardDuty,
Detective, Inspector, Config, or Security Hub:
(a) "continuously score this instance's OS packages for CVEs";
(b) "tell me if this IAM principal's API call pattern changed over the last 30 days";
(c) "alert me that an instance is communicating with a crypto-mining domain";
(d) "prove this S3 bucket has been non-public for the last 24 hours";
(e) "give me one normalized list of all of the above."

→ `answers/phase-3-answers.md` → **D3.5**

---

## Phase 3 teardown

Full steps — housekeeping, not a drill. These services bill continuously, so don't
skip this.

- [ ] **Custom + managed Config rules, recorder, delivery channel:** delete via
      `scripts/phase-3/setup_config_remediation.py --teardown --apply` and
      `scripts/phase-3/setup_custom_config_rule.py --teardown --apply`.
- [ ] **GuardDuty remediation:** delete the EventBridge rule + Lambda + role
      (`scripts/phase-3/setup_guardduty_remediation.py --teardown --apply`). Remove
      any NACL deny entries the Lambda added during the drills.
- [ ] **Detectors/scanners:** disable GuardDuty, Inspector, Security Hub, and
      Detective (`scripts/phase-3/enable_securityhub_inspector.py --disable --apply`,
      `aws guardduty delete-detector ...`).
- [ ] Delete the throwaway security group, public test bucket, and the Config
      delivery-channel bucket.
- [ ] Run `python scripts/phase-1/teardown_check.py --profile scs-member` for the sweep.

## What you should now be able to answer cold

Pure self-test — answers in `answers/phase-3-answers.md` → **Answer-cold**.

- **C3.1** What are the two pieces Config needs to start recording, and what does each do?
- **C3.2** How does a custom Config-rule Lambda report its result back to Config?
- **C3.3** Why block a malicious IP at a NACL rather than a security group?
- **C3.4** Where in a GuardDuty finding is the remote attacker IP, and how does EventBridge match the finding?
- **C3.5** What does Inspector scan, and how is that different from what Config evaluates?
- **C3.6** GuardDuty vs Detective vs Security Hub — one sentence each on what each is *for*.

When you can answer those without notes, you're ready for **Phase 4**.
