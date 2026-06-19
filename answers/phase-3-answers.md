# Phase 3 — Answer key (Detection & automated remediation)

Consult **after** attempting each challenge in
`labs/phase-3-detection-remediation.md`. IDs match the lab. Policy JSON lives in
`policies/phase-3/`; Lambdas + wiring in `scripts/phase-3/`.

---

## B3.1 — Managed Config rule + SSM auto-remediation

1. **Recorder + delivery channel.** The **configuration recorder** watches
   supported resources and captures a **configuration item** every time one
   changes (the "what does this resource look like now" snapshot). The **delivery
   channel** ships those configuration snapshots and history to an **S3 bucket**
   (and optionally an SNS topic). You need both: the recorder produces data, the
   delivery channel persists/distributes it. Config rules can't evaluate without a
   running recorder.
2. **`s3-bucket-public-read-prohibited` is change-triggered** — it evaluates when
   the configuration of an `AWS::S3::Bucket` changes (its rule definition declares
   a `ConfigurationItemChangeNotification` scope on the S3 bucket resource type),
   not on a fixed clock. (Many rules can *also* run periodically; this one is
   change-driven.)
3. **The make-or-break IAM construct: the remediation execution role.** Config's
   remediation hands the SSM Automation document a **role to assume**, and that
   role must be allowed to perform the fix (e.g. `s3:PutBucketPublicAccessBlock` /
   `s3:PutBucketAcl` / `s3:DeleteBucketPolicy`) **and** trust `ssm.amazonaws.com`.
   Without it, the rule still flags NON_COMPLIANT but the remediation throws an
   access error and the bucket stays public. Use `AutomaticRemediation` (with a
   retry count) for hands-off correction.

---

## V3.1 — verify

`describe-compliance-by-config-rule` shows `COMPLIANT` normally. After you make the
bucket public it flips to **`NON_COMPLIANT`** (change-triggered, usually within a
minute or two of the config change being recorded). With auto-remediation
configured, SSM runs the document and the bucket returns to non-public; the rule
re-evaluates back to `COMPLIANT`. You can watch the remediation under **Config →
Rules → (rule) → Remediation action**, or in **SSM → Automation** execution
history. End-to-end is typically a few minutes, not instant.

---

## D3.1 — Break/Fix

1. **Public bucket →** rule goes `NON_COMPLIANT`; auto-remediation invokes the SSM
   document, which re-blocks public access. End state: bucket is **non-public
   again**; the remediation execution shows in SSM Automation history with status
   Success.
2. **Stripped remediation-role permission →** the rule still detects and reports
   `NON_COMPLIANT`, but the SSM Automation execution **fails** with an access-denied
   error (visible in SSM Automation history / the rule's remediation status). Config
   doesn't fix things itself — it only *orchestrates* SSM under the **execution
   role's** identity, so if that role can't act, nothing changes. Detection and
   remediation are decoupled on purpose.

---

## B3.2 — Custom Config rule (Lambda)

1. **Evaluation logic.** From the configuration item, read the security group's
   `ipPermissions` (ingress). For each permission, if the port range covers **22**
   or **3389** (TCP) and any `ipRanges` entry is `0.0.0.0/0` **or** any
   `ipv6Ranges` entry is `::/0`, the group is **`NON_COMPLIANT`**; otherwise
   `COMPLIANT`. Report by calling **`config.put_evaluations()`** with the
   `ComplianceType`, the resource id/type, the ordering timestamp, and the
   **`ResultToken`** from the event.
2. **Non-SG resource →** return **`NOT_APPLICABLE`** (the rule simply doesn't apply
   to that resource type). Using `NOT_APPLICABLE` — not `COMPLIANT` — keeps the
   compliance dashboard honest.
3. **Two permission pieces:** the Lambda **execution role** needs
   `config:PutEvaluations` plus CloudWatch Logs; and **Config must be allowed to
   invoke the Lambda** — a Lambda **resource policy** granting
   `config.amazonaws.com` `lambda:InvokeFunction` (the `setup_custom_config_rule.py`
   script adds it with `add_permission`).

See `scripts/phase-3/custom_sg_config_rule_lambda.py` for the reference
implementation and `policies/phase-3/3.2-custom-rule-lambda-exec.json` for the
execution policy.

---

## D3.2 — Break/Fix

1. **`0.0.0.0/0` → 22 →** rule reports `NON_COMPLIANT` for that SG; the Lambda's
   CloudWatch logs show the evaluated group id and the offending permission (no
   secrets, just resource ids).
2. **Only 443 from `0.0.0.0/0` →** `COMPLIANT` — 443 isn't in the {22, 3389} set,
   so open HTTPS to the world doesn't trip *this* rule (a different rule would
   judge that).
3. **Lambda errors on a resource →** Config records the rule's evaluation for that
   resource as **insufficient-data / error**, *not* COMPLIANT. That matters: a
   security control must **fail closed** in your dashboard — an un-evaluated
   resource is an unknown, never a silent pass.

---

## B3.3 — GuardDuty → EventBridge → Lambda → NACL

1. **Event pattern.** Match `"source": ["aws.guardduty"]` and
   `"detail-type": ["GuardDuty Finding"]`. Narrow by severity with a numeric filter
   on `detail.severity` (e.g. `[{ "numeric": [">=", 7] }]`) or by
   `detail.type`.
2. **Attacker IPv4 location:**
   `detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4`
   (for an SSH brute-force / network finding; port-probe and other action types
   nest it similarly under `service.action.*`). To stay idempotent the Lambda must
   manage (a) a **unique NACL rule number** (pick a deterministic slot, e.g. derive
   from a base + offset, or scan existing entries) and (b) a **check for an existing
   deny on that CIDR** so re-firing the same IP doesn't create a duplicate/colliding
   entry.
3. **Why a NACL:** a **NACL is stateless, subnet-scoped, and supports explicit
   `deny` rules**, so you can block one bad `/32` while everything else stays open.
   A **security group is allow-only** — it has no `deny`, so you cannot express
   "everything except this IP" in an SG. Blocking a specific attacker requires the
   deny semantics only the NACL provides.

See `scripts/phase-3/guardduty_nacl_remediation_lambda.py`.

---

## V3.3 — verify

After `create-sample-findings`, confirm: (a) the Lambda was invoked — check its
**CloudWatch Logs** for the parsed finding and the NACL entry it added (and the
EventBridge rule's `Invocations`/`TriggeredRules` metrics); (b) the **subnet NACL**
gained a `deny` entry for the attacker CIDR (`aws ec2 describe-network-acls`).
**Sample** findings carry a **documented placeholder IP** (a sample/test range),
not a real attacker, and the finding title is prefixed with `[SAMPLE]`. The lab
deploys the Lambda with `IGNORE_SAMPLE=false` precisely so the sample's placeholder
IP **does** get a NACL deny entry you can observe end-to-end. **In production you'd
set `IGNORE_SAMPLE=true`** so test findings never trigger a real block — a nuance
the exam likes (don't let sample/test data drive automated remediation).

---

## D3.3 — Break/Fix

1. **No `ec2:CreateNetworkAclEntry` →** the Lambda invocation **fails**; you see the
   access-denied error in its CloudWatch Logs. EventBridge **retries** asynchronous
   Lambda invocations (default up to 2 retries) and can send exhausted events to a
   **dead-letter queue** if you configured one.
2. **Two findings, same IP →** a naive Lambda adds a **second** entry (or collides
   on the rule number). Correct handling: **check for an existing deny on that CIDR
   first** and skip, making the operation idempotent.
3. **NACL scale risk:** NACLs have a **hard cap on entries** (quota ~20 default,
   max raised but still bounded). "One deny rule per bad IP" exhausts the NACL
   quickly and risks evicting/colliding rules. Better targets for high-volume IP
   blocking: an **AWS WAF IP set** (for layer-7/ALB/CloudFront), a **Network
   Firewall** rule group, or a managed prefix list — purpose-built for large,
   churning blocklists.

---

## B3.4 — Security Hub + Inspector

1. **Aggregation + format.** With Security Hub on, your Config and GuardDuty
   findings appear in the **Findings** view, normalized into the **AWS Security
   Finding Format (ASFF)** — a single JSON schema so you triage everything in one
   place. Standards like **FSBP** also generate their own control findings.
2. **Inspector scans three resource types: EC2 instances, ECR container images,
   and Lambda functions.** It finds **software vulnerabilities (CVEs)** and network
   reachability — a *vulnerability* class that Config (configuration compliance) and
   GuardDuty (active threats) do **not** cover.
3. **Console:** a failed FSBP control (e.g. "S3 buckets should prohibit public
   read") links to the specific non-compliant resource — the same drift your Phase
   3.1 rule caught, now rolled into the standard's score.

---

## D3.4 — Break/Fix

1. **CVE vs C2:** the **Inspector** finding reports the known-exploitable OpenSSL
   **CVE** on the instance; the **GuardDuty** finding reports the instance talking
   to a known **command-and-control / malicious** server. Inspector = latent
   vulnerability; GuardDuty = active behavior.
2. **Accepted risk:** use Security Hub **finding suppression** via an **automation
   rule / suppression filter** (set workflow status to `SUPPRESSED`) — it documents
   the decision and keeps an audit trail, rather than silently ignoring the finding
   (which would reappear and erode trust in the dashboard).

---

## B3.5 — Detective

1. **Three data sources:** **VPC Flow Logs, CloudTrail management events, and
   GuardDuty findings**, ingested into a **behavior graph**.
2. **Question Detective answers:** *is this activity normal for this entity?* It
   provides baselines and entity timelines to **scope an investigation** (how long
   has this IP been talking to us, what else did this principal do), which GuardDuty
   — a point-in-time detector — doesn't give you.

---

## D3.5 — service ownership

- (a) CVEs on OS packages → **Inspector**
- (b) IAM principal's API pattern changed over 30 days → **Detective**
- (c) instance talking to a crypto-mining domain → **GuardDuty**
- (d) prove a bucket stayed non-public for 24h → **Config** (configuration history /
  timeline)
- (e) one normalized list of all of the above → **Security Hub**

---

## Answer-cold

- **C3.1** A **configuration recorder** (captures configuration items when
  resources change) and a **delivery channel** (persists them to S3 / notifies
  SNS). Both are required before any rule can evaluate.
- **C3.2** It calls **`config:PutEvaluations`**, passing the compliance result and
  the **`ResultToken`** from the invoking event — the result is an API call back to
  Config, not a function return value.
- **C3.3** Because a **NACL supports explicit `deny` and is stateless/subnet-wide**,
  so it can block one IP while leaving everything else open; a **security group is
  allow-only** and cannot express a deny.
- **C3.4** At
  `detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4`;
  EventBridge matches on `source = aws.guardduty` and
  `detail-type = "GuardDuty Finding"`, optionally narrowed by severity/type.
- **C3.5** Inspector scans **EC2, ECR images, and Lambda for CVEs/vulnerabilities**;
  Config evaluates **resource configuration against compliance rules**. Different
  questions: "is the software vulnerable?" vs "is the configuration allowed?"
- **C3.6** **GuardDuty** = continuous threat *detection* from logs/flow/DNS.
  **Detective** = *investigation/scoping* of findings via a behavior graph.
  **Security Hub** = *aggregation + standards* — the normalized single pane.
