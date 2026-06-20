# Phase 4 — Answer key (Perimeter defense & logging integrity)

Consult **after** attempting each challenge in
`labs/phase-4-perimeter-logging.md`. IDs match the lab. Policy/JSON lives in
`policies/phase-4/`; runnable tooling in `scripts/phase-4/`.

---

## B4.1 — WAF Web ACL (SQLi + XSS) on an ALB

1. **Default action Allow.** A Web ACL is a default-allow firewall with *blocking
   exceptions*: legitimate traffic must pass, and you carve out the bad. You'd flip
   the default to **Block** only for a deny-by-default posture (e.g. an allow-list
   Web ACL that lets through known-good paths/IPs and blocks everything else).
2. **Two managed groups + one custom rule.** Add
   `AWSManagedRulesCommonRuleSet` (its `CrossSiteScripting_*` rules catch XSS) and
   `AWSManagedRulesSQLiRuleSet`, each as a `ManagedRuleGroupStatement` with action
   **Block** and a distinct **`Priority`** (rules evaluate low→high). Then a custom
   rule with an `XssMatchStatement` (or `SqliMatchStatement`) inspecting
   `QueryString` with a **`TextTransformation`** of `URL_DECODE` (often plus
   `HTML_ENTITY_DECODE`). The transformation **normalizes the input before
   matching**, defeating evasion where an attacker URL-encodes (`%27` for `'`) or
   HTML-entity-encodes the payload to slip past a naive string match.
3. **Associate.** `wafv2 associate-web-acl` needs the **ALB ARN** (`ResourceArn`)
   and the Web ACL ARN. Association takes effect within seconds; in-flight requests
   complete, new requests are evaluated. (Scope must be `REGIONAL` and the Web ACL in
   the **same region** as the ALB.)

See `policies/phase-4/4.1-webacl-rules.json` for the rule set and
`scripts/phase-4/setup_waf_alb.py` for the build/associate/teardown.

---

## V4.1 — verify

The SQLi-ish request returns **HTTP 403** (WAF blocks before it reaches the ALB
target); the normal request returns **200** (or your app's normal response).
Independent of the HTTP code, confirm the block in **WAF → Web ACL → Sampled
requests** (or enable **WAF logging** to CloudWatch Logs / Firehose / S3): the
sample shows the **matched rule** and the request details, which proves *which* rule
fired rather than guessing from the status code. The Web ACL's **CloudWatch
metrics** (`BlockedRequests`) also tick up.

---

## D4.1 — Break/Fix

1. **Block → Count.** In Count mode the attack request is **allowed through** but
   WAF still **records the match** (increments `CountedRequests`, appears in samples).
   Legitimate use: **test a new/managed rule in production** to measure false
   positives before you let it block real traffic.
2. **WCU limit.** Each Web ACL has a capacity budget (**1,500 WCU** by default per
   Web ACL); adding rules past it fails with a **`WAFLimitsExceededException`**. Your
   two options: **remove/simplify rules** (managed groups have fixed WCU costs), or
   **request a WCU quota increase**. The exam wants you to know WCU is the budgeting
   unit and managed groups consume a published amount.
3. **Can't WAF an EC2 instance.** WAF only attaches to **CloudFront, ALB, API
   Gateway, AppSync, and Cognito user pools** — layer-7 entry points. An EC2
   instance (or NLB) is layer 3/4, so you protect those instances by **putting them
   behind an ALB (or CloudFront)** and attaching the WAF there. For layer 3/4 you'd
   reach for security groups/NACLs/Network Firewall/Shield instead.

---

## B4.2 — Tamper-evident CloudTrail

1. **Validation artifacts.** With log-file validation on, CloudTrail writes, in
   addition to the gzipped **log files**, periodic **digest files** (to a
   `CloudTrail-Digest/` prefix). Each digest file lists the log files delivered in
   the last hour with a **SHA-256 hash** of each, chains to the previous digest, and
   is **digitally signed** with a CloudTrail private key. The log files are the
   evidence; the digest files are the **tamper-evidence**.
2. **Bucket policy.** Allow `s3:PutObject` to principal `cloudtrail.amazonaws.com`
   on `.../AWSLogs/<acct>/*`, and `s3:GetBucketAcl` on the bucket. Two conditions
   matter, and they do *different* jobs: the **confused-deputy guard** is
   **`StringEquals "aws:SourceArn": "<trail-arn>"`** (optionally with
   `aws:SourceAccount`) — it ensures only *your* trail, not some other account's
   CloudTrail tricked into writing here, can deliver. The
   **`StringEquals "s3:x-amz-acl": "bucket-owner-full-control"`** condition is an
   **ownership requirement**, not a confused-deputy guard — it forces CloudTrail to
   grant the bucket owner full control of the delivered objects so you can actually
   read them. See `policies/phase-4/4.2-cloudtrail-bucket-policy.json`.
3. **Org pattern.** (a) You create the trail in the **management account** with
   `--is-organization-trail`; it auto-applies to every member account, present and
   future. (b) The destination bucket lives in the **log-archive account**, and its
   policy's `aws:SourceArn`/`aws:SourceAccount` (and the `AWSLogs/<orgId>/<acct>/*`
   key paths) cover the whole org. A **member account can't stop the org trail** —
   it's owned by the management account and the member has no API authority over it;
   that's the entire point of putting the trail and the bucket outside the workload
   accounts.

---

## V4.2 — verify

A clean `validate-logs` run reports each digest/log file as **valid** and prints a
summary ("Results requested... X files valid"). If a log file was **modified**, it
reports that file's hash **doesn't match** the digest; if a file was **deleted**, it
reports it as **missing/expected but not found**. Digest files are delivered
**hourly**, so you may need to wait up to ~an hour after the trail starts before
there's a digest to validate against.

---

## D4.2 — Break/Fix

1. **Delete/modify a log file → re-validate.** `validate-logs` flags the exact file
   as **invalid (hash mismatch)** or **missing**, naming it. This proves you **can
   detect** tampering with certainty — but validation **does not recover** the
   content; the data in that file is gone unless you have versioning/backup/Object
   Lock (hence 4.3). Detection ≠ recovery.
2. **Disable then re-enable validation.** The **gap is detectable**: the digest
   chain references the prior digest, so a window with no digest coverage shows up as
   a break in the chain. Lesson: validation only protects files **written while it
   was on** — turning it on *after* an incident gives you nothing for the period that
   already passed. Enable it **before** you need it.
3. **Attacker with workload-account admin.** Single-account trail: they can
   `StopLogging`, delete the trail, and (absent Object Lock) empty the bucket — they
   own everything. Org trail to a **log-archive account**: they **can't** stop the
   org trail (management-owned) and **can't** reach the bucket (different account
   they don't control). The blast radius of a compromised workload account stops at
   that account.

---

## B4.3 — Deny-delete + Object Lock

1. **Explicit deny vs root.** An **explicit deny in a bucket policy applies to every
   principal in the account, including the root user** — so root's `DeleteObject`
   call is denied *while the policy is in place*. **But root can simply
   `PutBucketPolicy` to remove or rewrite the policy**, then delete. So a
   bucket-policy deny stops everyone except someone who can edit the policy itself.
2. **Object Lock prerequisites.** You must have **versioning enabled**, and Object
   Lock is normally enabled **at bucket creation** (`--object-lock-enabled-for-bucket`).
   You can't flip it on for an arbitrary existing bucket via the API (enabling it on
   an existing bucket requires AWS Support); versioning is mandatory because WORM
   retention is applied **per object version**.
3. **GOVERNANCE vs COMPLIANCE vs legal hold.** For "immutable for 1 year even
   against a rogue full-IAM admin," use **COMPLIANCE** mode: until retention expires,
   **no one — including the root user — can delete or overwrite** the object version,
   and the retention period **can't be shortened**. **GOVERNANCE** falls short
   because anyone with `s3:BypassGovernanceRetention` can override it. **Legal hold**
   is indefinite (no expiry) and good for litigation, but it's an on/off flag a
   privileged principal can also remove — it's not a fixed-term guarantee. See
   `policies/phase-4/4.3-deny-delete-bucket-policy.json`.

---

## D4.3 — Break/Fix

1. **Deny-delete policy → admin delete fails; root removes policy → delete
   succeeds.** This proves bucket-policy protection is only as strong as control over
   **who can change the policy**. It's a good *defense-in-depth* layer but **not** a
   guarantee against a principal who can call `PutBucketPolicy` (i.e. root or an
   admin). That's the gap COMPLIANCE Object Lock closes.
2. **COMPLIANCE + unexpired retention → delete the version.** Fails with
   **`AccessDenied` / Object Lock retention** error. Adding
   `s3:BypassGovernanceRetention` **does not help** — bypass only works for
   **GOVERNANCE** mode. COMPLIANCE is enforced by S3 itself regardless of IAM.
3. **GOVERNANCE deleted the night before the audit.** The single change that would
   have stopped them: **COMPLIANCE mode** (instead of GOVERNANCE). Trade-off: it's
   **irreversible** — you cannot shorten or remove the retention, cannot delete those
   object versions until the clock runs out, and you pay storage for them the whole
   time. That rigidity is exactly the guarantee, so choose the retention period
   deliberately.

---

## B4.4 — Athena over CloudTrail + Flow Logs

1. **External table + partition projection.** Athena tables are **external** because
   the data already lives in S3 and Athena only stores the **schema** in the Glue
   Data Catalog — dropping the table never touches the S3 objects.
   **Partition projection** lets Athena compute partition values (by date/region/
   account) from the S3 key layout instead of scanning a partition catalog or the
   whole prefix, so a dated query reads only the relevant day's objects — far less
   data scanned.
2. **Denied API calls.** Filter on **`errorcode`** for `AccessDenied*` /
   `UnauthorizedOperation` (and/or `errormessage`); return
   **`useridentity.arn`** (the caller), **`eventname`**, and **`sourceipaddress`**,
   bounded by a date partition. See `scripts/phase-4/athena_security_queries.sql`.
3. **Flow Logs REJECT.** The action field is **`action`** (`ACCEPT` / `REJECT`);
   group by **`srcaddr`** where `action = 'REJECT'`, order by count desc. A single
   source IP hitting **many different `dstport`s** with REJECTs is the signature of a
   **port scan**.

---

## D4.4 — Break/Fix

1. **Whole-prefix vs partitioned scan.** The unpartitioned query reports a large
   **Data scanned** figure; adding a date predicate drops it to roughly the single
   day's bytes. Athena **bills per TB scanned**, so less data scanned = proportionally
   lower cost (and faster). Partitioning is the primary Athena cost lever.
2. **Athena/Lake beats grep** because: (a) it **scales** — you query terabytes
   across accounts/regions without downloading anything; and (b) **partitioning +
   SQL** make it cheap and expressive (joins, aggregations, time windows) versus
   ad-hoc `grep` over JSON that you must first fetch and decompress.
3. **Object-level S3 reads.** Those are **data events**, which are **off by default
   and billed** — you must have **enabled S3 data events** on the trail (4.2) for the
   bucket for object-level `GetObject` to appear in CloudTrail at all. Management
   events alone wouldn't capture them.

---

## B4.5 — Metric filter on root usage & IAM changes

1. **CloudTrail → CW Logs needs a role.** CloudTrail assumes a **CloudWatch Logs
   role** (a service role granting `logs:CreateLogStream` / `logs:PutLogEvents`) to
   deliver events to the log group. S3 delivery alone isn't enough for **alarming**
   because S3 is **storage**, not an evaluation engine — metric filters + alarms live
   in CloudWatch and act in **near-real-time**, whereas S3 just holds the logs for
   later querying.
2. **Filter patterns.** Root usage (the canonical CIS pattern):
   `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`
   (the two exclusions drop normal service-initiated events so you only catch a human
   acting as root). IAM changes: match `Put*Policy` / `Attach*Policy` /
   `Create*Policy` / `DeletePolicy` etc. on `$.eventName`. Each filter increments a
   **CloudWatch custom metric** (e.g. value 1 per match) that an alarm can watch. See
   `policies/phase-4/4.5-metric-filter-patterns.json`.
3. **Alarm ≥ 1 → SNS.** Threshold **≥ 1 in a single period** because **one**
   occurrence of root usage or an IAM change is already noteworthy — you want to know
   on the first event, not after a trend. **SNS** because the alarm only changes
   *state*; SNS is what turns that state change into an actual **notification**
   (email/SMS/Lambda/ticket) a human or system receives.

---

## D4.5 — Break/Fix

1. **Trigger root usage.** The path is: event → CloudTrail → CW Logs (delivery
   latency, typically a few minutes) → metric filter increments the metric → alarm
   evaluates its **period** (e.g. 1 min/5 min) → SNS notifies. End-to-end latency is
   governed mainly by **CloudTrail-to-CW-Logs delivery time plus the alarm's
   evaluation period** — minutes, not seconds.
2. **Metric-filter/alarm vs Athena.** Use the **metric-filter/alarm** path for
   **near-real-time alerting on known, high-signal events** (root login, IAM change,
   security-group change) — push, proactive. Use **Athena** for **ad-hoc / historical
   investigation** across large volumes where you don't know the question in advance
   — pull, retrospective. They're complementary: alarms tell you *now*, Athena tells
   you *what happened*.

---

## Answer-cold

- **C4.1** A Web ACL attaches to **CloudFront, ALB, API Gateway, AppSync, and
  Cognito user pools**; it **cannot** attach to an **EC2 instance** (or an NLB) —
  those are layer 3/4, so you front them with an ALB/CloudFront and WAF that.
- **C4.2** Validation produces **digest files** containing **SHA-256 hashes** of
  each delivered log file, **signed** and **chained** to the prior digest; you prove
  integrity by running **`aws cloudtrail validate-logs`**, which recomputes hashes
  and verifies the signature, flagging any modified, deleted, or inserted file.
- **C4.3** A **deny-delete bucket policy** can be **removed by root** (or any
  principal with `PutBucketPolicy`), so it doesn't bind the account owner.
  **Object Lock COMPLIANCE** is enforced by **S3 itself** — until retention expires,
  **no one including root** can delete/overwrite the version and the period can't be
  shortened.
- **C4.4** Partitioning lets Athena scan **only the relevant objects** instead of the
  whole prefix, and Athena bills **per TB scanned**, so it directly cuts cost.
  One-liner: **Athena** = bring-your-own external tables over raw S3 (DDL, flexible);
  **CloudTrail Lake** = managed event data store with built-in SQL and no table setup.
- **C4.5** **Event → CloudTrail → CloudWatch Logs (via a CW Logs role) → metric
  filter → CloudWatch alarm → SNS.**
- **C4.6** **Management events** (control-plane, e.g. `RunInstances`,
  `AttachRolePolicy`) are **on by default and free** for the first copy; **data
  events** (data-plane, e.g. S3 `GetObject`, Lambda `Invoke`) are **off by default
  and billed**.
