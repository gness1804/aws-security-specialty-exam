# Phase 4 — Perimeter defense & logging integrity (Week 6)

**Domains trained:** Domain 2 (Security Logging & Monitoring, 18%) and Domain 3
(Infrastructure Security, 20%) — together the single largest weight on the exam.
Light overlap into Domain 6 (the org-trail + log-archive pattern is governance).

**The mindset shift:** Phase 3 made the system *notice and self-heal*. Phase 4
hardens the two things an attacker goes after next: the **edge** (can they reach
your app at all?) and the **evidence** (can they erase the proof?). You'll put a
WAF in front of an application, build a CloudTrail you can *prove* wasn't tampered
with, make a log bucket that even root can't delete from, and learn to interrogate
all of it with SQL. The throughline: a control you can't audit isn't a control.

By the end you should be able to trace a request from the internet through the WAF,
and trace an API call from the moment it happens to a tamper-evident record of it
sitting in a bucket nobody can quietly empty.

---

## How this lab works

Same active-recall format. Build/Break-Fix sections **pose the task and stop** —
sketch your answer, then check `answers/phase-4-answers.md` (keyed **B4.1**,
**D4.3**, …), the files in `policies/phase-4/`, and the runnable tooling in
`scripts/phase-4/`. Prerequisite and Teardown are given in full.

> **Cost warning:** an ALB bills per hour, WAF bills per Web ACL + per rule + per
> request, CloudTrail's *first* trail is free but data events and extra trails
> bill, and Athena bills per TB scanned. Stand things up at the start of a session,
> run the teardown at the end. See `cost-safety.md`.

---

## Prerequisite

- Phases 1–3 complete; work in **Account B** (`scs-member`) unless a step says
  otherwise. One region throughout (`us-east-1` in examples).
- An **internet-facing ALB** to protect in 4.1. If you don't have one, the setup
  script can point WAF at an existing ALB ARN you pass it; standing up the ALB +
  target group + a tiny instance is left as ordinary infra (not an exam concept).
  A two-target setup isn't needed — even an ALB returning 503 demonstrates the WAF.
- A **default VPC with Flow Logs** you can enable for 4.4 (the script enables them
  to an S3 bucket if absent).
- For 4.2's *org-trail* discussion you'd want a second (log-archive) account, but
  the script defaults to a **single-account trail with log-file validation** so it
  runs in your current setup. Read the org pattern; build the runnable version.

> **Reading after the labs:** AWS WAF + CloudTrail log-file validation + the SRA
> log-archive account pattern (see `reading-list.md`, Phase 4).

---

## Scenario 4.1 — WAF Web ACL blocking SQLi + XSS on an ALB  ·  **Core**

### Goal
Put an **AWS WAF (v2)** Web ACL in front of an ALB that blocks SQL-injection and
cross-site-scripting attempts — using both AWS **managed rule groups** and one
**custom match statement** you write yourself — then associate it with the ALB.

### Why the exam cares
WAF is the exam's go-to answer for **layer-7** filtering. You must know: WAF
attaches to **ALB, CloudFront, API Gateway, AppSync, and Cognito** — **not** to an
EC2 instance or an NLB (those are layer 3/4); the **scope** is `REGIONAL` for an
ALB and `CLOUDFRONT` (in `us-east-1`) for CloudFront; the Web ACL has a **default
action** (Allow) and rules that **Block/Allow/Count**; managed rule groups
(`AWSManagedRulesCommonRuleSet` for XSS, `AWSManagedRulesSQLiRuleSet` for SQLi)
versus custom `SqliMatchStatement` / `XssMatchStatement`; **text transformations**
(URL_DECODE, HTML_ENTITY_DECODE) that defeat evasion; **WCU** capacity limits; and
that **Count mode** lets you test a rule in production without blocking.

### Build challenge · B4.1
1. Create a **Web ACL** with **scope `REGIONAL`** and **default action Allow**. Why
   is the default Allow (not Block), and what would flip that decision?
2. Add two **managed rule groups** — the common rule set (catches XSS) and the SQLi
   rule set — each in **Block** mode, each with a distinct **priority**. Then add
   **one custom rule** of your own: an `XssMatchStatement` (or `SqliMatchStatement`)
   inspecting the query string with a **text transformation** applied. Why apply a
   transformation like URL_DECODE before the match — what evasion does it defeat?
3. **Associate** the Web ACL with your ALB. What's the one identifier the
   association call needs, and what happens to requests already in flight?

> Hint: a rule that *blocks* lives inside a Web ACL whose *default* lets everything
> else through. The order rules run in is the `Priority`, lowest first.

→ Reference: `answers/phase-4-answers.md` → **B4.1**. Policy/JSON:
`policies/phase-4/4.1-webacl-rules.json`. Tooling:
`scripts/phase-4/setup_waf_alb.py` (dry-run first).

### Verify · V4.1
```bash
# A SQLi-ish query string; expect HTTP 403 once the Web ACL is associated.
curl -s -o /dev/null -w "%{http_code}\n" "http://<ALB_DNS>/?q=1%27%20OR%20%271%27%3D%271"
# A normal request; expect 200 (or your app's normal response).
curl -s -o /dev/null -w "%{http_code}\n" "http://<ALB_DNS>/?q=hello"
```
What status does each return when the WAF is working, and **where** do you confirm
the block independent of the HTTP code (which AWS feature shows you the matched
rule and a sample of the request)?
→ `answers/phase-4-answers.md` → **V4.1**

### Break it / Fix it · D4.1
1. Switch the SQLi rule's action from **Block** to **Count** and re-send the attack.
   What changes for the caller, and what's the legitimate operational reason you'd
   ever run a rule in Count?
2. **Capacity:** keep adding rules until you approach the Web ACL's **WCU** limit.
   What error appears, and what are your two options when a Web ACL is out of WCU?
3. **Conceptual:** your security team says "just put the WAF on the EC2 instances."
   Why can't you, and what's the correct placement to protect those instances at
   layer 7?

→ `answers/phase-4-answers.md` → **D4.1**

---

## Scenario 4.2 — Tamper-evident CloudTrail to an isolated log bucket  ·  **Core**

### Goal
Create a **multi-region CloudTrail** with **log-file integrity validation** enabled,
delivering to an S3 bucket whose policy only CloudTrail can write to — and then
**validate** the logs to prove they weren't altered. Understand how this scales to
an **organization trail** landing in a dedicated **log-archive account**.

### Why the exam cares
Domain 2's core question is *can you trust your logs?* You must know: **log-file
validation** produces **digest files** containing **SHA-256 hashes** of each log
file, **signed** with a CloudTrail private key, so `aws cloudtrail validate-logs`
can detect any modification, deletion, or insertion; **organization trails**
(created in the management account, `IsOrganizationTrail=true`) capture every member
account and **can't be turned off by a member**; the **log-archive account** pattern
(SRA) isolates logs so an attacker who owns a workload account still can't reach
them; the difference between **management events** (free, on by default) and **data
events** (S3 object-level, Lambda invoke — billed, off by default); and the S3
**bucket policy** CloudTrail needs (`s3:PutObject` with
`bucket-owner-full-control` and an `aws:SourceArn` condition).

### Build challenge · B4.2
1. Create a trail that is **multi-region** with **log-file validation on**, writing
   to an S3 bucket. What two artifacts does validation add to the bucket, and what
   does each contain?
2. Write the **S3 bucket policy** that lets CloudTrail (and only CloudTrail) deliver
   objects. Name the two conditions that stop the *confused-deputy* problem and
   ensure the bucket owner can read what's written.
3. **Org pattern (conceptual + policy):** if this were an `IsOrganizationTrail`
   delivering to a bucket in a **separate log-archive account**, what changes in (a)
   *where* you create the trail and (b) the bucket policy's principals/conditions?
   Why is a member account unable to stop this trail?

> Hint: the thing that makes the logs *trustworthy* isn't encryption — it's a
> second set of files whose hashes you can recompute and a signature you can verify.

→ Reference: `answers/phase-4-answers.md` → **B4.2**. Policy:
`policies/phase-4/4.2-cloudtrail-bucket-policy.json`. Tooling:
`scripts/phase-4/setup_org_cloudtrail.py` (defaults to single-account + validation).

### Verify · V4.2
```bash
aws cloudtrail validate-logs --trail-arn <TRAIL_ARN> \
  --start-time 2026-06-01T00:00:00Z --profile scs-member
```
What does a clean run report, and what does it report if a log file was deleted or
edited? (You may need to wait for the first digest file — how often are they
delivered?)
→ `answers/phase-4-answers.md` → **V4.2**

### Break it / Fix it · D4.2
1. **Delete or modify** one delivered log file in the bucket, then re-run
   `validate-logs`. Exactly what does it say, and what does that prove you *can* and
   *cannot* recover?
2. **Disable validation**, let a new log file land, then re-enable it. Is the gap
   detectable later — and what does that tell you about turning validation on *after*
   an incident vs *before*?
3. **Conceptual:** an attacker gains admin in the workload account and wants the
   logs gone. With a single-account trail vs an org trail to a log-archive account,
   what can they delete in each case?

→ `answers/phase-4-answers.md` → **D4.2**

---

## Scenario 4.3 — A log bucket even root can't empty: deny-delete + Object Lock  ·  **Core**

### Goal
Protect the log bucket from deletion two ways and understand why you need both: a
**bucket policy** that explicitly **denies `s3:DeleteObject`** (and friends), and
**S3 Object Lock** in **COMPLIANCE** mode for true **WORM** retention that not even
the account root can override.

### Why the exam cares
This is the exam's favorite "ransomware / insider / log-tampering" control. You must
know: **Object Lock requires versioning** and is normally enabled **at bucket
creation**; **GOVERNANCE** mode can be bypassed by a principal with
`s3:BypassGovernanceRetention`, while **COMPLIANCE** mode **cannot be bypassed by
anyone, including the root user**, until retention expires; **legal hold** is an
on/off lock with no date; and the crucial subtlety that an **explicit deny in a
bucket policy applies to every principal in the account *including root* — but root
can simply *remove* that bucket policy**, whereas COMPLIANCE-mode Object Lock is
enforced by S3 itself and survives policy changes.

### Build challenge · B4.3
1. Write a **bucket policy** statement that **denies** `s3:DeleteObject`,
   `s3:DeleteObjectVersion`, and `s3:PutBucketObjectLockConfiguration` to **all
   principals** (`"Principal": "*"`). Does an explicit deny here stop the **account
   root**? And what can root still do that defeats this protection?
2. Enable **Object Lock** with a default **retention** in **COMPLIANCE** mode for N
   days. What did you have to enable on the bucket first, and why can't you simply
   turn Object Lock on for any old existing bucket?
3. **Distinguish:** GOVERNANCE vs COMPLIANCE vs legal hold — for "logs that must be
   immutable for 1 year even against a rogue admin with full IAM," which one, and why
   the others fall short.

> Hint: a bucket policy is something *you* (or root) can edit. Object Lock in one
> particular mode is something *S3* enforces and *nobody* can shorten.

→ Reference: `answers/phase-4-answers.md` → **B4.3**. Policy:
`policies/phase-4/4.3-deny-delete-bucket-policy.json`. Tooling:
`scripts/phase-4/setup_s3_object_lock.py`.

### Break it / Fix it · D4.3
1. With the **deny-delete bucket policy** in place, try to delete an object as your
   admin user. It fails. Now (carefully, on a throwaway bucket) **remove the bucket
   policy** as root and delete again. What does this prove about bucket-policy-only
   protection?
2. With **COMPLIANCE** Object Lock and an unexpired retention, try to delete the
   object version. What error, and does adding `s3:BypassGovernanceRetention` help?
3. **Conceptual:** you set GOVERNANCE mode thinking it was "good enough." An admin
   with `s3:BypassGovernanceRetention` deletes the logs the night before an audit.
   What single configuration change would have stopped them, and what's the
   trade-off you accept by making it?

→ `answers/phase-4-answers.md` → **D4.3**

---

## Scenario 4.4 — Interrogate the evidence: Athena over CloudTrail + Flow Logs  ·  **Core**

### Goal
Stand up **Athena** tables over your **CloudTrail** logs and **VPC Flow Logs** in
S3, then write the queries an incident responder actually runs: *who made denied API
calls, did root do anything, what traffic got rejected at the subnet.*

### Why the exam cares
Domain 2 + Domain 1: you must know **Athena is serverless SQL over S3**, billed
**per TB scanned** (so **partitioning** — especially **partition projection** on
date/region/account — is the cost control the exam tests); that CloudTrail and Flow
Logs each have a known schema you define as an **external table** (with the right
**SerDe**); and **when to reach for Athena vs CloudTrail Lake** (Lake = managed
event data store with its own SQL, no table DDL; Athena = bring-your-own-table over
raw S3, more flexible/cheaper for ad-hoc).

### Build challenge · B4.4
1. Create an Athena **external table** over the CloudTrail S3 prefix using the
   CloudTrail SerDe. Why must this be an *external* table, and what does
   **partition projection** buy you over scanning the whole prefix?
2. Write the query that finds every **`AccessDenied` / `UnauthorizedOperation`**
   event in the last day, returning the principal, the event name, and the source IP.
   Which CloudTrail field carries the failure, and which carries the caller?
3. Write a **VPC Flow Logs** query that returns the top source IPs whose traffic was
   **`REJECT`ed**. Which field is the action, and how would you use this to spot a
   port scan?

> Hint: Athena reads what's *already* in S3 — you're describing the shape of files
> that exist, not loading data. The cheaper your partitions, the less you scan.

→ Reference: `answers/phase-4-answers.md` → **B4.4**. Query starters:
`scripts/phase-4/athena_security_queries.sql`. Tooling (creates DB + tables, runs a
query): `scripts/phase-4/setup_athena_security.py`.

### Break it / Fix it · D4.4
1. Run a query that scans the **whole** CloudTrail prefix, note the **data scanned**.
   Add a date partition predicate and run again. How much less did it scan, and why
   does that map directly to cost?
2. **Conceptual:** a teammate proposes querying CloudTrail by downloading the JSON
   and grepping it. Give two concrete reasons Athena (or Lake) wins for anything
   beyond a one-off.
3. **Conceptual:** you need queryable history of a *specific* high-value S3 bucket's
   object-level reads. What did you have to enable back in **4.2** for those events
   to even exist in CloudTrail, and is it free?

→ `answers/phase-4-answers.md` → **D4.4**

---

## Scenario 4.5 — Real-time alarms: metric filter on root login & IAM changes  ·  **Stretch**

### Goal
Send CloudTrail to **CloudWatch Logs**, then create **metric filters** that count
**root-account usage** and **IAM policy changes**, with **CloudWatch alarms** that
notify an **SNS** topic the moment either happens. These are textbook **CIS
benchmark** monitoring controls.

### Why the exam cares
The exam expects you to know the **CloudTrail → CloudWatch Logs → metric filter →
alarm → SNS** pipeline cold (it's the answer to "alert me in near-real-time when
X"), the difference between this **push/alarm** path and the **pull/query** path of
Athena (4.4), that sending CloudTrail to CW Logs needs a **CloudWatch Logs role**,
and the **filter-pattern syntax** for matching JSON event fields — especially the
canonical root-usage pattern.

### Build challenge · B4.5
1. Wire CloudTrail to a **CloudWatch Logs** log group. What extra IAM construct does
   CloudTrail need to write there, and why isn't S3 delivery enough for *alarming*?
2. Write the **metric filter pattern** for **root usage** —
   `userIdentity.type = "Root"`, excluding normal AWS service events — and a second
   for **IAM changes** (`Put*`/`Attach*`/`Create*` policy events). What do these
   patterns emit that an alarm can watch?
3. Create a **CloudWatch alarm** on each metric (threshold ≥ 1 over one period) that
   notifies an **SNS** topic. Why threshold ≥ 1, and why SNS rather than just the
   alarm state?

> Hint: a metric filter turns *matching log lines* into a *number*; an alarm watches
> that number cross a line and pulls the SNS lever.

→ Reference: `answers/phase-4-answers.md` → **B4.5**. Filter patterns:
`policies/phase-4/4.5-metric-filter-patterns.json`. Tooling:
`scripts/phase-4/setup_cw_metric_alarms.py`.

### Break it / Fix it · D4.5
1. Trigger the root-usage filter (sign in as root in the console, or simulate the
   log line). How long until the alarm fires and SNS notifies — and what governs
   that latency?
2. **Conceptual:** the same insight is available in Athena (4.4). When do you choose
   the metric-filter/alarm path over the Athena-query path, and vice versa?

→ `answers/phase-4-answers.md` → **D4.5**

---

## Phase 4 teardown

Full steps — housekeeping, not a drill. WAF, the ALB, extra trails, and Athena all
bill, so don't skip this.

- [ ] **WAF:** disassociate the Web ACL from the ALB and delete it
      (`scripts/phase-4/setup_waf_alb.py --teardown --apply`). Delete the ALB +
      target group + test instance if you created them for the lab.
- [ ] **CloudTrail:** delete the lab trail
      (`scripts/phase-4/setup_org_cloudtrail.py --teardown --apply`). Note: the
      **first** trail is free, so you may choose to leave a validated trail running.
- [ ] **S3 Object Lock buckets:** a COMPLIANCE-locked object **cannot** be deleted
      until retention expires — use a **short** retention (e.g. 1 day) for the lab,
      or accept the bucket lingers until it lapses. Remove the deny-delete policy
      from throwaway buckets first (`setup_s3_object_lock.py --teardown --apply`).
- [ ] **Athena:** drop the database/tables
      (`setup_athena_security.py --teardown --apply`); delete the Athena query-result
      bucket. The source CloudTrail/Flow-Log buckets stay (they're your evidence).
- [ ] **Metric filters / alarms / SNS:** delete them
      (`setup_cw_metric_alarms.py --teardown --apply`).
- [ ] Run `python scripts/phase-1/teardown_check.py --profile scs-member` for the sweep.

## What you should now be able to answer cold

Pure self-test — answers in `answers/phase-4-answers.md` → **Answer-cold**.

- **C4.1** Which four/five resource types can a WAF Web ACL attach to, and which
  common one can it *not*?
- **C4.2** What does CloudTrail log-file validation produce, and how do you prove a
  log file wasn't altered?
- **C4.3** Why does S3 Object Lock COMPLIANCE mode protect logs when a deny-delete
  bucket policy does not?
- **C4.4** Why does partitioning a CloudTrail Athena table reduce cost, and what's
  the one-line difference between Athena and CloudTrail Lake?
- **C4.5** Trace the five components, in order, of the near-real-time "alert me when
  root logs in" pipeline.
- **C4.6** Management events vs data events: which is on by default, which costs, and
  give one example of each.

When you can answer those without notes, you're ready for **Phase 5**.
