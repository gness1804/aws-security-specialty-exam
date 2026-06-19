# Phase 2 — Data protection: Secrets, TLS, S3 encryption, Macie (Week 3)

**Domains trained:** Domain 5 (Data Protection, 18%) primarily, with Domain 3
(Infrastructure Security — encryption *in transit*) and a touch of Domain 2
(discovery findings feed monitoring).

**The mindset shift:** Phase 1 controlled *who can reach* a resource. Phase 2
controls *the data itself* — rotate the credentials that protect it, force every
byte to move over TLS, guarantee it's encrypted at rest under a key you choose,
and prove you actually know where the sensitive data lives. The exam tests the
*enforcement mechanism* (a bucket policy condition, a listener redirect, a
rotation staging label), not just "is encryption on."

By the end you should be able to look at a failed rotation, a plaintext-HTTP
request, or an unencrypted `PutObject` and name the exact control that should have
caught it.

---

## How this lab works

Same as Phase 1: Build/Break-Fix sections **pose the task and stop**. Sketch your
answer first, then check `answers/phase-2-answers.md` (keyed **B2.1**, **D2.3**,
etc.), the paste-ready files in `policies/phase-2/`, and the runnable tooling in
`scripts/phase-2/`. Prerequisite and Teardown are given in full.

---

## Prerequisite

- Phase 1 complete (you have `scs-mgmt` / `scs-member` profiles and the org).
- Work in **Account B** (`scs-member`) unless noted; it's your sandbox workload account.
- Pick one region and stay in it (`us-east-1` in these examples) — **rotation
  Lambdas and their secrets must be co-regional**, and ACM/ALB are regional too.
- A throwaway VPC with a public subnet for the ALB scenario (the default VPC is fine).

> **Reading after the labs:** Secrets Manager rotation + S3 encryption options +
> ACM (see `reading-list.md`, Phase 2).

---

## Scenario 2.1 — Secrets Manager with automatic rotation  ·  **Core**

### Goal
Store a secret, attach a Lambda that rotates it on a schedule, and understand the
**four-step rotation contract** and the **staging labels** well enough to debug a
rotation that silently stops working.

### Why the exam cares
Rotation is the single most-tested Secrets Manager topic. The exam expects you to
know: the four rotation steps (`createSecret` → `setSecret` → `testSecret` →
`finishSecret`), the three staging labels (`AWSCURRENT`, `AWSPENDING`,
`AWSPREVIOUS`) and how they move, that the rotation Lambda and secret must be in
the **same region**, that the Lambda needs a **resource-based policy** allowing
`secretsmanager.amazonaws.com` to invoke it, and the classic failure mode: a
secret protecting a DB in a **private subnet** whose rotation Lambda can't reach
the Secrets Manager endpoint without a **VPC endpoint** (or NAT).

### Build challenge · B2.1
1. Create a secret (a fake DB credential JSON is fine —
   `{"username":"app","password":"..."}`). **Do not paste a real password
   anywhere it could be logged.**
2. **Before reading any code,** sketch what each of the four rotation steps must
   do and *which staging label moves at which step*. In particular: at the start
   of rotation, what label does the brand-new value get, and at which step does it
   become `AWSCURRENT`?
3. Enumerate the **IAM permissions** the rotation Lambda needs on Secrets Manager,
   and the **one resource-based policy** that must exist so rotation can invoke the
   Lambda at all.
4. Configure rotation on the secret with, say, a 30-day schedule.

> Hint (not the crux): the new secret value is created and staged *before* it's
> ever promoted; promotion is a single atomic re-labeling, not a copy.

→ Reference: `answers/phase-2-answers.md` → **B2.1**. Working rotation handler +
wiring script: `scripts/phase-2/secrets_rotation_lambda.py`,
`scripts/phase-2/setup_secret_rotation.py` (read the handler *after* step 2).

### Verify · V2.1
Trigger one rotation and confirm the value rolled without you ever printing it:
```bash
aws secretsmanager rotate-secret --secret-id scs/phase2/demo --profile scs-member
aws secretsmanager describe-secret --secret-id scs/phase2/demo \
  --query 'VersionIdsToStages' --profile scs-member
```
Predict what `VersionIdsToStages` should show for a healthy rotation (how many
versions, carrying which labels?).
→ `answers/phase-2-answers.md` → **V2.1**

### Break it / Fix it · D2.1
Predict the cause before you fix each:
1. **Strip the Lambda's resource policy** (remove the `secretsmanager.amazonaws.com`
   invoke permission). Trigger rotation. What happens, and where do you see the error?
2. **Remove the Lambda's `secretsmanager:PutSecretValue` permission.** Which of the
   four steps fails, and what label is left dangling?
3. **Conceptual:** the secret protects an RDS instance in a private subnet with no
   NAT. Rotation was working, then you tightened the subnet. Rotation now times
   out. What's the fix, and why is this an *in-transit/connectivity* problem, not a
   permissions problem?

→ `answers/phase-2-answers.md` → **D2.1**

---

## Scenario 2.2 — ACM certificate + enforce TLS in transit  ·  **Core**

### Goal
Issue a public ACM certificate, terminate HTTPS on an ALB, force HTTP→HTTPS, and
separately force **S3** access to TLS-only. Then articulate why you *can't* just
attach the ACM cert to an EC2 instance.

### Why the exam cares
Encryption *in transit* questions hinge on **where an ACM public cert can and
cannot live**: ALB / NLB / CloudFront / API Gateway / App Runner — **yes**; an EC2
instance directly — **no** (you can't export a public ACM cert's private key).
The exam also loves the S3 TLS-only bucket policy (`aws:SecureTransport`) and the
ALB listener redirect pattern.

### Build challenge · B2.2
1. Request a **public ACM certificate** for a domain you control and validate it
   via **DNS** (why is DNS validation preferred over email for automation?).
2. Stand up an ALB. Add an **HTTPS:443 listener** using the cert, and make the
   **HTTP:80 listener redirect** to 443. (CLI/script primary; the ALB wizard is
   fine too.)
3. Write an **S3 bucket policy** that **denies any request not made over TLS.**
   Which condition key and operator? Should the `Deny` apply to `"AWS": "*"`?
4. **Answer in writing:** your app runs on a bare EC2 instance and needs HTTPS.
   You cannot attach the ACM public cert to it. Name *two* valid ways to give that
   app HTTPS.

> Hint: the TLS-only bucket policy is a single `Deny` statement gated on one
> boolean condition key.

→ Reference + the EC2 answer: `answers/phase-2-answers.md` → **B2.2**
(`policies/phase-2/2.2-s3-deny-insecure-transport.json`).

### Break it / Fix it · D2.2
1. With the TLS-only bucket policy applied, fetch an object over **plain HTTP**
   (e.g. `curl http://<bucket>.s3.amazonaws.com/key`). What status/error, and which
   statement produced it?
2. Hit the ALB on **http://** (port 80). What happens, and what response code does
   the redirect return?

→ `answers/phase-2-answers.md` → **D2.2**

---

## Scenario 2.3 — S3 default encryption, bucket keys, and PutObject enforcement  ·  **Core**

### Goal
Turn on default SSE-KMS encryption with a **bucket key**, then add a bucket policy
that **rejects** any `PutObject` that isn't encrypted with *your* KMS key — so a
client can't downgrade to SSE-S3 or use the wrong key.

### Why the exam cares
You must distinguish **SSE-S3 vs SSE-KMS vs DSSE-KMS vs SSE-C**, know that S3 now
encrypts every object at rest by default (SSE-S3 minimum), know what a **bucket
key** does (cuts KMS request cost/throttling by caching a short-lived data key),
and — most tested — know the **bucket-policy conditions** that *enforce* a specific
encryption mode: `s3:x-amz-server-side-encryption` and
`s3:x-amz-server-side-encryption-aws-kms-key-id`.

### Build challenge · B2.3
1. Create a bucket, enable **default encryption = SSE-KMS** with a CMK you own and
   **bucket key enabled**. In one sentence, what does the bucket key actually save?
2. Write a bucket policy with **two** `Deny` statements: (a) deny `PutObject` when
   the request's server-side-encryption header isn't `aws:kms`, and (b) deny
   `PutObject` when the KMS key id isn't your key's ARN. Which condition operator
   handles the "header absent entirely" case?
3. **Subtlety to resolve:** since S3 auto-encrypts by default now, what does the
   explicit `Deny` policy still buy you that default encryption alone does not?

→ Reference: `answers/phase-2-answers.md` → **B2.3**
(`policies/phase-2/2.3-s3-deny-unencrypted-put.json`,
`2.3-s3-deny-wrong-kms-key.json`). Apply with
`scripts/phase-2/enforce_s3_encryption.py`.

### Break it / Fix it · D2.3
Predict, then test (the script's `--break` mode performs these uploads):
1. `PutObject` with **no** encryption header. Allowed or denied? By which statement?
2. `PutObject` with `--sse aws:kms` but the **wrong key**. Result?
3. `PutObject` with `--sse aws:kms --sse-kms-key-id <your key>`. Result?

→ `answers/phase-2-answers.md` → **D2.3**

---

## Scenario 2.4 — Macie sensitive-data discovery  ·  **Stretch**

### Goal
Enable Macie, seed a bucket with fake PII, run a discovery job, and read the
findings. Then build a **custom data identifier** for a token format Macie's
managed identifiers don't know.

### Why the exam cares
Domain 5/Domain 2 questions ask *how you'd locate sensitive data at scale* and
*how findings flow*. Know: Macie's **managed data identifiers** (PII, credentials,
financial), **custom data identifiers** (regex + optional keywords + proximity),
one-time vs scheduled **discovery jobs** vs **automated sensitive data
discovery**, that Macie is **regional**, and that findings publish to
**EventBridge** and **Security Hub**.

### Build challenge · B2.4
1. Enable Macie in your region (CLI/Boto3). Seed a small bucket with a text file
   of obviously-fake PII (SSNs, emails, a fake credit-card-shaped number).
2. Create a **one-time sensitive-data discovery job** scoped to that bucket. While
   it runs, predict which **managed data identifiers** will fire.
3. **Custom identifier:** your app emits tokens shaped like `SCSLAB-<8 hex>`.
   Macie won't flag those. Write the **regex** for a custom data identifier that
   would. What two optional features could cut false positives?
4. Review findings in the **Macie console** (this is the one place console beats
   CLI — the finding detail view is the exam's mental model).

> Hint: a custom data identifier is *regex first*; keywords/proximity are
> refinements, not the match itself.

→ Reference (regex + flow): `answers/phase-2-answers.md` → **B2.4**. Enable +
job-create tooling: `scripts/phase-2/macie_discovery.py`.

### Break it / Fix it · D2.4
1. Your custom regex matches `SCSLAB-1a2b3c4d` but also fires on
   `DESCSLAB-1a2b3c4d` inside other words. How do you tighten it?
2. **Conceptual:** Macie reports a bucket as **unencrypted/public** even though
   objects are SSE-S3 encrypted. What is Macie actually flagging here, and why
   isn't that a contradiction?

→ `answers/phase-2-answers.md` → **D2.4**

---

## Phase 2 teardown

Full steps — housekeeping, not a drill.

- [ ] **Secrets Manager:** `aws secretsmanager delete-secret --secret-id scs/phase2/demo
      --force-delete-without-recovery --profile scs-member` (skips the 7–30 day window).
- [ ] **Rotation Lambda:** delete the function and its IAM role if you created them
      (`scripts/phase-2/setup_secret_rotation.py --teardown`).
- [ ] **ALB + listeners + target group:** delete (they bill hourly). Leave the ACM
      cert — public certs are free and auto-renew; or delete it if you won't reuse it.
- [ ] **S3:** empty and delete the demo + Macie buckets. KMS CMK: schedule deletion
      if it was a throwaway.
- [ ] **Macie:** disable it (`aws macie2 disable-macie --profile scs-member`) so it
      stops accruing per-GB discovery cost.
- [ ] Run `python scripts/phase-1/teardown_check.py --profile scs-member` for the
      cross-cutting sweep.

## What you should now be able to answer cold

Pure self-test — answers in `answers/phase-2-answers.md` → **Answer-cold**.

- **C2.1** Name the four rotation steps in order and the staging label that moves at the last one.
- **C2.2** Why can't you attach a public ACM certificate to an EC2 instance, and what do you do instead?
- **C2.3** Which bucket-policy condition keys enforce (a) "must be SSE-KMS" and (b) "must be *this* KMS key"?
- **C2.4** SSE-S3 vs SSE-KMS vs DSSE-KMS vs SSE-C — who holds/manages the key in each?
- **C2.5** What does an S3 **bucket key** reduce, and why does that matter at scale?
- **C2.6** A rotation Lambda for a private-subnet RDS secret times out. First thing you check?

When you can answer those without notes, you're ready for **Phase 3**.
