# Phase 2 — Answer key (Data Protection)

Consult **after** attempting each challenge in
`labs/phase-2-data-protection.md`. IDs match the lab. Canonical policy JSON lives
in `policies/phase-2/`; runnable tooling in `scripts/phase-2/`.

---

## B2.1 — Secrets Manager rotation

**The four steps** (a single rotation invokes the Lambda four times, once per
step, passing the step name and the secret's version):

1. **`createSecret`** — generate the *new* secret value (e.g.
   `GetRandomPassword`) and store it with `PutSecretValue` under the staging label
   **`AWSPENDING`**. The old value keeps **`AWSCURRENT`**. Idempotent: if an
   `AWSPENDING` version already exists, do nothing.
2. **`setSecret`** — change the actual resource (e.g. run `ALTER USER` on the DB)
   so the new `AWSPENDING` value becomes valid. This is the service-specific step;
   for a generic secret with no backing service it can be a no-op.
3. **`testSecret`** — verify the `AWSPENDING` value actually works (open a DB
   connection with it, etc.). Fail loudly here rather than promote a broken secret.
4. **`finishSecret`** — atomically **move `AWSCURRENT` onto the `AWSPENDING`
   version**. The version that *was* `AWSCURRENT` then takes `AWSPREVIOUS`, and
   Secrets Manager clears the `AWSPENDING` label once rotation completes (your
   handler only moves `AWSCURRENT` — it never touches `AWSPENDING` itself). This is
   a *re-labeling*, not a copy — the promotion is the last thing that happens.

**Staging labels:** `AWSCURRENT` = the live value clients get by default;
`AWSPENDING` = the candidate mid-rotation; `AWSPREVIOUS` = the immediately prior
value (kept for rollback).

**Lambda IAM permissions** (on Secrets Manager): `GetSecretValue`,
`PutSecretValue`, `UpdateSecretVersionStage`, `DescribeSecret`,
`GetRandomPassword`, plus whatever the backing resource needs (e.g. `rds:...` or a
DB connection). Scope `GetSecretValue`/`PutSecretValue` to the secret ARN.

**The one resource-based policy that must exist:** a **Lambda resource policy**
(`lambda:AddPermission`) allowing **`secretsmanager.amazonaws.com`** to
`lambda:InvokeFunction`, conditioned on your account. Without it, Secrets Manager
cannot invoke the rotation function at all — rotation never even starts.

**Same-region rule:** the rotation Lambda must be in the same Region as the
secret.

---

## V2.1 — healthy rotation

`VersionIdsToStages` should show **two version IDs**: one carrying
`["AWSCURRENT"]` (the freshly promoted value) and one carrying `["AWSPREVIOUS"]`
(the value that was current before). No version should still be holding
`AWSPENDING` — a lingering `AWSPENDING` means rotation didn't reach
`finishSecret`. You confirmed all this **without printing the secret string** —
only version IDs and labels.

---

## D2.1 — Break/Fix answers

1. **No Lambda resource policy →** Secrets Manager can't invoke the function;
   rotation fails immediately. You see it in the secret's rotation status /
   CloudTrail (`AccessDeniedException` on the invoke), not in the Lambda logs
   (the Lambda never ran).
2. **No `PutSecretValue` →** **`createSecret`** fails (step 1), because it can't
   stage the new value. No `AWSPENDING` version is created; `AWSCURRENT` is
   untouched, so clients keep working but the secret never rotates. (If you instead
   removed `UpdateSecretVersionStage`, step 4 `finishSecret` fails and you're left
   with a dangling `AWSPENDING` version.)
3. **Private-subnet RDS, no NAT →** the Lambda can reach the DB (same VPC) but
   can't reach the **Secrets Manager API endpoint** to read/write the secret, so it
   hangs until timeout. Fix: add a **Secrets Manager interface VPC endpoint**
   (PrivateLink) in the Lambda's subnets (or a NAT gateway). It's a *connectivity*
   problem — the Lambda has the IAM permission, it just has no network path to the
   regional API.

---

## B2.2 — ACM + TLS

**DNS validation** is preferred because ACM can **auto-renew** the cert
indefinitely as long as the validation CNAME stays in your zone — no human action
each year. Email validation requires a human to click a link per renewal cycle.

**ALB listeners:** HTTPS:443 listener with the ACM cert and a modern TLS security
policy; HTTP:80 listener with a single **redirect** action to
`HTTPS://#{host}:443/#{path}?#{query}` returning **HTTP 301**.

**S3 TLS-only bucket policy** (`policies/phase-2/2.2-s3-deny-insecure-transport.json`):
a `Deny` on `"AWS": "*"` for `s3:*` when `aws:SecureTransport` is `false`. Yes —
the `Deny` should apply to `"*"`; you want *everyone*, including your own
principals, forced onto TLS. Condition: `"Bool": {"aws:SecureTransport": "false"}`.

**EC2 + HTTPS (you cannot attach the public ACM cert directly):** two valid ways —
(a) put an **ALB or CloudFront in front** of the instance and terminate TLS there
with the ACM cert; (b) use **ACM Private CA** to issue a private cert you *can*
export/install on the instance, or import a third-party cert into ACM/IAM for use
on a load balancer. (You can't export a *public* ACM cert's private key, which is
why direct attach is impossible.)

---

## D2.2 — Break/Fix answers

1. **Plain-HTTP S3 fetch →** `403 AccessDenied`, produced by the
   `DenyInsecureTransport` statement (the request arrived with
   `aws:SecureTransport=false`). Note: explicit `Deny` always wins over any allow.
2. **HTTP to the ALB →** the port-80 listener returns **301** and the client is
   redirected to the HTTPS URL; no app traffic is served over plaintext.

---

## B2.3 — S3 encryption enforcement

**Bucket key** caches a single KMS-generated data key at the bucket level for a
short time so S3 doesn't call `kms:GenerateDataKey`/`Decrypt` on **every** object
operation — it cuts KMS request **cost and throttling** dramatically at scale.

**Two deny statements:**

(a) `policies/phase-2/2.3-s3-deny-unencrypted-put.json` — deny `s3:PutObject` when
`s3:x-amz-server-side-encryption` is **not** `aws:kms`. Use **`StringNotEquals`**
*and* a `Null`-true variant (or `StringNotEquals` with `Null` handling) so that a
request which **omits the header entirely** is also denied — `StringNotEquals`
alone can pass a missing key, so the **`Null`** operator (`"...": "true"`) is what
catches "header absent."

(b) `policies/phase-2/2.3-s3-deny-wrong-kms-key.json` — deny `s3:PutObject` when
`s3:x-amz-server-side-encryption-aws-kms-key-id` `StringNotEquals` your key ARN.

**What the explicit Deny buys you over default encryption:** default encryption
guarantees objects are *encrypted*, but a client can still **override** the
request to SSE-S3 or a *different* KMS key. The deny policy makes the bucket
**reject** those requests, so you enforce *which* key/mode protects the data — an
auditable, exam-favored guarantee, not just "something encrypted it."

---

## D2.3 — Break/Fix answers

1. **No header →** denied by the `Null`/`StringNotEquals` statement (header
   absent). (Object is *not* written. Contrast: with only default encryption and
   no deny policy, S3 would silently apply SSE-KMS and accept it.)
2. **`aws:kms` + wrong key →** denied by the
   `...-aws-kms-key-id StringNotEquals` statement.
3. **`aws:kms` + your key →** succeeds; both conditions satisfied.

---

## B2.4 — Macie

**Likely managed identifiers that fire** on the seeded file: US SSN, email
address, and credit-card number (Macie ships managed data identifiers for each).

**Custom data identifier regex** for `SCSLAB-<8 hex>`:

```
SCSLAB-[0-9a-fA-F]{8}
```

**Two false-positive reducers:** (1) **keywords** — require a nearby word like
`token` or `scslab` within a maximum **proximity** distance; (2) an **ignore
words / exclusion** list, or a tighter **word-boundary** anchor. (Macie custom
identifiers support keywords, maximum-match-distance, and ignore words.)

**Findings flow:** Macie findings publish to **EventBridge** (automate response)
and **Security Hub** (single pane). Macie is **regional** — enable it per region
you store data in.

---

## D2.4 — Break/Fix answers

1. **`DESCSLAB-...` false match →** anchor the regex with a word boundary so it
   won't match mid-word: `\bSCSLAB-[0-9a-fA-F]{8}\b`. (The leading `\b` stops the
   `...SCSLAB` inside `DESCSLAB` from matching.)
2. **"Unencrypted/public" finding on SSE-S3 objects →** Macie's bucket-level
   *policy* findings evaluate **block-public-access / bucket policy / default
   encryption configuration**, which is separate from whether individual objects
   happen to be encrypted. A bucket can hold encrypted objects yet still have
   public-access settings or a missing *default*-encryption configuration that
   Macie flags. It's flagging the **bucket's posture**, not decrypting objects —
   no contradiction.

---

## Answer-cold

- **C2.1** `createSecret` → `setSecret` → `testSecret` → `finishSecret`. At
  `finishSecret`, **`AWSCURRENT`** moves onto the `AWSPENDING` version (old current
  becomes `AWSPREVIOUS`).
- **C2.2** You can't export a public ACM cert's private key, so it can't be
  installed on the instance. Instead front the instance with an **ALB/CloudFront**
  (terminate TLS there) or use **ACM Private CA** / an imported cert.
- **C2.3** (a) `s3:x-amz-server-side-encryption` must equal `aws:kms` (with a
  `Null` check for the absent header); (b)
  `s3:x-amz-server-side-encryption-aws-kms-key-id` must equal your key ARN.
- **C2.4** **SSE-S3:** AWS owns/manages the key (AES-256), invisible to you.
  **SSE-KMS:** a KMS CMK (AWS-managed or customer-managed) — you get key policy +
  CloudTrail audit. **DSSE-KMS:** same as SSE-KMS but **dual-layer** (two
  independent encryptions) for high-assurance workloads. **SSE-C:** *you* supply
  and manage the key on every request; AWS never stores it.
- **C2.5** A bucket key reduces **KMS API requests** (cost and throttling) by
  caching a bucket-level data key instead of calling KMS per object — critical for
  high-volume buckets.
- **C2.6** **Network path to the Secrets Manager endpoint** — for a private-subnet
  resource, confirm a Secrets Manager **VPC interface endpoint** (or NAT) exists.
  The Lambda usually has the IAM permission; it's the connectivity that's missing.
