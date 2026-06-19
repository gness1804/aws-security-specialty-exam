# Phase 1 — Answer key (IAM & KMS)

Consult this **after** you've attempted each challenge in
`labs/phase-1-preventative-architecture.md`. IDs match the lab (B = Build, V =
Verify, D = Drill, C = answer-cold). The canonical policy JSON also lives as
paste-ready files in `policies/phase-1/`.

> Using the answer to *check* your attempt cements the material. Using it to
> *skip* the attempt does not. The exam rewards recall, not recognition.

---

## B1.1 — Cross-account role: the two policies

**Identity-based policy on `analyst` in Account A** (`policies/phase-1/1.1-account-a-assume-permission.json`)
— this is the *who is allowed to ask* side. It carries **no** conditions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAssumeAuditRoleInB",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<ACCOUNT_B_ID>:role/CrossAccountAuditRole"
    }
  ]
}
```

**Trust (resource-based) policy on `CrossAccountAuditRole` in Account B**
(`policies/phase-1/1.1-account-b-trust-policy.json`) — this is the *under what
conditions will we say yes* side. The `Condition` block lives **here**, not on
the identity policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustAccountAAnalystWithMFAandIP",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_A_ID>:user/analyst" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": { "aws:MultiFactorAuthPresent": "true" },
        "NumericLessThan": { "aws:MultiFactorAuthAge": "3600" },
        "IpAddress": { "aws:SourceIp": ["203.0.113.0/24"] }
      }
    }
  ]
}
```

Replace the CIDR with your egress block. `aws:MultiFactorAuthAge` (optional but
exam-relevant) forces re-auth after an hour.

**Permissions policy on the role:** attach the AWS-managed `SecurityAudit` policy
(or any read-only set). **Why it's separate:** the trust policy decides *who may
assume*; the permissions policy decides *what the session can do once assumed*.
The exam tests that you know these are two distinct evaluations — a principal can
pass the trust policy and still be unable to act, or fail the trust policy and
never get a session at all. Both sides must succeed for a cross-account action to
work: an identity-based `Allow` in A **and** a trust `Allow` (with conditions
met) in B.

---

## V1.1 — what success looks like

The `assume-role` call returns a temporary credential set:
`AccessKeyId`, `SecretAccessKey`, `SessionToken`, plus `Expiration` and the
`AssumedRoleId`/`Arn`. **The output must never be logged or pasted anywhere** —
`SecretAccessKey` and `SessionToken` are live credentials. `assume_role_test.py`
prints only the assumed-role ARN and the expiry timestamp, never the secret
material, which is the habit the course (and your CLAUDE.md house rules) enforce.

---

## D1.1 — Break/Fix answers

1. **No MFA →** `AccessDenied` on the `sts:AssumeRole` call. The
   `Bool: aws:MultiFactorAuthPresent = true` condition evaluated false. Exam
   phrasing: "user is denied despite having `sts:AssumeRole` permission" — the
   trust-policy condition is the cause.
2. **Wrong IP →** `AccessDenied`. The `IpAddress: aws:SourceIp` condition didn't
   match the request's source IP. (Note: behind NAT/VPN your apparent source IP
   is the egress address, not your LAN address — a common real-world gotcha.)
3. **Different principal →** `analyst` is denied **even with correct MFA and IP**,
   because the `Principal` element no longer matches `analyst`'s ARN. This proves
   the principal is matched *independently of* and *before* the conditions — if
   the principal doesn't match, the conditions are never the deciding factor.
4. **Account-root principal (`...:root`) →** `analyst` would *additionally* need
   an identity-based `sts:AssumeRole` permission in Account A. The `:root`
   principal delegates trust to the **whole account**, which means Account A's own
   IAM administrators decide *which* of its principals may use that trust. That's
   exactly why both the identity side (A) and the resource side (B) exist.

---

## B1.1b — OrgID trust + permission boundary

**Org-scoped trust policy** (`policies/phase-1/1.1b-trust-with-orgid.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "*" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "aws:PrincipalOrgID": "o-xxxxxxxxxx" },
      "Bool": { "aws:MultiFactorAuthPresent": "true" }
    }
  }]
}
```

**Why `"AWS": "*"` is safe here (the trap):** on its own, `"*"` would trust every
principal on Earth. But the `aws:PrincipalOrgID` condition restricts the effective
set to principals in *your* organization only. The exam shows policies like this
and asks "is this dangerous?" — the answer is **no, *because of* the condition**.
Remove the condition and it becomes catastrophic.

**Permission boundary** (`policies/phase-1/1.1b-permission-boundary.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BoundaryAllowReadOnlyAndS3",
      "Effect": "Allow",
      "Action": ["s3:Get*", "s3:List*", "ec2:Describe*", "cloudtrail:LookupEvents"],
      "Resource": "*"
    }
  ]
}
```

**With `AdministratorAccess` *also* attached:** the effective permissions are the
**intersection** of the attached policies and the boundary — so the session can do
only what's in the boundary (read-only + a little S3), *not* everything admin
allows. The boundary is a ceiling, never a grant.

---

## D1.1b — boundary vs attached policy

Launching EC2 from the assumed session is **denied**, because the permission
boundary doesn't allow `ec2:RunInstances` — even though `AdministratorAccess` is
attached and *does* allow it. This proves a boundary is a **ceiling**: an action
must be allowed by **both** an attached policy **and** the boundary to succeed.
The exam tests this intersection relentlessly (often combined with an SCP, which
adds a *third* gate that must also allow the action).

---

## B1.2 — KMS default statement and the lockout policy

**The safe default statement** (`policies/phase-1/1.2-kms-default-statement.json`)
— the one a normal key keeps:

```json
{
  "Sid": "EnableRootAccountPermissions",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_B_ID>:root" },
  "Action": "kms:*",
  "Resource": "*"
}
```

**What `:root` actually means (the trap):** it means **"the account"** — i.e.
"allow IAM policies in account B to govern this key" — **not** "the root user
specifically." This statement is the bridge that lets ordinary IAM
identity-policies have any power over the key at all. Without it, IAM is mute on
this key.

**The deliberately broken policy**
(`policies/phase-1/1.2-kms-lockout-policy.json`):

```json
{
  "Version": "2012-10-17",
  "Id": "deliberate-lockout-demo",
  "Statement": [
    {
      "Sid": "AllowAppRoleToUseKeyForData",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_B_ID>:role/AppEncryptRole" },
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
      "Resource": "*"
    }
  ]
}
```

**Administrative actions now impossible for anyone:** `kms:PutKeyPolicy`,
`kms:ScheduleKeyDeletion`, `kms:EnableKeyRotation`, `kms:CreateGrant`,
`kms:Disable*` — nothing grants `kms:*` or any admin action to any principal. The
key has data users but **no administrators**.

---

## D1.2 — lockout, recovery, and the safe pattern

1. **Rotate / schedule-deletion attempts →** both fail with
   `AccessDeniedException`, *even though your IAM policy grants `kms:*`.* The key
   policy never delegated to IAM (no `:root`/`kms:*` statement), so IAM's "allow"
   is irrelevant. Key policy is the root of trust; IAM only has power the key
   policy hands it.
2. **Recovery channel:** because **no principal in the account** — including the
   **account root user** — can modify the key policy, the only fix is to **open an
   AWS Support case** and ask them to update the key policy / restore the root
   statement. **There is no self-service console button.** This is the single most
   tested KMS-lockout fact: root can't save you, only AWS Support can.
3. **The safe pattern** combines three statements: (a) the
   `EnableRootAccountPermissions` `:root`/`kms:*` statement so IAM can govern the
   key, (b) a scoped **key-administrators** statement (`kms:Create*`, `kms:Put*`,
   `kms:ScheduleKeyDeletion`, `kms:EnableKeyRotation`, etc.) for a dedicated admin
   role, and (c) the **data-users** statement (`Encrypt`/`Decrypt`/
   `GenerateDataKey`/`DescribeKey`) for app roles. With the root statement back,
   `enable-key-rotation` succeeds.

---

## B1.2b — ViaService + encryption-context statement

`policies/phase-1/1.2b-viaservice-context.json` — add to a key policy that still
has the root statement:

```json
{
  "Sid": "AllowS3UseWithContext",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_B_ID>:role/AppEncryptRole" },
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:ViaService": "s3.us-east-1.amazonaws.com",
      "kms:EncryptionContext:project": "scs-lab"
    }
  }
}
```

The two condition keys: **`kms:ViaService`** (the call must be made *through* the
named service endpoint, not directly) and **`kms:EncryptionContext:<key>`** (the
request must carry the named context pair).

---

## D1.2b — Break/Fix answers

1. **Direct `GenerateDataKey` →** denied by `kms:ViaService` (the call didn't come
   through S3).
2. **Via S3, wrong/no context →** denied by `kms:EncryptionContext:project` (the
   required context pair was absent or mismatched).
3. **Via S3 with `project=scs-lab` →** succeeds; both conditions are satisfied.

**Three condition keys this trains:** `kms:ViaService` (gates on the calling
service), `kms:EncryptionContext:<key>` (gates on the AAD/context pair, which is
also cryptographically bound to the ciphertext), and `kms:CallerAccount` (gates on
which account the caller belongs to — useful for shared/cross-account keys).

---

## Answer-cold

- **C1.1** Because authorization for a cross-account assume requires the **trust
  policy** in the target account to also allow it. `sts:AssumeRole` on the
  identity side is necessary but not sufficient — if the trust policy's
  `Principal` doesn't match or a `Condition` (MFA, IP, ExternalId, OrgID) fails,
  the assume is denied.
- **C1.2** The **trust policy** (`AssumeRolePolicyDocument`) says *who may assume
  the role and under what conditions*; the **permissions policy** says *what the
  resulting session is allowed to do*. Different documents, different evaluation
  stages, both required.
- **C1.3** **Only AWS Support.** No principal in the account — not even the root
  user — can modify a key policy that grants them nothing; you must file a Support
  case.
- **C1.4** "The **account**" — it delegates control of the key to the account's
  IAM policies. It does **not** mean the root user specifically; it's what lets
  IAM identity-based policies govern the key at all.
- **C1.5** **`aws:PrincipalOrgID`** restricts a policy to principals in your
  organization (lets you safely use `"AWS":"*"`). A **permission boundary** caps a
  principal's max permissions to the *intersection* with its attached policies.
  **`kms:ViaService`** restricts key use to calls routed through a named service.
  **Encryption context** restricts key use to requests carrying specific AAD pairs
  (and binds them to the ciphertext). Each is a *narrowing* condition, never a
  grant on its own.
