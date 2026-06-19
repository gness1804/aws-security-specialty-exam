# Phase 1 — Preventative architecture: IAM & KMS (Weeks 1–2)

**Domains trained:** Domain 4 (Identity & Access Management, 16%) and Domain 5
(Data Protection, 18%) — together ~34% of the exam.

**The mindset shift:** stop thinking "how do I grant access" and start thinking
"how do I prove that *only* the intended principal, under the intended
conditions, can reach this resource — and how would an attacker who got partway
in be stopped." Phase 1 builds two architectures that the exam returns to again
and again: conditional cross-account delegation, and the KMS key-policy /
IAM-policy interaction (including the famous self-lockout).

By the end of Phase 1 you should be able to read any cross-account `AssumeRole`
failure or KMS `AccessDeniedException` and name the exact statement responsible.

---

## Prerequisite: stand up the two-account Organization

You need this once; Phases 6 and 7 reuse it.

1. In your **management account** (signed in as an IAM user with MFA, not root),
   open **AWS Organizations** -> **Create an organization** (keep all features
   enabled — SCPs require "all features").
2. **Add a member account**: Organizations -> Add account -> Create an account.
   Give it a name like `scs-member` and a unique email (a `+alias` on your
   address works: `you+scsmember@example.com`). AWS creates it with an
   `OrganizationAccountAccessRole` you can assume from management.
3. Note both account IDs. Throughout these labs:
   - **Account A** = `scs-mgmt` (where your human user lives — the "trusted" side).
   - **Account B** = `scs-member` (where the protected role/resources live).
4. Configure CLI profiles (no long-lived keys in Account B — assume into it):
   ```bash
   aws configure --profile scs-mgmt        # IAM user in A, MFA enabled
   # Profile that assumes OrganizationAccountAccessRole into B:
   cat >> ~/.aws/config <<'CFG'
   [profile scs-member]
   role_arn = arn:aws:iam::<ACCOUNT_B_ID>:role/OrganizationAccountAccessRole
   source_profile = scs-mgmt
   mfa_serial = arn:aws:iam::<ACCOUNT_A_ID>:mfa/<your-user-name>
   CFG
   ```
   Replace the two account IDs and your user name. The `mfa_serial` line makes the
   CLI prompt for an MFA token — exactly the behavior the exam tests.

> **Reading after this step:** IAM policy evaluation logic (see `reading-list.md`).

---

## Scenario 1.1 — Cross-account role: MFA + IP-restricted AssumeRole  ·  **Core**

### Goal
Create a role in **Account B** that a specific user in **Account A** can assume
**only if** (a) they authenticated with MFA and (b) their request originates from
an allowed IP CIDR block. Anyone else — including other principals in Account A —
must be denied.

### Why the exam cares
Cross-account delegation with `sts:AssumeRole` plus trust-policy `Condition`
blocks (`aws:MultiFactorAuthPresent`, `aws:SourceIp`, `sts:ExternalId`,
`aws:PrincipalOrgID`) is one of the most heavily tested IAM patterns. The exam
loves to show you a trust policy and ask why a principal can or can't assume the
role, or which condition to add to satisfy a stated requirement.

### Build it

1. **In Account A**, create an IAM user (or reuse one) named `analyst`. Ensure
   MFA is enabled on it.
2. **In Account A**, attach a policy to `analyst` allowing it to assume the
   Account B role (the *identity* side of the permission):

   `policies/1.1-account-a-assume-permission.json`:
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

3. **In Account B**, create the role `CrossAccountAuditRole` with this **trust
   policy** (the *resource* side — where the conditions live):

   `policies/1.1-account-b-trust-policy.json`:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "TrustAccountAAnalystWithMFAandIP",
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::<ACCOUNT_A_ID>:user/analyst"
         },
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
   Replace the CIDR with your actual egress IP block (find it: `curl -s https://checkip.amazonaws.com`).
   `aws:MultiFactorAuthAge` (optional but exam-relevant) forces re-auth after an hour.

4. Attach a **permissions policy** to the role granting only what an auditor
   needs (e.g., `SecurityAudit` AWS-managed policy, or read-only). The trust
   policy says *who* may assume; the permissions policy says *what they can do*
   once assumed — the exam tests that you know these are two different things.

### Verify
```bash
# From an allowed IP, with MFA: should succeed and return temporary creds
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_B_ID>:role/CrossAccountAuditRole \
  --role-session-name analyst-test \
  --profile scs-mgmt   # this profile prompts for MFA per the config above
```
The call returns temporary credentials (the script in `scripts/phase-1/` captures
them into a session **without printing the secret values** — only the assumed-role
ARN and expiry).

### Break it / Fix it
1. **Break MFA:** assume the role using a profile/session that has *no* MFA.
   Observe `AccessDenied` — the `Bool aws:MultiFactorAuthPresent` condition
   fired. Read the error; this is the exact string the exam paraphrases.
2. **Break the IP:** temporarily change the CIDR in the trust policy to a block
   you're *not* in (e.g., `198.51.100.0/24`). Re-attempt. Observe denial.
3. **Break the principal:** change the trust `Principal` to a different user ARN.
   Confirm `analyst` is now denied even *with* MFA and correct IP — proving the
   principal element is evaluated independently of the conditions.
4. **Fix** each by reverting, re-testing after each change so you can attribute
   cause to effect.

> Drill question to ask yourself: if the trust policy allowed the whole account
> (`"AWS": "arn:aws:iam::<ACCOUNT_A_ID>:root"`) instead of the specific user,
> what *else* would `analyst` need to assume the role? (Answer: an identity-based
> `sts:AssumeRole` permission in A — which is why both sides exist.)

---

## Scenario 1.1b — Add `aws:PrincipalOrgID` + a permission boundary  ·  **Stretch**

### Goal
Harden 1.1 two ways the exam favors: (a) trust *any* principal in your
Organization without enumerating account IDs, and (b) cap the assumed role's
maximum permissions with a **permission boundary**, so even an over-broad attached
policy can't exceed the boundary.

### Build it
1. Replace the trust `Principal`/`Condition` with an org-scoped condition:

   `policies/1.1b-trust-with-orgid.json`:
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
   `"AWS": "*"` looks alarming but is safe here — the `aws:PrincipalOrgID`
   condition restricts it to your org. This is a classic exam "is this policy
   dangerous?" trap: the answer is no, *because of* the condition.

2. Create a **permission boundary** managed policy and attach it to the role.
   Even if the role's permissions policy is `AdministratorAccess`, the effective
   permissions are the *intersection* with the boundary:

   `policies/1.1b-permission-boundary.json`:
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

### Break it / Fix it
Attach `AdministratorAccess` to the role *and* the boundary above. Try to launch
an EC2 instance from the assumed session — it's denied, because the boundary
doesn't allow `ec2:RunInstances`. This proves the boundary is a ceiling, not a
grant. The exam tests this intersection relentlessly.

---

## Scenario 1.2 — KMS CMK deliberate lockout + emergency recovery  ·  **Core**

### Goal
Create a symmetric KMS key, then write a key policy that grants access to an
application role **but removes the default statement that lets account
administrators manage the key.** Experience the lockout, then execute AWS's
documented recovery path.

### Why the exam cares
The KMS key policy is the *root* of trust for a key — IAM policies only work if
the key policy delegates to IAM (via the `"Principal": {"AWS": "...:root"}` +
`kms:*` default statement). Remove that, and IAM is powerless over the key. The
exam tests whether you understand: (1) key policy vs IAM policy precedence, (2)
that a key with no admin access is *not* permanently bricked, and (3) the exact
recovery channel (AWS Support, because no principal in your account can fix it).

### Build it

1. Create a symmetric encryption key (we'll do this via the script so we can
   control the policy precisely). The **safe** default key policy includes:

   `policies/1.2-kms-default-statement.json` (the statement you'd normally keep):
   ```json
   {
     "Sid": "EnableRootAccountPermissions",
     "Effect": "Allow",
     "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_B_ID>:root" },
     "Action": "kms:*",
     "Resource": "*"
   }
   ```
   This statement is what lets IAM policies in the account govern the key. The
   `:root` principal here means "the account," not the root user specifically —
   another exam trap.

2. Now build the **deliberately broken** key policy: grant the app role data
   permissions, grant a separate admin role *nothing*, and **omit** the root
   statement entirely:

   `policies/1.2-kms-lockout-policy.json`:
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
   Notice: no statement grants `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`,
   `kms:EnableKeyRotation`, or `kms:*` to anyone. The key now has data users but
   **no administrators**.

### Break it / Fix it (the whole point)
1. As an Account B admin, try to rotate or schedule deletion:
   ```bash
   aws kms enable-key-rotation --key-id <KEY_ID> --profile scs-member
   aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7 --profile scs-member
   ```
   Both fail with `AccessDeniedException` — *even though you are an account
   administrator with `kms:*` in your IAM policy.* This is the lockout. Sit with
   it: IAM said yes, the key policy didn't delegate to IAM, so the answer is no.
2. **Recovery path (know this cold):** because no principal in the account can
   modify the key policy, the only fix is to **open an AWS Support case** asking
   them to update the key policy / add back the root statement. There is no
   self-service console button. (You won't actually file a case in the lab —
   instead, *prevent* the lockout by always keeping the root statement, and
   recover your demo key by simply leaving it to expire or, if you kept admin on
   a second principal, restoring the policy.)
3. **The safe pattern** the exam wants you to choose: keep the
   `EnableRootAccountPermissions` statement, and *additionally* scope a dedicated
   key-admin role and data-user roles. Rebuild the key policy combining the
   default root statement + admin statement + the data statement, and confirm you
   can now rotate it.

> **To avoid a real lockout in your sandbox:** the provided script
> `kms_lockout_demo.py` defaults to creating the key *with* a recovery admin
> principal you control, and only strips it when you pass `--full-lockout`. Use
> `--full-lockout` only if you're comfortable letting that key sit until you
> escalate or abandon it.

---

## Scenario 1.2b — Multi-condition key grant (ViaService + encryption context)  ·  **Stretch**

### Goal
Grant a role the ability to use the key **only when the call comes through a
specific service** (e.g., S3) **and** carries a specific **encryption context** —
the KMS equivalent of fine-grained, conditional access.

### Build it
Add this statement to a *safe* key policy (one that still has the root statement):

`policies/1.2b-viaservice-context.json`:
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

### Break it / Fix it
1. Call `kms:GenerateDataKey` *directly* (not via S3) — denied by `kms:ViaService`.
2. Call it via S3 but with the wrong/no encryption context — denied by the
   `kms:EncryptionContext:project` condition.
3. Call it via S3 with `project=scs-lab` in the context — succeeds.
This trains the exam's favorite KMS condition keys: `kms:ViaService`,
`kms:EncryptionContext:<key>`, and `kms:CallerAccount`.

---

## Phase 1 teardown

- [ ] Detach/delete the `analyst` test policies and the `CrossAccountAuditRole`
      (and `AppEncryptRole`) once you've finished the drills.
- [ ] **KMS:** schedule deletion of any demo keys you can still administer
      (`aws kms schedule-key-deletion --pending-window-in-days 7`). If you used
      `--full-lockout`, note the key ID and let it sit — at $1/month it's cheap;
      delete it after escalation practice or abandon it.
- [ ] Run `python scripts/phase-1/teardown_check.py --profile scs-member` to
      confirm no unexpected billable resources remain.

## What you should now be able to answer cold
- Why does a principal with `sts:AssumeRole` permission still get denied? (Trust
  policy conditions / principal mismatch.)
- What's the difference between a trust policy and a permissions policy on a role?
- A KMS key has no statement granting `kms:*` to the account root. Who can fix
  the key policy? (Only AWS Support.)
- What does `"Principal": {"AWS": "...:root"}` in a key policy actually mean?
- How do `aws:PrincipalOrgID`, permission boundaries, `kms:ViaService`, and
  encryption context each narrow access?

When you can answer those without notes, you're ready for Phase 3.
