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

## How this lab works (read once)

This is an **active-recall** course. The Build and Break/Fix sections pose a task
or a question and then **stop** — they do not hand you the policy JSON or the
explanation. Try to produce the answer yourself first; that struggle is the part
that sticks. When you're done (or genuinely stuck), check your work against:

- **`answers/phase-1-answers.md`** — the reference policies, explanations, and
  drill answers, keyed to the IDs you'll see below (e.g. **B1.1**, **D1.2**).
- **`policies/phase-1/`** — the canonical policy JSON as paste-ready files
  (these are part of the answer key — open them only to check or to apply).
- **`scripts/phase-1/`** — runnable Boto3 tooling to apply and test what you built.

Two sections give you the full steps inline, because they're housekeeping rather
than exam concepts: the **Prerequisite** setup below, and each **Teardown**.

---

## Prerequisite: stand up the two-account Organization

You need this once; Phases 4 and 5 reuse it. This is setup, not a drill — full
steps are given.

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

### Build challenge · B1.1
This is the heart of the scenario — write the two policies yourself before
looking at anything.

1. **In Account A**, create (or reuse) an IAM user named `analyst` with MFA
   enabled.
2. **Write the *identity-based* policy** for `analyst` that lets them call
   `sts:AssumeRole` on a role named `CrossAccountAuditRole` in Account B — and
   *only* that role.
3. **Write the *trust* (resource-based) policy** for `CrossAccountAuditRole` in
   Account B that:
   - trusts the `analyst` user in Account A as principal,
   - requires MFA to be present,
   - requires the request to come from your egress CIDR
     (`curl -s https://checkip.amazonaws.com` gives your current IP),
   - *(stretch within the challenge)* forces re-authentication after one hour.
4. Decide what **permissions policy** to attach to the role so the assumed
   session can actually do auditor work — and articulate why that's a *separate*
   policy from the trust policy.

> Hint (tease, not the crux): two policies live on two different sides. One says
> *who is allowed to ask*; the other says *under what conditions we'll say yes*.
> Only one of them carries the `Condition` block.

When you've drafted both, check them and apply:
- **Reference solution + the "which side carries conditions" explanation:**
  `answers/phase-1-answers.md` → **B1.1**
- **Apply it** with `scripts/phase-1/setup_cross_account_role.py` (dry-run first).

### Verify · V1.1
From an allowed IP, with MFA, attempt the assume:
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_B_ID>:role/CrossAccountAuditRole \
  --role-session-name analyst-test \
  --profile scs-mgmt   # this profile prompts for MFA per the config above
```
Before you run it, predict: what should come back, and what should you make sure
the output does **not** contain? (`scripts/phase-1/assume_role_test.py` performs
this and prints only the assumed-role ARN and expiry — never the secret values.)
→ what "success" looks like: `answers/phase-1-answers.md` → **V1.1**

### Break it / Fix it · D1.1
For each break below, **predict the outcome and name the exact policy element
responsible** before you test. Then revert and re-test so you attribute cause to
effect one variable at a time.

1. **Break MFA:** assume the role from a session that has *no* MFA. What happens,
   and which condition fired?
2. **Break the IP:** change the trust-policy CIDR to a block you're *not* in
   (e.g. `198.51.100.0/24`) and re-attempt. What happens?
3. **Break the principal:** change the trust `Principal` to a different user ARN.
   Is `analyst` denied even *with* correct MFA and IP? Why does that prove the
   principal element is evaluated independently of the conditions?
4. **Conceptual:** if the trust policy had allowed the whole account
   (`"AWS": "arn:aws:iam::<ACCOUNT_A_ID>:root"`) instead of the specific user,
   what *else* would `analyst` need in order to assume the role?

→ Answers and the error strings the exam paraphrases: `answers/phase-1-answers.md`
→ **D1.1**

---

## Scenario 1.1b — Add `aws:PrincipalOrgID` + a permission boundary  ·  **Stretch**

### Goal
Harden 1.1 two ways the exam favors: (a) trust *any* principal in your
Organization without enumerating account IDs, and (b) cap the assumed role's
maximum permissions with a **permission boundary**, so even an over-broad attached
policy can't exceed the boundary.

### Build challenge · B1.1b
1. **Rewrite the trust policy** so it trusts any principal in your Organization
   (no hard-coded account IDs) while still requiring MFA. You'll need one
   condition key for the org scope and a principal value that *looks* dangerous
   but isn't — figure out why it's safe.
2. **Write a permission-boundary managed policy** that caps the role at read-only
   plus a little S3, and attach it. Then predict: if you also attach
   `AdministratorAccess` to the role, what can the assumed session actually do?

> Hint: the boundary is not a grant. Effective permissions are an *intersection*.

→ Reference policies + the "why `"AWS": "*"` is safe here" trap explained:
`answers/phase-1-answers.md` → **B1.1b**
(`policies/phase-1/1.1b-trust-with-orgid.json`, `1.1b-permission-boundary.json`)

### Break it / Fix it · D1.1b
Attach `AdministratorAccess` to the role *and* the boundary above. From the
assumed session, try to launch an EC2 instance. **What happens, and why?** What
does that prove about how boundaries relate to attached policies?

→ Answer: `answers/phase-1-answers.md` → **D1.1b**

---

## Scenario 1.2 — KMS CMK deliberate lockout + emergency recovery  ·  **Core**

### Goal
Create a symmetric KMS key, then write a key policy that grants access to an
application role **but removes the default statement that lets account
administrators manage the key.** Experience the lockout, then reason out AWS's
documented recovery path.

### Why the exam cares
The KMS key policy is the *root* of trust for a key — IAM policies only work if
the key policy delegates to IAM (via the `"Principal": {"AWS": "...:root"}` +
`kms:*` default statement). Remove that, and IAM is powerless over the key. The
exam tests whether you understand: (1) key policy vs IAM policy precedence, (2)
that a key with no admin access is *not* permanently bricked, and (3) the exact
recovery channel.

### Build challenge · B1.2
1. **Write the "safe" default key statement** — the one a normal key keeps that
   lets IAM policies in the account govern the key. What principal does it name,
   and what does that principal value *actually* mean? (It is a classic trap.)
2. **Now write a deliberately broken key policy:** grant an app role only
   `Encrypt`/`Decrypt`/`GenerateDataKey`/`DescribeKey`, and **omit the default
   statement entirely.** List which administrative actions *no one* can now
   perform on this key.

> Safety: build this with `scripts/phase-1/kms_lockout_demo.py`, which by default
> keeps a recovery-admin principal you control and only fully strips it when you
> pass `--full-lockout`. Use `--full-lockout` only if you accept letting that key
> sit (~$1/month) until you escalate or abandon it.

→ Reference policies + what `:root` really means: `answers/phase-1-answers.md`
→ **B1.2** (`policies/phase-1/1.2-kms-default-statement.json`,
`1.2-kms-lockout-policy.json`)

### Break it / Fix it · D1.2
1. As an Account B admin (with `kms:*` in your IAM policy), try to administer the
   locked-out key:
   ```bash
   aws kms enable-key-rotation --key-id <KEY_ID> --profile scs-member
   aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7 --profile scs-member
   ```
   Predict the result first. IAM says you may; what does the key say, and who
   wins?
2. **The recovery question (know this cold):** no principal in the account can
   modify this key's policy. Who *can* fix it, and through what channel? Is there
   a self-service console button? Could the account root user fix it?
3. **The safe pattern:** describe the key policy you'd actually ship — what
   statements does it combine so the key has data users *and* administrators
   *and* still delegates to IAM? Rebuild it and confirm you can rotate the key.

→ Answers (including the exact recovery channel): `answers/phase-1-answers.md`
→ **D1.2**

---

## Scenario 1.2b — Multi-condition key grant (ViaService + encryption context)  ·  **Stretch**

### Goal
Grant a role the ability to use the key **only when the call comes through a
specific service** (e.g. S3) **and** carries a specific **encryption context** —
the KMS equivalent of fine-grained, conditional access.

### Build challenge · B1.2b
Starting from a *safe* key policy (one that still has the root statement), add a
statement that lets `AppEncryptRole` use the key for data operations **only when
both** of these hold: the call is made *via S3* in your region, and it carries an
encryption context pair `project = scs-lab`. Write the `Condition` block yourself
— which two condition keys do you need?

→ Reference statement: `answers/phase-1-answers.md` → **B1.2b**
(`policies/phase-1/1.2b-viaservice-context.json`)

### Break it / Fix it · D1.2b
Predict each result, then test:
1. Call `kms:GenerateDataKey` **directly** (not via S3). Allowed or denied? By what?
2. Call it **via S3 but with the wrong / no encryption context**. Result?
3. Call it **via S3 with `project=scs-lab`** in the context. Result?

Which three KMS condition keys does this drill train, and what does each gate on?

→ Answers: `answers/phase-1-answers.md` → **D1.2b**

---

## Phase 1 teardown

Full steps given — this is housekeeping, not a drill.

- [ ] Detach/delete the `analyst` test policies and the `CrossAccountAuditRole`
      (and `AppEncryptRole`) once you've finished the drills.
- [ ] **KMS:** schedule deletion of any demo keys you can still administer
      (`aws kms schedule-key-deletion --pending-window-in-days 7`). If you used
      `--full-lockout`, note the key ID and let it sit — at ~$1/month it's cheap;
      delete it after escalation practice or abandon it.
- [ ] Run `python scripts/phase-1/teardown_check.py --profile scs-member` to
      confirm no unexpected billable resources remain.

## What you should now be able to answer cold

These are pure self-test — no answers beside them. If any is shaky, redo the
matching drill. Worked answers live in `answers/phase-1-answers.md` → **Answer-cold**.

- **C1.1** Why does a principal *with* `sts:AssumeRole` permission still get denied?
- **C1.2** What's the difference between a trust policy and a permissions policy on a role?
- **C1.3** A KMS key has no statement granting `kms:*` to the account root. Who can fix the key policy?
- **C1.4** What does `"Principal": {"AWS": "...:root"}` in a key policy actually mean?
- **C1.5** How do `aws:PrincipalOrgID`, permission boundaries, `kms:ViaService`, and encryption context each narrow access?

When you can answer those without notes, you're ready for **Phase 2**.
