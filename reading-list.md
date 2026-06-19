# Reading list — the disciplined 20%

The rule: **read after the lab, not before.** Once you've felt a service break,
the documentation snaps into focus and you retain far more. Each item is
time-boxed. If a reading runs long, skim to the boxed callouts and the IAM/policy
examples — those are what the exam tests.

Total reading load across the course is roughly 14–18 hours, which keeps you near
the 80/20 hands-on split.

---

## Standing references (bookmark, don't read cover-to-cover)

- **AWS SCS-C03 Exam Guide (PDF)** — the official domain/task breakdown. Read once,
  now, to internalize the six domains and their weights. ~30 min.
  <https://d1.awsstatic.com/training-and-certification/docs-security-spec/AWS-Certified-Security-Specialty_Exam-Guide.pdf>
- **AWS Security Reference Architecture (SRA)** — the canonical "where does each
  security service live in a multi-account org" diagram set. You'll return to this
  in Phases 3, 4, and 5. Skim now (~45 min), revisit per phase.
  <https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html>
- **IAM JSON policy reference** — keep open while writing policies. Reference, not reading.
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html>

---

## Per-phase assigned reading

### Phase 1 — IAM & KMS (Weeks 1–2)
- **IAM policy evaluation logic** (docs): explicit deny > allow > implicit deny,
  and how SCP/permission-boundary/identity/resource policies intersect. ~45 min.
  This single mental model answers a large share of Domain 4 questions.
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>
- **KMS key policies vs. IAM policies** + **default key policy** + **grants**. ~45 min.
  The lockout lab makes this concrete; the reading names the recovery path.
  <https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html> ·
  <https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html> ·
  <https://docs.aws.amazon.com/kms/latest/developerguide/grants.html>
- _Stretch:_ **KMS encryption context & `kms:ViaService`** condition keys. ~20 min.
  <https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html>

### Phase 2 — Data protection (Week 3)
- **Secrets Manager rotation** ("Rotate secrets" + the four-step Lambda rotation
  contract: createSecret/setSecret/testSecret/finishSecret). ~40 min.
  <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html> ·
  <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-overview.html>
- **S3 encryption options** (SSE-S3 / SSE-KMS / DSSE-KMS) + **bucket keys**, and
  encryption at rest vs in transit / envelope encryption. ~40 min.
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html> ·
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html>
- **ACM**: cert issuance, validation, and where ACM certs can and cannot be
  attached (ALB/CloudFront/API GW yes; EC2 directly no). ~20 min.
  <https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html> ·
  <https://docs.aws.amazon.com/acm/latest/userguide/acm-services.html>

### Phase 3 — Detection & remediation (Weeks 4–5)
- **AWS Config**: managed vs custom rules, the configuration-item/recorder/
  delivery-channel model, and remediation actions (SSM Automation). ~45 min.
  <https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html> ·
  <https://docs.aws.amazon.com/config/latest/developerguide/remediation.html>
- **GuardDuty finding types**: finding format, severity, and the common types
  (recon, crypto-mining, credential exfiltration, SSH brute force). ~30 min.
  <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html>
- **Security Hub**: standards (FSBP, CIS, PCI), the finding aggregation model, and
  how Config/GuardDuty/Inspector findings flow in. ~30 min.
  <https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html>
- _Stretch:_ **Detective** behavior-graph concepts. ~15 min.
  <https://docs.aws.amazon.com/detective/latest/userguide/what-is-detective.html>

### Phase 4 — Perimeter & logging (Week 6)
- **AWS WAF**: managed rule groups, rate-based rules, and string/SQLi/XSS match
  statements. ~30 min.
  <https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html>
- **CloudTrail**: org trails, log-file integrity validation (digest files), data
  vs management events, CloudTrail Lake vs Athena. ~40 min.
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html> ·
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html>
- **SRA log-archive account pattern** (centralized logging). ~30 min.
  <https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/log-archive.html>

### Phase 5 — Governance (Week 7)
- **Service Control Policies**: SCPs are guardrails not grants; deny-list vs
  allow-list strategy; common patterns (region lock, protect CloudTrail/GuardDuty,
  require MFA, deny root). ~45 min.
  <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html>
- **Config aggregators + conformance packs**. ~20 min.
  <https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html> ·
  <https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html>

### Phase 6 — Exam mindset (Week 8)
- Re-skim the **Exam Guide** task statements. ~20 min.
  <https://d1.awsstatic.com/training-and-certification/docs-security-spec/AWS-Certified-Security-Specialty_Exam-Guide.pdf>
- Re-skim your own notes from every Break/Fix drill. ~as needed.

---

## How this maps to the exam

If you complete every lab and the reading above, you will have touched, with your
own hands, the services behind essentially every SCS-C03 task statement. The
reading exists to give names and edge-cases to what you already built — that
combination (built it + can name the failure mode) is what passing the Specialty
exam actually requires.
