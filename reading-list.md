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
- **AWS Security Reference Architecture (SRA)** — the canonical "where does each
  security service live in a multi-account org" diagram set. You'll return to this
  in Phases 4, 6, and 7. Skim now (~45 min), revisit per phase.
- **IAM JSON policy reference** — keep open while writing policies. Reference, not reading.

---

## Per-phase assigned reading

### Phase 1 — IAM & KMS (Weeks 1–2)
- **IAM policy evaluation logic** (docs): explicit deny > allow > implicit deny,
  and how SCP/permission-boundary/identity/resource policies intersect. ~45 min.
  This single mental model answers a large share of Domain 4 questions.
- **KMS key policies vs. IAM policies** (KMS Developer Guide, "Key policies"
  section) + **"Default key policy"** + **grants**. ~45 min. The lockout lab makes
  this concrete; the reading names the recovery path.
- _Stretch:_ **KMS encryption context & `kms:ViaService`** condition keys. ~20 min.

### Phase 3 — Data protection (Week 3)
- **Secrets Manager rotation** (User Guide, "Rotating secrets" + the four-step
  Lambda rotation contract: createSecret/setSecret/testSecret/finishSecret). ~40 min.
- **Data protection whitepaper** sections on encryption at rest vs in transit,
  envelope encryption, and S3 encryption options (SSE-S3 / SSE-KMS / DSSE-KMS / bucket keys). ~40 min.
- **ACM** (User Guide): cert issuance, validation, and where ACM certs can and
  cannot be attached (ALB/CloudFront/API GW yes; EC2 directly no). ~20 min.

### Phase 4 — Detection & remediation (Weeks 4–5)
- **AWS Config** (Developer Guide): managed vs custom rules, the
  configuration-item/recorder/delivery-channel model, and remediation actions
  (SSM Automation). ~45 min.
- **GuardDuty finding types** (User Guide): finding format, severity, and the
  common types (recon, crypto-mining, credential exfiltration, SSH brute force). ~30 min.
- **Security Hub** (User Guide): standards (FSBP, CIS, PCI), the finding
  aggregation model, and how Config/GuardDuty/Inspector findings flow in. ~30 min.
- _Stretch:_ **Detective** behavior graph concepts. ~15 min.

### Phase 6 — Perimeter & logging (Week 6)
- **AWS WAF** (Developer Guide): managed rule groups, rate-based rules, and
  string/SQLi/XSS match statements. ~30 min.
- **CloudTrail** (User Guide): org trails, log file integrity validation (digest
  files), data events vs management events, and CloudTrail Lake vs Athena. ~40 min.
- **Logging & monitoring whitepaper / SRA log-archive account pattern.** ~30 min.

### Phase 7 — Governance (Week 7)
- **Service Control Policies** (Organizations User Guide): SCPs are guardrails not
  grants; deny-list vs allow-list strategy; common SCP patterns (region lock,
  protect CloudTrail/GuardDuty, require MFA, deny root). ~45 min.
- **Config aggregators + conformance packs** (Developer Guide). ~20 min.

### Phase 8 — Exam mindset (Week 8)
- Re-skim the **Exam Guide** task statements. ~20 min.
- Re-skim your own notes from every Break/Fix drill. ~as needed.

---

## How this maps to the exam

If you complete every lab and the reading above, you will have touched, with your
own hands, the services behind essentially every SCS-C03 task statement. The
reading exists to give names and edge-cases to what you already built — that
combination (built it + can name the failure mode) is what passing the Specialty
exam actually requires.
