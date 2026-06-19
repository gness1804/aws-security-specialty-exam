# Cost & Safety Guardrails — read before launching anything

A personal sandbox can surprise-bill you if a lab leaves a NAT gateway, an ALB, a
GuardDuty detector, or a Config recorder running. This file sets up the guardrails
once and gives you a teardown checklist to run at the end of every session.

The two rules:

1. **Set the budget alarm before you create your first billable resource.**
2. **Run the teardown checklist at the end of every lab session.** Don't let
   resources idle between sessions.

---

## 1. Billing visibility (one-time, management account)

1. Sign in to the **management account** as an IAM user (not root).
2. Enable IAM access to billing: root menu -> Account -> "IAM user and role access
   to Billing Information" -> activate.
3. Billing console -> **Budgets** -> create a monthly cost budget. Suggested: a
   hard ceiling you're comfortable with (e.g., $20/month), with alerts at 50%,
   80%, and 100% of forecasted spend, emailed to you.
4. Billing console -> **Cost Explorer** -> enable it. Check it at the start of
   each session — a creeping daily cost is your early-warning that a lab left
   something running.

### Budget via CLI (paste-friendly)

Set your account ID and email, then create a $20/month budget with an 80% alert.
This writes no secrets to output.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile scs-mgmt)
cat > /tmp/budget.json <<JSON
{ "BudgetName": "scs-sandbox-monthly", "BudgetLimit": { "Amount": "20", "Unit": "USD" },
  "TimeUnit": "MONTHLY", "BudgetType": "COST" }
JSON
cat > /tmp/notify.json <<JSON
[ { "Notification": { "NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80, "ThresholdType": "PERCENTAGE" },
    "Subscribers": [ { "SubscriptionType": "EMAIL", "Address": "you@example.com" } ] } ]
JSON
aws budgets create-budget --account-id "$ACCOUNT_ID" \
  --budget file:///tmp/budget.json \
  --notifications-with-subscribers file:///tmp/notify.json --profile scs-mgmt
```

> Replace `you@example.com` before running. A budget itself is free.

---

## 2. The usual cost offenders in this course

Watch these specifically — they bill by the hour or by the GB whether or not you're using them:

| Resource | Appears in | Cost note | Teardown |
|----------|-----------|-----------|----------|
| **NAT Gateway** | any VPC lab with private subnets | ~$0.045/hr + data | Delete the NAT GW, release the EIP |
| **Application Load Balancer** | Phase 6 WAF, Phase 3 ACM | ~$0.0225/hr + LCU | Delete the ALB |
| **GuardDuty** | Phase 4 | 30-day free trial, then per-event | Disable the detector when done |
| **Config recorder** | Phase 4, 7 | per configuration item recorded | Stop the recorder, delete delivery channel |
| **Macie** | Phase 3 | per-GB classified; sample-data jobs are cheap | Disable Macie |
| **Detective** | Phase 4 stretch | 30-day trial, then per-GB ingested | Disable the graph |
| **Inspector** | Phase 4 | per-instance / per-image scanned | Disable Inspector |
| **KMS CMK** | Phase 1, 3 | $1/month per key + per-request | Schedule key deletion (7–30 day window) |
| **Secrets Manager secret** | Phase 3 | $0.40/secret/month + per-10k API calls | Delete the secret (force, no recovery window) |
| **VPC Flow Logs / CloudTrail to S3** | Phase 6 | S3 storage + data scanned by Athena | Delete log objects when done; lifecycle-expire |

> **GuardDuty, Config, Macie, Inspector, Detective, Security Hub** all keep
> billing after a lab ends because they run continuously. The teardown checklist
> below disables them. Turn them on at the start of the lab, off at the end —
> unless you're mid-multi-day lab.

---

## 3. End-of-session teardown checklist

Run this at the end of **every** session. Each phase's lab guide also ends with a
phase-specific teardown; this is the cross-cutting sweep.

- [ ] Terminate any EC2 instances you launched.
- [ ] Delete any ALBs and their target groups.
- [ ] Delete NAT gateways and release their Elastic IPs.
- [ ] Disable continuous-billing detectors you turned on: GuardDuty, Config
      recorder, Macie, Inspector, Detective, Security Hub.
- [ ] Schedule deletion of KMS CMKs you no longer need (min 7-day window).
- [ ] Delete Secrets Manager secrets you no longer need.
- [ ] Empty + delete throwaway S3 buckets (mind Object Lock in Phase 6 — those
      are deliberately undeletable for a retention window).
- [ ] Check Cost Explorer for anything still accruing.

### Teardown helper script

`scripts/teardown_check.py` (added in Phase 1) audits your account for the
offenders above and prints what is still running — **never secrets, only resource
IDs and types** — with a `--dry-run` default. It only deletes when you pass
`--apply`, and it asks for confirmation per resource class.

---

## 4. Safety rules these scripts follow (so you can trust them)

- **No secrets to stdout/stderr/logs.** Scripts never print KMS key material,
  secret values, session tokens, or access keys. They print resource IDs and
  ARNs only.
- **Destructive = dry-run by default.** Anything that deletes or modifies
  defaults to `--dry-run`. You must pass `--apply` to act.
- **Least privilege.** Scripts use named CLI profiles, never embedded
  credentials. Set `AWS_PROFILE` or pass `--profile`.
- **Confirm before irreversible.** Key deletion, secret deletion, and policy
  replacement prompt for confirmation unless `--yes` is passed.

If a lab ever asks you to paste real credentials into a file, that's a mistake —
stop and use a named profile instead.
