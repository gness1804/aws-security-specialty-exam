#!/usr/bin/env python3
"""CloudTrail -> CW Logs -> metric filters -> alarms -> SNS (scenario 4.5, Stretch).

Wires the lab trail to a CloudWatch Logs group (creating the CloudWatch Logs role
CloudTrail needs), then creates two CIS-style metric filters (root-account usage and
IAM policy changes), a CloudWatch alarm on each (threshold >= 1), and an SNS topic
the alarms notify. Filter patterns mirror policies/phase-4/4.5-metric-filter-patterns.json.

Creating actions are gated behind --apply (default: dry run). --teardown removes the
alarms, filters, log group, role, and topic (it does NOT delete the trail). Pass
--notify-email to subscribe an address (you must confirm the SNS email). No secrets
are handled or printed -- names and ARNs only; the email is passed to SNS, not echoed.

Usage:
  python setup_cw_metric_alarms.py --profile scs-member                       # dry run
  python setup_cw_metric_alarms.py --profile scs-member --apply --notify-email you@example.com
  python setup_cw_metric_alarms.py --profile scs-member --teardown --apply
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

TRAIL_NAME = "scs-phase4-trail"
LOG_GROUP = "/scs/phase4/cloudtrail"
CT_LOGS_ROLE = "scs-phase4-ct-cwlogs-role"
CT_LOGS_POLICY = "ct-to-cwlogs"
TOPIC_NAME = "scs-phase4-security-alarms"
NAMESPACE = "SecurityMetrics"

# CIS-style root-usage pattern (adjacent string literals concatenate).
ROOT_USAGE_PATTERN = (
    '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS '
    '&& $.eventType != "AwsServiceEvent" }'
)
# IAM policy create/attach/detach/delete/put events -> one OR'd filter pattern.
_IAM_EVENTS = [
    "DeleteGroupPolicy",
    "DeleteRolePolicy",
    "DeleteUserPolicy",
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "CreatePolicy",
    "DeletePolicy",
    "CreatePolicyVersion",
    "DeletePolicyVersion",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
]
IAM_CHANGE_PATTERN = "{ " + " || ".join(f"($.eventName = {e})" for e in _IAM_EVENTS) + " }"

FILTERS = [
    {
        "name": "scs-RootAccountUsage",
        "metric": "RootAccountUsageCount",
        "pattern": ROOT_USAGE_PATTERN,
        "alarm": "scs-RootAccountUsageAlarm",
    },
    {
        "name": "scs-IAMPolicyChanges",
        "metric": "IAMPolicyChangeCount",
        "pattern": IAM_CHANGE_PATTERN,
        "alarm": "scs-IAMPolicyChangeAlarm",
    },
]

CT_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _ct_logs_policy(region: str, account: str) -> dict:
    arn = f"arn:aws:logs:{region}:{account}:log-group:{LOG_GROUP}:*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailCreateLogStreamAndPut",
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": arn,
            }
        ],
    }


def build(session: boto3.Session, region: str, account: str, email: str | None, apply: bool) -> int:
    print("Plan:")
    for s in (
        f"create log group {LOG_GROUP}",
        f"create CloudWatch Logs role {CT_LOGS_ROLE} (trusts cloudtrail)",
        f"point trail {TRAIL_NAME} at the log group",
        f"create SNS topic {TOPIC_NAME}" + (f" + subscribe {email}" if email else ""),
        "create 2 metric filters (root usage, IAM changes) + alarms (>= 1)",
    ):
        print("  -", s)
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    logs = session.client("logs")
    iam = session.client("iam")
    ct = session.client("cloudtrail")
    sns = session.client("sns")
    cw = session.client("cloudwatch")
    try:
        try:
            logs.create_log_group(logGroupName=LOG_GROUP)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        lg_arn = f"arn:aws:logs:{region}:{account}:log-group:{LOG_GROUP}:*"

        try:
            role_arn = iam.create_role(
                RoleName=CT_LOGS_ROLE,
                AssumeRolePolicyDocument=json.dumps(CT_TRUST),
                Description="Phase 4: lets CloudTrail write to CloudWatch Logs",
            )["Role"]["Arn"]
        except iam.exceptions.EntityAlreadyExistsException:
            role_arn = iam.get_role(RoleName=CT_LOGS_ROLE)["Role"]["Arn"]
        iam.put_role_policy(
            RoleName=CT_LOGS_ROLE,
            PolicyName=CT_LOGS_POLICY,
            PolicyDocument=json.dumps(_ct_logs_policy(region, account)),
        )
        print("[ok] log group + CloudWatch Logs role ready")

        ct.update_trail(
            Name=TRAIL_NAME, CloudWatchLogsLogGroupArn=lg_arn, CloudWatchLogsRoleArn=role_arn
        )
        print(f"[ok] trail {TRAIL_NAME} now delivers to {LOG_GROUP}")

        topic_arn = sns.create_topic(Name=TOPIC_NAME)["TopicArn"]
        if email:
            sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email)
            print("[ok] SNS topic ready; check your inbox to confirm the subscription")
        else:
            print("[ok] SNS topic ready (no email subscription requested)")

        for f in FILTERS:
            logs.put_metric_filter(
                logGroupName=LOG_GROUP,
                filterName=f["name"],
                filterPattern=f["pattern"],
                metricTransformations=[
                    {
                        "metricName": f["metric"],
                        "metricNamespace": NAMESPACE,
                        "metricValue": "1",
                        "defaultValue": 0,
                    }
                ],
            )
            cw.put_metric_alarm(
                AlarmName=f["alarm"],
                MetricName=f["metric"],
                Namespace=NAMESPACE,
                Statistic="Sum",
                Period=300,
                EvaluationPeriods=1,
                Threshold=1,
                ComparisonOperator="GreaterThanOrEqualToThreshold",
                TreatMissingData="notBreaching",
                AlarmActions=[topic_arn],
                AlarmDescription=f"Phase 4: {f['name']}",
            )
            print(f"[ok] filter + alarm: {f['name']}")
    except ct.exceptions.TrailNotFoundException:
        print(f"[error] trail {TRAIL_NAME} not found. Run setup_org_cloudtrail.py first.")
        return 1
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, apply: bool) -> int:
    print("Plan: delete alarms, metric filters, log group, role, SNS topic (trail kept)")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    logs = session.client("logs")
    iam = session.client("iam")
    cw = session.client("cloudwatch")
    sns = session.client("sns")

    def _safe(fn):
        try:
            fn()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")

    _safe(lambda: cw.delete_alarms(AlarmNames=[f["alarm"] for f in FILTERS]))
    for f in FILTERS:
        _safe(lambda f=f: logs.delete_metric_filter(logGroupName=LOG_GROUP, filterName=f["name"]))
    _safe(lambda: logs.delete_log_group(logGroupName=LOG_GROUP))
    _safe(lambda: iam.delete_role_policy(RoleName=CT_LOGS_ROLE, PolicyName=CT_LOGS_POLICY))
    _safe(lambda: iam.delete_role(RoleName=CT_LOGS_ROLE))
    for t in sns.list_topics().get("Topics", []):
        if t["TopicArn"].endswith(f":{TOPIC_NAME}"):
            _safe(lambda arn=t["TopicArn"]: sns.delete_topic(TopicArn=arn))
    print("[ok] teardown complete.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--notify-email", default=None, help="Email to subscribe to the SNS topic")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.apply)
    account = session.client("sts").get_caller_identity()["Account"]
    return build(session, args.region, account, args.notify_email, args.apply)


if __name__ == "__main__":
    sys.exit(main())
