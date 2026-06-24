#!/usr/bin/env python3
"""Deploy the GuardDuty -> EventBridge -> Lambda -> NACL remediation (scenario 3.3).

Packages guardduty_nacl_remediation_lambda.py, creates its execution role, creates
an EventBridge rule matching GuardDuty findings, targets the Lambda, and grants
EventBridge permission to invoke it. Creating actions are gated behind --apply
(default: dry run). --teardown removes everything.

You must pass the NACL the Lambda should add deny entries to (--nacl-id), and a
GuardDuty detector must exist in the region.

Usage:
  python setup_guardduty_remediation.py --nacl-id acl-0abc --profile scs-member          # dry run
  python setup_guardduty_remediation.py --nacl-id acl-0abc --profile scs-member --apply
  python setup_guardduty_remediation.py --profile scs-member --teardown --apply
"""

import argparse
import json
import sys
from pathlib import Path

import _deploy
import boto3
from botocore.exceptions import ClientError

HANDLER = Path(__file__).with_name("guardduty_nacl_remediation_lambda.py")
FUNCTION_NAME = "scs-phase3-gd-nacl-block"
ROLE_NAME = "scs-phase3-gd-nacl-block-role"
POLICY_NAME = "nacl-block"
RULE_NAME = "scs-guardduty-findings"


def exec_policy(region: str, account: str, nacl_id: str) -> dict:
    """Least-privilege exec policy for the NACL-block Lambda.

    DescribeNetworkAcls has no resource-level support, so it stays on "*";
    CreateNetworkAclEntry is scoped to the one NACL this Lambda manages.
    """
    nacl_arn = f"arn:aws:ec2:{region}:{account}:network-acl/{nacl_id}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DescribeNacls",
                "Effect": "Allow",
                "Action": "ec2:DescribeNetworkAcls",
                "Resource": "*",
            },
            {
                "Sid": "AddNaclDenyEntries",
                "Effect": "Allow",
                "Action": "ec2:CreateNetworkAclEntry",
                "Resource": nacl_arn,
            },
            {
                "Sid": "Logs",
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }


# Start broad (all findings), then narrow by severity in production.
EVENT_PATTERN = {
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
}


def build(session: boto3.Session, nacl_id: str, apply: bool) -> int:
    print("Plan: role + Lambda + EventBridge rule + target + invoke permission")
    print(f"  NACL_ID={nacl_id}, rule={RULE_NAME}")
    print("Event pattern:", json.dumps(EVENT_PATTERN))
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0
    if not nacl_id:
        print("[error] --nacl-id is required with --apply")
        return 1

    iam = session.client("iam")
    lam = session.client("lambda")
    events = session.client("events")
    account = session.client("sts").get_caller_identity()["Account"]
    try:
        role_arn = _deploy.ensure_role(
            iam, ROLE_NAME, POLICY_NAME, exec_policy(session.region_name, account, nacl_id)
        )
        fn_arn = _deploy.create_lambda(
            lam,
            FUNCTION_NAME,
            role_arn,
            HANDLER.stem,
            _deploy.build_zip(HANDLER),
            # Lab deploys IGNORE_SAMPLE=false so create-sample-findings exercises
            # the full block (V3.3 / D3.3). In production set it "true" so test
            # findings don't trigger real NACL changes.
            env={"NACL_ID": nacl_id, "BASE_RULE_NUM": "100", "IGNORE_SAMPLE": "false"},
        )
        print(f"[ok] deployed {FUNCTION_NAME}")

        rule_arn = events.put_rule(
            Name=RULE_NAME,
            EventPattern=json.dumps(EVENT_PATTERN),
            Description="Phase 3: route GuardDuty findings to the NACL-block Lambda",
        )["RuleArn"]
        _deploy.add_service_invoke(
            lam,
            FUNCTION_NAME,
            "EventBridgeInvoke",
            "events.amazonaws.com",
            source_arn=rule_arn,
        )
        events.put_targets(Rule=RULE_NAME, Targets=[{"Id": "nacl-block", "Arn": fn_arn}])
        print(f"[ok] wired EventBridge rule {RULE_NAME} -> {FUNCTION_NAME}")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, apply: bool) -> int:
    print("Plan: remove EventBridge target + rule, Lambda, role")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    events = session.client("events")
    for action in (
        lambda: events.remove_targets(Rule=RULE_NAME, Ids=["nacl-block"]),
        lambda: events.delete_rule(Name=RULE_NAME),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    _deploy.delete_function_and_role(
        session.client("lambda"),
        session.client("iam"),
        FUNCTION_NAME,
        ROLE_NAME,
        POLICY_NAME,
    )
    print("[ok] teardown complete. Remove any NACL deny entries the Lambda added.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nacl-id", default=None, help="Subnet NACL to add deny entries to")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.apply)
    return build(session, args.nacl_id, args.apply)


if __name__ == "__main__":
    sys.exit(main())
