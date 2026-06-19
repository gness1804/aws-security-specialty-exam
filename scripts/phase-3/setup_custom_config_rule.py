#!/usr/bin/env python3
"""Deploy the custom security-group Config rule (scenario 3.2).

Packages custom_sg_config_rule_lambda.py, creates its execution role, grants
Config permission to invoke it, and creates a configuration-change-triggered
custom Config rule scoped to security groups. Creating actions are gated behind
--apply (default: dry run). --teardown removes the rule, function, and role.

Requires the Config recorder to be running (see setup_config_remediation.py).

Usage:
  python setup_custom_config_rule.py --profile scs-member               # dry run
  python setup_custom_config_rule.py --profile scs-member --apply
  python setup_custom_config_rule.py --profile scs-member --teardown --apply
"""

import argparse
import sys
from pathlib import Path

import _deploy
import boto3
from botocore.exceptions import ClientError

HANDLER = Path(__file__).with_name("custom_sg_config_rule_lambda.py")
FUNCTION_NAME = "scs-phase3-sg-config-rule"
ROLE_NAME = "scs-phase3-sg-config-rule-role"
POLICY_NAME = "config-eval"
RULE_NAME = "scs-no-public-ssh-rdp"

EXEC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReportEvaluationsToConfig",
            "Effect": "Allow",
            "Action": "config:PutEvaluations",
            "Resource": "*",
        },
        {
            "Sid": "Logs",
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ],
}


def build(session: boto3.Session, apply: bool) -> int:
    print("Plan: role + Lambda + Config invoke permission + custom rule", RULE_NAME)
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    iam = session.client("iam")
    lam = session.client("lambda")
    config = session.client("config")
    try:
        role_arn = _deploy.ensure_role(iam, ROLE_NAME, POLICY_NAME, EXEC_POLICY)
        fn_arn = _deploy.create_lambda(
            lam, FUNCTION_NAME, role_arn, HANDLER.stem, _deploy.build_zip(HANDLER)
        )
        print(f"[ok] deployed {FUNCTION_NAME}")
        _deploy.add_service_invoke(lam, FUNCTION_NAME, "ConfigInvoke", "config.amazonaws.com")
        print("[ok] granted config.amazonaws.com invoke permission")
        config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": RULE_NAME,
                "Description": "NON_COMPLIANT if SG opens 22/3389 to 0.0.0.0/0",
                "Scope": {"ComplianceResourceTypes": ["AWS::EC2::SecurityGroup"]},
                "Source": {
                    "Owner": "CUSTOM_LAMBDA",
                    "SourceIdentifier": fn_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ConfigurationItemChangeNotification",
                        }
                    ],
                },
            }
        )
        print(f"[ok] created custom Config rule {RULE_NAME}")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, apply: bool) -> int:
    print("Plan: delete custom rule, Lambda, role")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    config = session.client("config")
    try:
        config.delete_config_rule(ConfigRuleName=RULE_NAME)
    except ClientError as e:
        print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    _deploy.delete_function_and_role(
        session.client("lambda"),
        session.client("iam"),
        FUNCTION_NAME,
        ROLE_NAME,
        POLICY_NAME,
    )
    print("[ok] teardown complete")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.apply)
    return build(session, args.apply)


if __name__ == "__main__":
    sys.exit(main())
