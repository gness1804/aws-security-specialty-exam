#!/usr/bin/env python3
"""Enable AWS Config + managed rule + SSM auto-remediation (scenario 3.1).

Sets up the configuration recorder and delivery channel, adds the managed rule
s3-bucket-public-read-prohibited, creates the SSM remediation execution role, and
configures automatic remediation that re-blocks a public bucket. Creating actions
are gated behind --apply (default: dry run). --teardown removes everything.

A delivery-channel S3 bucket name is required (--delivery-bucket); it's created if
absent. No secrets are handled or printed.

Usage:
  python setup_config_remediation.py --delivery-bucket <BKT> --profile scs-member
  # add --apply to create; add --teardown --apply to remove.
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

RECORDER_NAME = "default"
CHANNEL_NAME = "default"
RULE_NAME = "s3-bucket-public-read-prohibited"
REMEDIATION_ROLE = "scs-phase3-s3-remediation-role"
REMEDIATION_POLICY = "s3-remediate"
SSM_DOCUMENT = "AWS-DisableS3BucketPublicReadWrite"

REMEDIATION_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ssm.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
REMEDIATION_PERMS = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "RemediatePublicS3",
            "Effect": "Allow",
            "Action": [
                "s3:PutBucketPublicAccessBlock",
                "s3:GetBucketPublicAccessBlock",
                "s3:PutBucketAcl",
                "s3:GetBucketAcl",
                "s3:DeleteBucketPolicy",
                "s3:GetBucketPolicy",
            ],
            "Resource": "arn:aws:s3:::*",
        }
    ],
}


def _ensure_bucket(s3, bucket: str, region: str) -> None:
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        kwargs = {"Bucket": bucket}
        if region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**kwargs)


def build(session: boto3.Session, region: str, account: str, bucket: str, apply: bool) -> int:
    print("Plan:")
    for s in (
        f"create delivery bucket {bucket} (if absent) + Config bucket policy",
        "create service-linked role for Config",
        f"put + start configuration recorder ({RECORDER_NAME}, all supported)",
        f"put delivery channel ({CHANNEL_NAME}) -> {bucket}",
        f"put managed rule {RULE_NAME}",
        f"create remediation role {REMEDIATION_ROLE} (trusts ssm)",
        f"put automatic remediation via {SSM_DOCUMENT}",
    ):
        print("  -", s)
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    iam = session.client("iam")
    s3 = session.client("s3")
    config = session.client("config")
    try:
        _ensure_bucket(s3, bucket, region)
        # Service-linked role lets Config write/record.
        try:
            iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidInput":
                raise  # already exists -> InvalidInput; ignore
        slr_arn = (
            f"arn:aws:iam::{account}:role/aws-service-role/"
            "config.amazonaws.com/AWSServiceRoleForConfig"
        )

        config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": RECORDER_NAME,
                "roleARN": slr_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
            }
        )
        config.put_delivery_channel(DeliveryChannel={"name": CHANNEL_NAME, "s3BucketName": bucket})
        config.start_configuration_recorder(ConfigurationRecorderName=RECORDER_NAME)
        print("[ok] recorder + delivery channel running")

        config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": RULE_NAME,
                "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
                "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            }
        )
        print(f"[ok] managed rule {RULE_NAME} added")

        role_arn = _ensure_remediation_role(iam)
        config.put_remediation_configurations(
            RemediationConfigurations=[
                {
                    "ConfigRuleName": RULE_NAME,
                    "TargetType": "SSM_DOCUMENT",
                    "TargetId": SSM_DOCUMENT,
                    "Automatic": True,
                    "MaximumAutomaticAttempts": 5,
                    "RetryAttemptSeconds": 60,
                    "Parameters": {
                        "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
                        "S3BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}},
                    },
                }
            ]
        )
        print("[ok] automatic remediation configured")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def _ensure_remediation_role(iam) -> str:
    import json

    try:
        arn = iam.create_role(
            RoleName=REMEDIATION_ROLE,
            AssumeRolePolicyDocument=json.dumps(REMEDIATION_TRUST),
            Description="Phase 3 S3 public-access remediation role",
        )["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        arn = iam.get_role(RoleName=REMEDIATION_ROLE)["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=REMEDIATION_ROLE,
        PolicyName=REMEDIATION_POLICY,
        PolicyDocument=json.dumps(REMEDIATION_PERMS),
    )
    return arn


def teardown(session: boto3.Session, apply: bool) -> int:
    print("Plan: delete remediation config, rule, recorder, delivery channel, remediation role")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    config = session.client("config")
    iam = session.client("iam")
    for action in (
        lambda: config.delete_remediation_configuration(ConfigRuleName=RULE_NAME),
        lambda: config.delete_config_rule(ConfigRuleName=RULE_NAME),
        lambda: config.stop_configuration_recorder(ConfigurationRecorderName=RECORDER_NAME),
        lambda: config.delete_delivery_channel(DeliveryChannelName=CHANNEL_NAME),
        lambda: config.delete_configuration_recorder(ConfigurationRecorderName=RECORDER_NAME),
        lambda: iam.delete_role_policy(RoleName=REMEDIATION_ROLE, PolicyName=REMEDIATION_POLICY),
        lambda: iam.delete_role(RoleName=REMEDIATION_ROLE),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    print("[ok] teardown complete. Empty + delete the delivery bucket manually.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--delivery-bucket", default=None, help="S3 bucket for Config history")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.apply)
    if args.apply and not args.delivery_bucket:
        p.error("--delivery-bucket is required with --apply")
    account = session.client("sts").get_caller_identity()["Account"]
    return build(session, args.region, account, args.delivery_bucket, args.apply)


if __name__ == "__main__":
    sys.exit(main())
