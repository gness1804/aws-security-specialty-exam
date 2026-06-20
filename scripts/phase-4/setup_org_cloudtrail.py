#!/usr/bin/env python3
"""Create a tamper-evident CloudTrail to an isolated bucket (scenario 4.2).

Creates an S3 bucket with a CloudTrail-only delivery policy, then a multi-region
trail with log-file validation enabled. Defaults to a SINGLE-account trail so it
runs in the current two-account lab setup; pass --org-trail to make it an
organization trail (must be run in the management account, and the bucket policy
must cover the org -- see the inline note and the org pattern in B4.2).

Creating actions are gated behind --apply (default: dry run). --teardown deletes
the trail (the bucket is left in place -- it's your evidence; empty/delete it
manually). No secrets are handled or printed -- bucket names, trail names, ARNs only.

Usage:
  python setup_org_cloudtrail.py --bucket scs-trail-<ACCT> --profile scs-member          # dry run
  python setup_org_cloudtrail.py --bucket scs-trail-<ACCT> --profile scs-member --apply
  python setup_org_cloudtrail.py --profile scs-member --teardown --apply
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

TRAIL_NAME = "scs-phase4-trail"


def _bucket_policy(bucket: str, account: str, region: str) -> dict:
    trail_arn = f"arn:aws:cloudtrail:{region}:{account}:trail/{TRAIL_NAME}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
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


def build(
    session: boto3.Session, region: str, account: str, bucket: str, org: bool, apply: bool
) -> int:
    print("Plan:")
    for s in (
        f"create bucket {bucket} (if absent) + CloudTrail delivery policy",
        f"create trail {TRAIL_NAME} (multi-region, log-file validation ON)",
        f"{'ORGANIZATION trail (run in mgmt account)' if org else 'single-account trail'}",
        "start logging",
    ):
        print("  -", s)
    if org:
        print(
            "  note: --org-trail requires running in the management account and a "
            "bucket policy covering AWSLogs/<orgId>/* with aws:SourceAccount."
        )
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0
    if not bucket:
        print("[error] --bucket is required with --apply")
        return 1

    s3 = session.client("s3")
    ct = session.client("cloudtrail")
    try:
        _ensure_bucket(s3, bucket, region)
        s3.put_bucket_policy(
            Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account, region))
        )
        print(f"[ok] bucket {bucket} ready with CloudTrail delivery policy")

        try:
            ct.create_trail(
                Name=TRAIL_NAME,
                S3BucketName=bucket,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                IsOrganizationTrail=org,
            )
            print(f"[ok] created trail {TRAIL_NAME} (validation on)")
        except ct.exceptions.TrailAlreadyExistsException:
            ct.update_trail(
                Name=TRAIL_NAME,
                S3BucketName=bucket,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                IsOrganizationTrail=org,
            )
            print(f"[ok] updated existing trail {TRAIL_NAME}")
        ct.start_logging(Name=TRAIL_NAME)
        print("[ok] logging started. First digest file arrives within ~1 hour.")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, apply: bool) -> int:
    print(f"Plan: stop logging + delete trail {TRAIL_NAME} (bucket left in place)")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    ct = session.client("cloudtrail")
    for action in (
        lambda: ct.stop_logging(Name=TRAIL_NAME),
        lambda: ct.delete_trail(Name=TRAIL_NAME),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    print("[ok] trail removed. Empty + delete the log bucket manually if desired.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bucket", default=None, help="S3 bucket for CloudTrail logs")
    p.add_argument("--org-trail", action="store_true", help="Make it an organization trail")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.apply)
    if args.apply and not args.bucket:
        p.error("--bucket is required with --apply")
    account = session.client("sts").get_caller_identity()["Account"]
    return build(session, args.region, account, args.bucket, args.org_trail, args.apply)


if __name__ == "__main__":
    sys.exit(main())
