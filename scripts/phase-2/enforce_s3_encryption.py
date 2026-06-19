#!/usr/bin/env python3
"""Enforce SSE-KMS + bucket key + a deny-unencrypted-PutObject bucket policy.

Sets bucket default encryption to SSE-KMS with a bucket key, then applies a bucket
policy that denies any PutObject not encrypted with the given KMS key. Creating/
modifying actions are gated behind --apply (default: dry run prints the plan).

--break runs the three Break/Fix uploads from drill D2.3 (no header / wrong key /
right key) so you can observe which statement denies which. It uploads a tiny
in-memory object and never writes secrets to output.

Usage:
  python enforce_s3_encryption.py --bucket my-bkt --kms-key-arn arn:... --profile scs-member
  python enforce_s3_encryption.py --bucket my-bkt --kms-key-arn arn:... --profile scs-member --apply
  python enforce_s3_encryption.py --bucket my-bkt --kms-key-arn arn:... --profile scs-member --break
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError


def deny_policy(bucket: str, kms_key_arn: str) -> dict:
    obj = f"arn:aws:s3:::{bucket}/*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyMissingEncryptionHeader",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": obj,
                "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}},
            },
            {
                "Sid": "DenyWrongEncryptionType",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": obj,
                "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}},
            },
            {
                "Sid": "DenyWrongKmsKey",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": obj,
                "Condition": {
                    "StringNotEquals": {
                        "s3:x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn
                    }
                },
            },
        ],
    }


def apply_config(s3, bucket: str, kms_key_arn: str) -> int:
    try:
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key_arn,
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(deny_policy(bucket, kms_key_arn)))
    except ClientError as e:
        print(f"[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    print(f"[ok] default SSE-KMS + bucket key + deny policy applied to {bucket}")
    return 0


def run_break(s3, bucket: str, kms_key_arn: str) -> int:
    """Attempt the three D2.3 uploads and report allow/deny per the policy."""
    body = b"phase2-drill"
    attempts = [
        ("no header", {}),
        ("aws:kms + wrong key", {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": "alias/aws/s3"}),
        ("aws:kms + correct key", {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_key_arn}),
    ]
    for label, extra in attempts:
        try:
            s3.put_object(Bucket=bucket, Key=f"drill/{label.replace(' ', '_')}", Body=body, **extra)
            print(f"[ALLOWED] {label}")
        except ClientError as e:
            print(f"[DENIED ] {label} -> {e.response['Error']['Code']}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bucket", required=True)
    p.add_argument("--kms-key-arn", required=True, help="Your CMK ARN")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true", help="Apply config (default: dry run)")
    p.add_argument(
        "--break",
        dest="do_break",
        action="store_true",
        help="Run the D2.3 upload drill against the bucket",
    )
    args = p.parse_args()

    s3 = boto3.Session(profile_name=args.profile, region_name=args.region).client("s3")

    if args.do_break:
        return run_break(s3, args.bucket, args.kms_key_arn)

    print(json.dumps(deny_policy(args.bucket, args.kms_key_arn), indent=2))
    if not args.apply:
        print("\n[dry-run] Bucket not modified. Re-run with --apply.")
        return 0
    return apply_config(s3, args.bucket, args.kms_key_arn)


if __name__ == "__main__":
    sys.exit(main())
