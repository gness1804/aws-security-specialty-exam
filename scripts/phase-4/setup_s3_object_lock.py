#!/usr/bin/env python3
"""Create a WORM log bucket: Object Lock + deny-delete bucket policy (scenario 4.3).

Creates a versioned bucket with Object Lock enabled at creation, sets a default
retention (COMPLIANCE by default -- not even root can delete until it expires), and
applies the explicit deny-delete bucket policy as a defense-in-depth layer. Object
Lock can only be enabled at bucket creation, so this always makes a NEW bucket.

Creating actions are gated behind --apply (default: dry run). --teardown removes the
deny-delete policy (so you can manage the bucket again) but CANNOT delete
COMPLIANCE-locked objects before their retention expires -- that's the guarantee.
Use a short --retention-days for the lab. No secrets are handled or printed.

Usage:
  python setup_s3_object_lock.py --bucket scs-worm-<ACCT> --profile scs-member   # dry run
  python setup_s3_object_lock.py --bucket scs-worm-<ACCT> --retention-days 1 \
      --profile scs-member --apply
  python setup_s3_object_lock.py --bucket scs-worm-<ACCT> --profile scs-member --teardown --apply
"""

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

POLICY_FILE = Path(__file__).parents[2] / "policies/phase-4/4.3-deny-delete-bucket-policy.json"


def _deny_delete_policy(bucket: str) -> dict:
    raw = json.loads(POLICY_FILE.read_text())
    raw.pop("_comment", None)
    raw["Statement"][0]["Resource"] = f"arn:aws:s3:::{bucket}/*"
    raw["Statement"][1]["Resource"] = f"arn:aws:s3:::{bucket}"
    return raw


# COMPLIANCE retention is irreversible -- not even root can shorten it. Cap it for
# the lab so a typo (e.g. 3650) can't create a decade-long, unkillable lock; require
# --allow-long-retention to deliberately exceed the cap.
COMPLIANCE_DAYS_CAP = 7


def build(
    session: boto3.Session,
    region: str,
    bucket: str,
    mode: str,
    days: int,
    allow_long: bool,
    apply: bool,
) -> int:
    print("Plan:")
    for s in (
        f"create bucket {bucket} with ObjectLockEnabledForBucket=True (versioned)",
        f"set default retention: mode={mode}, days={days}",
        "apply explicit deny-delete bucket policy (defense in depth)",
    ):
        print("  -", s)
    if mode == "COMPLIANCE":
        print(
            f"  WARNING: COMPLIANCE objects cannot be deleted by anyone (incl. root) "
            f"for {days} day(s). Keep --retention-days small for the lab."
        )
        if days > COMPLIANCE_DAYS_CAP and not allow_long:
            print(
                f"\n[error] refusing: COMPLIANCE retention of {days}d exceeds the "
                f"{COMPLIANCE_DAYS_CAP}d lab cap and is IRREVERSIBLE. Re-run with "
                f"--allow-long-retention only if you truly mean it."
            )
            return 1
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0
    if not bucket:
        print("[error] --bucket is required with --apply")
        return 1

    s3 = session.client("s3")
    try:
        kwargs = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
        if region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**kwargs)
        # Object Lock implies versioning, but set it explicitly to be safe.
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        s3.put_object_lock_configuration(
            Bucket=bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": mode, "Days": days}},
            },
        )
        print(f"[ok] {bucket} created with Object Lock ({mode}, {days}d) + versioning")
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_deny_delete_policy(bucket)))
        print("[ok] deny-delete bucket policy applied")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, bucket: str, apply: bool) -> int:
    print(f"Plan: remove the deny-delete bucket policy from {bucket}")
    print("  note: COMPLIANCE-locked object versions remain undeletable until retention expires.")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    if not bucket:
        print("[error] --bucket is required with --teardown --apply")
        return 1
    s3 = session.client("s3")
    try:
        s3.delete_bucket_policy(Bucket=bucket)
        print("[ok] deny-delete policy removed")
    except ClientError as e:
        print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bucket", default=None, help="NEW bucket name (Object Lock is creation-time)")
    p.add_argument("--mode", choices=["COMPLIANCE", "GOVERNANCE"], default="COMPLIANCE")
    p.add_argument("--retention-days", type=int, default=1, help="Default retention (keep small)")
    p.add_argument(
        "--allow-long-retention",
        action="store_true",
        help=f"Permit COMPLIANCE retention > {COMPLIANCE_DAYS_CAP}d (irreversible)",
    )
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.bucket, args.apply)
    return build(
        session,
        args.region,
        args.bucket,
        args.mode,
        args.retention_days,
        args.allow_long_retention,
        args.apply,
    )


if __name__ == "__main__":
    sys.exit(main())
