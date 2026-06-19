#!/usr/bin/env python3
"""Enable Macie and create a one-time sensitive-data discovery job (Stretch, B2.4).

Enables Macie in the region, optionally registers a custom data identifier for the
SCSLAB-<8 hex> token format, and creates a one-time classification job over the
named bucket(s). Creating actions are gated behind --apply (default: dry run).
Macie bills per-GB classified, so the lab teardown disables it again.

Usage:
  python macie_discovery.py --bucket my-seeded-bucket --profile scs-member            # dry run
  python macie_discovery.py --bucket my-seeded-bucket --profile scs-member --apply
  python macie_discovery.py --disable --profile scs-member --apply
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

CUSTOM_ID_NAME = "scslab-token"
CUSTOM_ID_REGEX = r"\bSCSLAB-[0-9a-fA-F]{8}\b"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bucket", action="append", default=[], help="Bucket to scan (repeatable)")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true", help="Act (default: dry run)")
    p.add_argument("--disable", action="store_true", help="Disable Macie and exit")
    p.add_argument(
        "--no-custom-id",
        action="store_true",
        help="Skip creating the SCSLAB custom data identifier",
    )
    args = p.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    macie = session.client("macie2")
    account = session.client("sts").get_caller_identity()["Account"]

    if args.disable:
        print("Plan: disable Macie in", args.region)
        if not args.apply:
            print("[dry-run] Re-run with --apply.")
            return 0
        try:
            macie.disable_macie()
            print("[ok] Macie disabled")
        except ClientError as e:
            print(f"[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
            return 1
        return 0

    if not args.bucket:
        p.error("--bucket is required unless --disable is given")

    print("Plan:")
    print("  - enable Macie")
    if not args.no_custom_id:
        print(f"  - create custom data identifier {CUSTOM_ID_NAME} = /{CUSTOM_ID_REGEX}/")
    print(f"  - create one-time classification job over: {', '.join(args.bucket)}")
    if not args.apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    try:
        macie.enable_macie()
        print("[ok] Macie enabled")

        custom_ids = []
        if not args.no_custom_id:
            cid = macie.create_custom_data_identifier(
                name=CUSTOM_ID_NAME,
                regex=CUSTOM_ID_REGEX,
                description="Phase 2 lab: SCSLAB token format",
            )
            custom_ids.append(cid["customDataIdentifierId"])
            print(f"[ok] custom data identifier {CUSTOM_ID_NAME} created")

        job = macie.create_classification_job(
            jobType="ONE_TIME",
            name="scs-phase2-discovery",
            s3JobDefinition={"bucketDefinitions": [{"accountId": account, "buckets": args.bucket}]},
            customDataIdentifierIds=custom_ids,
        )
        print(f"[ok] classification job created: {job['jobId']}")
    except ClientError as e:
        print(f"[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
