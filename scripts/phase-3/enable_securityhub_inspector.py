#!/usr/bin/env python3
"""Enable Security Hub (+ FSBP standard) and Inspector (scenario 3.4).

Enabling actions are gated behind --apply (default: dry run). --disable turns both
services off again (they bill continuously, so run it at teardown). No secrets are
handled or printed.

Usage:
  python enable_securityhub_inspector.py --profile scs-member            # dry run
  python enable_securityhub_inspector.py --profile scs-member --apply
  python enable_securityhub_inspector.py --profile scs-member --disable --apply
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

INSPECTOR_RESOURCES = ["EC2", "ECR", "LAMBDA"]


def enable(session: boto3.Session, account: str, apply: bool) -> int:
    print(
        "Plan: enable Security Hub (+ default standards incl. FSBP) and Inspector",
        INSPECTOR_RESOURCES,
    )
    if not apply:
        print("\n[dry-run] Nothing enabled. Re-run with --apply.")
        return 0
    sh = session.client("securityhub")
    insp = session.client("inspector2")
    try:
        try:
            sh.enable_security_hub(EnableDefaultStandards=True)
            print("[ok] Security Hub enabled with default standards")
        except sh.exceptions.ResourceConflictException:
            print("[skip] Security Hub already enabled")
        insp.enable(accountIds=[account], resourceTypes=INSPECTOR_RESOURCES)
        print("[ok] Inspector enabled for", ", ".join(INSPECTOR_RESOURCES))
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def disable(session: boto3.Session, account: str, apply: bool) -> int:
    print("Plan: disable Inspector and Security Hub")
    if not apply:
        print("\n[dry-run] Re-run with --disable --apply.")
        return 0
    insp = session.client("inspector2")
    sh = session.client("securityhub")
    for action in (
        lambda: insp.disable(accountIds=[account], resourceTypes=INSPECTOR_RESOURCES),
        lambda: sh.disable_security_hub(),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    print("[ok] disabled")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--disable", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    if args.disable:
        return disable(session, account, args.apply)
    return enable(session, account, args.apply)


if __name__ == "__main__":
    sys.exit(main())
