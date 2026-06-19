#!/usr/bin/env python3
"""Phase 1 KMS lockout demo -- create a CMK and explore key-policy vs IAM-policy.

SAFE BY DEFAULT. Without --full-lockout the key keeps a recovery admin principal
(the account root statement), so you can always fix or delete it yourself. Pass
--full-lockout ONLY to recreate the true admin-less lockout; that key can then be
fixed only via an AWS Support case, so the script makes you confirm.

No key material is ever printed -- only the key ID/ARN and policy JSON.

Usage:
  # Dry run: print the key policy that WOULD be applied (creates nothing):
  python kms_lockout_demo.py --account-b 222222222222 --app-role AppEncryptRole \
      --profile scs-member

  # Create a SAFE demo key (keeps root admin statement):
  python kms_lockout_demo.py --account-b 222222222222 --app-role AppEncryptRole \
      --profile scs-member --apply

  # Recreate the real lockout (no admin) -- requires explicit confirmation:
  python kms_lockout_demo.py ... --apply --full-lockout
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError


def root_admin_statement(account_b: str) -> dict:
    return {
        "Sid": "EnableRootAccountPermissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_b}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }


def app_data_statement(account_b: str, app_role: str) -> dict:
    return {
        "Sid": "AllowAppRoleToUseKeyForData",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_b}:role/{app_role}"},
        "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
        "Resource": "*",
    }


def build_policy(account_b: str, app_role: str, full_lockout: bool) -> dict:
    statements = [app_data_statement(account_b, app_role)]
    if not full_lockout:
        statements.insert(0, root_admin_statement(account_b))
    return {"Version": "2012-10-17", "Id": "phase1-lockout-demo", "Statement": statements}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--account-b", required=True)
    p.add_argument("--app-role", default="AppEncryptRole")
    p.add_argument("--profile", default=None)
    p.add_argument("--apply", action="store_true", help="Actually create (default: dry run)")
    p.add_argument(
        "--full-lockout",
        action="store_true",
        help="Omit the root admin statement -> true lockout (Support-only recovery)",
    )
    args = p.parse_args()

    policy = build_policy(args.account_b, args.app_role, args.full_lockout)
    print("Key policy to be applied:\n")
    print(json.dumps(policy, indent=2))

    if args.full_lockout:
        print("\n*** WARNING: --full-lockout omits the root admin statement. ***")
        print("*** No principal in your account will be able to administer this key. ***")
        print("*** Recovery requires an AWS Support case. ***")

    if not args.apply:
        print("\n[dry-run] No key created. Re-run with --apply to create.")
        return 0

    if args.full_lockout:
        if input("\nType 'LOCKOUT' to confirm creating an admin-less key: ").strip() != "LOCKOUT":
            print("Aborted.")
            return 1

    session = boto3.Session(profile_name=args.profile)
    kms = session.client("kms")
    try:
        resp = kms.create_key(
            Description="Phase 1 lockout demo key",
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Policy=json.dumps(policy),
        )
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1

    meta = resp["KeyMetadata"]
    print(f"\n[ok] Created key. KeyId={meta['KeyId']}  Arn={meta['Arn']}")
    if not args.full_lockout:
        print("Try enable-key-rotation on the KeyId -- should SUCCEED (you kept admin).")
    else:
        print("Try enable-key-rotation on the KeyId -- should FAIL (no admin).")
    print("Cleanup: aws kms schedule-key-deletion --key-id <KeyId> --pending-window-in-days 7")
    return 0


if __name__ == "__main__":
    sys.exit(main())
