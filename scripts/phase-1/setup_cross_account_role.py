#!/usr/bin/env python3
"""Create the Phase 1 cross-account audit role in Account B.

Builds CrossAccountAuditRole with an MFA + source-IP restricted trust policy
that trusts a named user in Account A. Destructive/creating actions are gated
behind --apply; the default is a dry run that prints the exact policy it WOULD
submit. No secrets are ever printed.

Usage:
  # Dry run (default) -- prints the trust policy, creates nothing:
  python setup_cross_account_role.py \
      --account-a 111111111111 --account-b 222222222222 \
      --user analyst --cidr 203.0.113.0/24 --profile scs-member

  # Actually create it:
  python setup_cross_account_role.py ... --apply
"""
import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

ROLE_NAME = "CrossAccountAuditRole"
# AWS-managed read-only auditing policy attached to the role's *permissions*.
PERMISSIONS_POLICY_ARN = "arn:aws:iam::aws:policy/SecurityAudit"


def build_trust_policy(account_a: str, user: str, cidr: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TrustAccountAUserWithMFAandIP",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_a}:user/{user}"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"},
                    "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},
                    "IpAddress": {"aws:SourceIp": [cidr]},
                },
            }
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--account-a", required=True, help="Trusted account ID (where the user lives)")
    p.add_argument("--account-b", required=True, help="This account ID (where the role is created)")
    p.add_argument("--user", default="analyst", help="IAM user name in Account A")
    p.add_argument("--cidr", required=True, help="Allowed source IP CIDR, e.g. 203.0.113.0/24")
    p.add_argument("--profile", default=None, help="AWS named profile for Account B")
    p.add_argument("--apply", action="store_true", help="Actually create (default: dry run)")
    args = p.parse_args()

    trust = build_trust_policy(args.account_a, args.user, args.cidr)
    print("Trust policy that will be attached to", ROLE_NAME, ":\n")
    print(json.dumps(trust, indent=2))

    if not args.apply:
        print("\n[dry-run] No resources created. Re-run with --apply to create.")
        return 0

    session = boto3.Session(profile_name=args.profile)
    iam = session.client("iam")
    try:
        iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Phase 1 lab: MFA+IP restricted cross-account audit role",
            MaxSessionDuration=3600,
        )
        iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=PERMISSIONS_POLICY_ARN)
    except ClientError as e:
        # Print the AWS error code/message (never credentials) so you can map it
        # to the exam's phrasing.
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1

    print(f"\n[ok] Created role {ROLE_NAME} and attached {PERMISSIONS_POLICY_ARN}.")
    print("Test it with assume_role_test.py from an Account A profile.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
