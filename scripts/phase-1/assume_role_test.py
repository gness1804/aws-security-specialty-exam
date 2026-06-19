#!/usr/bin/env python3
"""Attempt to assume the Phase 1 cross-account role and report the result.

This is your Break/Fix harness: run it with MFA, without MFA, from an allowed IP,
and from a disallowed IP, and watch which condition denies you. It prints the
assumed-role ARN and the credential EXPIRY only -- it NEVER prints the
AccessKeyId, SecretAccessKey, or SessionToken. On denial it prints the AWS error
code so you can map it to the trust-policy condition that fired.

Usage:
  python assume_role_test.py \
      --role-arn arn:aws:iam::222222222222:role/CrossAccountAuditRole \
      --profile scs-mgmt --mfa-serial arn:aws:iam::111111111111:mfa/analyst
"""
import argparse
import sys

import boto3
from botocore.exceptions import ClientError


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role-arn", required=True)
    p.add_argument("--profile", default=None, help="Account A profile doing the assume")
    p.add_argument("--mfa-serial", default=None, help="MFA device ARN (omit to test the no-MFA denial)")
    p.add_argument("--session-name", default="phase1-test")
    args = p.parse_args()

    session = boto3.Session(profile_name=args.profile)
    sts = session.client("sts")

    kwargs = {"RoleArn": args.role_arn, "RoleSessionName": args.session_name}
    if args.mfa_serial:
        token = input("Enter current MFA token code: ").strip()
        kwargs["SerialNumber"] = args.mfa_serial
        kwargs["TokenCode"] = token

    try:
        resp = sts.assume_role(**kwargs)
    except ClientError as e:
        err = e.response["Error"]
        print(f"[DENIED] {err['Code']}: {err['Message']}")
        print("  -> Map this to a trust-policy condition: missing MFA? wrong IP? wrong principal?")
        return 1

    creds = resp["Credentials"]
    arn = resp["AssumedRoleUser"]["Arn"]
    # Deliberately print only non-secret metadata.
    print("[SUCCESS] Assumed role.")
    print(f"  Assumed-role ARN : {arn}")
    print(f"  Credentials expire: {creds['Expiration'].isoformat()}")
    print("  (Access key / secret / session token intentionally NOT printed.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
