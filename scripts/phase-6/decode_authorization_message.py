#!/usr/bin/env python3
"""Decode an AccessDenied encoded authorization message (scenario 6.2, READ-ONLY).

Some AWS denials (commonly EC2, and a number of other services) include an "encoded
authorization failure message" in the error. This calls
sts:DecodeAuthorizationMessage to turn that opaque blob into JSON showing the
principal, action, resource, and the statements/policy type that drove the denial --
the postmortem counterpart to the Policy Simulator's prediction.

Read-only: it changes nothing (no --apply/--teardown). You need permission to call
sts:DecodeAuthorizationMessage. Pass the blob with --message, or --message-file to
read it from a file (handy because the blobs are long). The decoded context contains
ARNs/account ids (resource identifiers) -- no credentials or secrets are printed.

Usage:
  python decode_authorization_message.py --message <ENCODED_BLOB> --profile scs-member
  python decode_authorization_message.py --message-file /tmp/blob.txt --profile scs-member
"""

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--message", help="The encoded authorization message blob")
    g.add_argument("--message-file", help="File containing the encoded blob")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    args = p.parse_args()

    blob = Path(args.message_file).read_text().strip() if args.message_file else args.message
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client("sts")
    try:
        decoded = sts.decode_authorization_message(EncodedMessage=blob)["DecodedMessage"]
    except ClientError as e:
        print(f"[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1

    # DecodedMessage is a JSON string; pretty-print it for reading.
    try:
        parsed = json.loads(decoded)
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(decoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
