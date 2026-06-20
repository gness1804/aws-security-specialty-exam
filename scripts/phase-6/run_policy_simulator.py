#!/usr/bin/env python3
"""Run the IAM Policy Simulator for the Phase 6.2 drills (READ-ONLY).

Two modes:
  * custom    -- simulate one or more local policy JSON files (simulate_custom_policy),
                 optionally with a permissions boundary and/or an MFA context value.
  * principal -- simulate a real principal's effective policies (simulate_principal_policy).

This script is read-only -- it evaluates permissions and changes nothing, so there's
no --apply/--teardown. It prints, per action: EvalDecision (allowed/explicitDeny/
implicitDeny), the matched statement(s), and any MissingContextValues. No secrets are
handled or printed -- policy docs, ARNs, and decisions only.

Usage:
  # custom: the mixed test policy, three actions
  python run_policy_simulator.py custom \
      --policy ../../policies/phase-6/6.2-simulator-test-policy.json \
      --actions s3:GetObject,s3:DeleteBucket,ec2:StartInstances --profile scs-member

  # custom + boundary (shows the intersection -> implicitDeny on ec2:StartInstances)
  python run_policy_simulator.py custom \
      --policy ../../policies/phase-6/6.2-simulator-test-policy.json \
      --boundary ../../policies/phase-6/6.2-permission-boundary.json \
      --actions ec2:StartInstances --profile scs-member

  # principal: a real role/user's effective permissions
  python run_policy_simulator.py principal \
      --principal-arn arn:aws:iam::<ACCT>:role/<ROLE> \
      --actions s3:GetObject,iam:DeleteRole --profile scs-member
"""

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def _load_policy(path: str) -> str:
    raw = json.loads(Path(path).read_text())
    raw.pop("_comment", None)
    return json.dumps(raw)


def _context_entries(mfa: bool) -> list:
    if not mfa:
        return []
    return [
        {
            "ContextKeyName": "aws:MultiFactorAuthPresent",
            "ContextKeyValues": ["true"],
            "ContextKeyType": "boolean",
        }
    ]


def _print_results(results: list) -> None:
    for r in results:
        action = r["EvalActionName"]
        decision = r["EvalDecision"]
        matched = [
            f"{m.get('SourcePolicyId', '?')}::{m.get('SourcePolicyType', '?')}"
            for m in r.get("MatchedStatements", [])
        ]
        missing = r.get("MissingContextValues", [])
        print(f"  {action:24} -> {decision}")
        if matched:
            print(f"      matched: {', '.join(matched)}")
        if missing:
            print(f"      missing context: {', '.join(missing)}")


def run_custom(session, policy_file, boundary_file, actions, resource, mfa) -> int:
    iam = session.client("iam")
    kwargs = {
        "PolicyInputList": [_load_policy(policy_file)],
        "ActionNames": actions,
        "ResourceArns": [resource],
        "ContextEntries": _context_entries(mfa),
    }
    if boundary_file:
        kwargs["PermissionsBoundaryPolicyInputList"] = [_load_policy(boundary_file)]
    try:
        resp = iam.simulate_custom_policy(**kwargs)
    except ClientError as e:
        print(f"[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    print(f"simulate_custom_policy ({'with boundary' if boundary_file else 'no boundary'}):")
    _print_results(resp["EvaluationResults"])
    return 0


def run_principal(session, principal_arn, actions, resource, mfa) -> int:
    iam = session.client("iam")
    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=actions,
            ResourceArns=[resource],
            ContextEntries=_context_entries(mfa),
        )
    except ClientError as e:
        print(f"[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    print(f"simulate_principal_policy for {principal_arn}:")
    _print_results(resp["EvaluationResults"])
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["custom", "principal"])
    p.add_argument("--policy", help="Policy JSON file (custom mode)")
    p.add_argument("--boundary", help="Permissions-boundary JSON file (custom mode)")
    p.add_argument("--principal-arn", help="Principal ARN (principal mode)")
    p.add_argument("--actions", required=True, help="Comma-separated action names")
    p.add_argument("--resource", default="*", help="Resource ARN to test against (default *)")
    p.add_argument("--mfa", action="store_true", help="Add aws:MultiFactorAuthPresent=true")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    args = p.parse_args()

    actions = [a.strip() for a in args.actions.split(",") if a.strip()]
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    if args.mode == "custom":
        if not args.policy:
            p.error("custom mode requires --policy")
        return run_custom(session, args.policy, args.boundary, actions, args.resource, args.mfa)
    if not args.principal_arn:
        p.error("principal mode requires --principal-arn")
    return run_principal(session, args.principal_arn, actions, args.resource, args.mfa)


if __name__ == "__main__":
    sys.exit(main())
