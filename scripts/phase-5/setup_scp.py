#!/usr/bin/env python3
"""Create + attach the four Phase 5.1 Service Control Policies (scenario 5.1).

Loads the four SCP JSON files from policies/phase-5/, creates each as an
Organizations SCP, and attaches them to a TARGET OU you name. Run from the
MANAGEMENT account (org APIs live there). Creating actions are gated behind --apply
(default: dry run). --teardown detaches and deletes them.

SAFETY: this refuses to attach to the org ROOT (an id like "r-xxxx") unless you pass
--i-understand-root, because a deny SCP on the root hits every account at once. SCPs
never restrict the management account, so you can always recover from there. Attach
to a dedicated LAB OU containing only the member account.

No secrets are handled or printed -- policy names, ids, and the target id only.

Usage:
  python setup_scp.py --target-ou ou-1234-abcd5678 --profile scs-mgmt            # dry run
  python setup_scp.py --target-ou ou-1234-abcd5678 --profile scs-mgmt --apply
  python setup_scp.py --target-ou ou-1234-abcd5678 --profile scs-mgmt --teardown --apply
"""

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

POLICY_DIR = Path(__file__).parents[2] / "policies/phase-5"

# (display name, Organizations policy name, JSON file)
POLICIES = [
    ("region lock", "scs-region-lock", "5.1-scp-region-lock.json"),
    ("protect detectives", "scs-protect-detectives", "5.1-scp-protect-detectives.json"),
    ("require MFA", "scs-require-mfa", "5.1-scp-require-mfa.json"),
    ("deny root", "scs-deny-root", "5.1-scp-deny-root.json"),
]


def _load_content(filename: str) -> str:
    raw = json.loads((POLICY_DIR / filename).read_text())
    raw.pop("_comment", None)
    return json.dumps(raw)


def _find_policy_id(org, name: str) -> str | None:
    paginator = org.get_paginator("list_policies")
    for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
        for pol in page["Policies"]:
            if pol["Name"] == name:
                return pol["Id"]
    return None


def build(session: boto3.Session, target: str, apply: bool) -> int:
    print(f"Plan: create + attach {len(POLICIES)} SCPs to target {target}")
    for disp, name, fn in POLICIES:
        print(f"  - {name} ({disp}) from {fn}")
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    org = session.client("organizations")
    try:
        for disp, name, fn in POLICIES:
            content = _load_content(fn)
            pid = _find_policy_id(org, name)
            if pid is None:
                pid = org.create_policy(
                    Type="SERVICE_CONTROL_POLICY",
                    Name=name,
                    Description=f"Phase 5.1 lab SCP: {disp}",
                    Content=content,
                )["Policy"]["PolicySummary"]["Id"]
                print(f"[ok] created {name} ({pid})")
            else:
                print(f"[ok] reusing existing {name} ({pid})")
            try:
                org.attach_policy(PolicyId=pid, TargetId=target)
                print(f"[ok] attached {name} -> {target}")
            except org.exceptions.DuplicatePolicyAttachmentException:
                print(f"[ok] {name} already attached to {target}")
    except org.exceptions.PolicyTypeNotEnabledException:
        print(
            "[error] SCPs are not enabled for this org. Enable the "
            "SERVICE_CONTROL_POLICY policy type on the org root first "
            "(Organizations console, or organizations enable-policy-type)."
        )
        return 1
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, target: str, apply: bool) -> int:
    print(f"Plan: detach + delete {len(POLICIES)} SCPs from target {target}")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    org = session.client("organizations")
    for _disp, name, _fn in POLICIES:
        pid = _find_policy_id(org, name)
        if pid is None:
            print(f"[ok] {name} not present")
            continue
        try:
            org.detach_policy(PolicyId=pid, TargetId=target)
        except ClientError as e:
            print(f"[warn] detach {name}: {e.response['Error']['Code']}")
        try:
            org.delete_policy(PolicyId=pid)
            print(f"[ok] deleted {name}")
        except ClientError as e:
            print(f"[warn] delete {name}: {e.response['Error']['Code']}")
    print("[ok] teardown complete. Confirm the member account's access is restored.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target-ou", required=True, help="OU id to attach to (ou-xxxx-xxxx)")
    p.add_argument(
        "--i-understand-root",
        action="store_true",
        help="Allow attaching to the org ROOT (r-xxxx) -- dangerous, hits every account",
    )
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()

    if args.target_ou.startswith("r-") and not args.i_understand_root:
        print(
            "[error] refusing to target the org ROOT — this would hit every account. "
            "Attach to a lab OU, or pass --i-understand-root if you truly mean it."
        )
        return 1
    if not args.target_ou.startswith("ou-"):
        # Account ids and OU-parents are valid SCP targets, but a lab should attach to
        # a dedicated child OU. Warn so a wide-blast-radius target isn't used by accident.
        print(
            f"[warn] target {args.target_ou} is not an OU id (ou-xxxx-xxxx). "
            "Prefer a dedicated lab OU so the guardrail's blast radius is contained."
        )

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.target_ou, args.apply)
    return build(session, args.target_ou, args.apply)


if __name__ == "__main__":
    sys.exit(main())
