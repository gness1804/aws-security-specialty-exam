#!/usr/bin/env python3
"""Create a Config aggregator (+ optional conformance pack) (scenario 5.2).

Default mode builds a SINGLE-account aggregator over all regions (runs in
scs-member), so the lab works without org plumbing. Pass --org with --role-arn to
build an ORGANIZATION aggregator from the management/delegated-admin account.
Optionally deploy the sample conformance pack with --conformance-pack.

Creating actions are gated behind --apply (default: dry run). --teardown removes the
aggregator and (if present) the conformance pack. No secrets are handled or printed
-- aggregator/pack names, account ids, and ARNs only.

Usage:
  python setup_config_aggregator.py --profile scs-member                         # dry run
  python setup_config_aggregator.py --profile scs-member --apply --conformance-pack
  python setup_config_aggregator.py --org --role-arn <ROLE_ARN> --profile scs-mgmt --apply
  python setup_config_aggregator.py --profile scs-member --teardown --apply
"""

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

AGGREGATOR_NAME = "scs-phase5-aggregator"
PACK_NAME = "scs-phase5-pack"
PACK_TEMPLATE = Path(__file__).parents[2] / "policies/phase-5/5.2-conformance-pack.yaml"


def build(
    session: boto3.Session,
    account: str,
    org: bool,
    role_arn: str | None,
    pack: bool,
    apply: bool,
) -> int:
    mode = "ORGANIZATION" if org else "single-account (all regions)"
    print("Plan:")
    print(f"  - create {mode} aggregator {AGGREGATOR_NAME}")
    if pack:
        print(f"  - deploy conformance pack {PACK_NAME} from {PACK_TEMPLATE.name}")
    if org and not role_arn:
        print("  [error] --org requires --role-arn (role Config assumes for org details)")
        return 1
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    config = session.client("config")
    try:
        if org:
            config.put_configuration_aggregator(
                ConfigurationAggregatorName=AGGREGATOR_NAME,
                OrganizationAggregationSource={"RoleArn": role_arn, "AllAwsRegions": True},
            )
        else:
            config.put_configuration_aggregator(
                ConfigurationAggregatorName=AGGREGATOR_NAME,
                AccountAggregationSources=[{"AccountIds": [account], "AllAwsRegions": True}],
            )
        print(f"[ok] aggregator {AGGREGATOR_NAME} created ({mode})")

        if pack:
            config.put_conformance_pack(
                ConformancePackName=PACK_NAME,
                TemplateBody=PACK_TEMPLATE.read_text(),
            )
            print(f"[ok] conformance pack {PACK_NAME} deploying (evaluation takes a few min)")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, apply: bool) -> int:
    print(f"Plan: delete conformance pack {PACK_NAME} + aggregator {AGGREGATOR_NAME}")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    config = session.client("config")
    for action in (
        lambda: config.delete_conformance_pack(ConformancePackName=PACK_NAME),
        lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=AGGREGATOR_NAME),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    print("[ok] teardown complete.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--org", action="store_true", help="Build an organization aggregator")
    p.add_argument("--role-arn", default=None, help="Role ARN Config assumes (org mode)")
    p.add_argument("--conformance-pack", action="store_true", help="Also deploy the sample pack")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.apply)
    account = session.client("sts").get_caller_identity()["Account"]
    return build(session, account, args.org, args.role_arn, args.conformance_pack, args.apply)


if __name__ == "__main__":
    sys.exit(main())
