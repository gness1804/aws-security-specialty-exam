#!/usr/bin/env python3
"""Audit an account for billable resources left running by the labs.

Read-only by default: lists the usual cost offenders (running EC2, ALBs, NAT
gateways, enabled GuardDuty/Config/Macie/Inspector, customer KMS keys, secrets)
and prints resource IDs/types only -- never any secret values. This is the
end-of-session sweep referenced in cost-safety.md.

Pass --apply to actually disable continuous-billing detectors (GuardDuty, Config
recorder, Macie). It will NOT delete data, terminate instances, or delete keys --
those you remove deliberately. Even with --apply it confirms per service.

Usage:
  python teardown_check.py --profile scs-member            # report only
  python teardown_check.py --profile scs-member --apply    # also disable detectors
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError


def safe(fn):
    """Run a describe call, swallowing 'not enabled / not subscribed' errors."""
    try:
        return fn()
    except ClientError as e:
        return {"_error": e.response["Error"]["Code"]}


def ids(resp: dict, list_key: str, id_key: str) -> list:
    """Pull a list of id_key values from resp[list_key]; [] if the call errored."""
    if "_error" in resp:
        return []
    return [item[id_key] for item in resp.get(list_key, [])]


def confirm(prompt: str) -> bool:
    return input(prompt).strip().lower() == "y"


def report(session) -> dict:
    out = {}
    ec2 = session.client("ec2")
    res = safe(
        lambda: ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
    )
    out["running_instances"] = (
        [i["InstanceId"] for r in res.get("Reservations", []) for i in r.get("Instances", [])]
        if "_error" not in res
        else []
    )

    # NOTE: describe_nat_gateways uses "Filter" (singular) -- an intentional EC2
    # API quirk, unlike describe_instances which uses "Filters". Do not "fix" it.
    nat = safe(
        lambda: ec2.describe_nat_gateways(
            Filter=[{"Name": "state", "Values": ["available", "pending"]}]
        )
    )
    out["nat_gateways"] = ids(nat, "NatGateways", "NatGatewayId")

    elb = session.client("elbv2")
    lbs = safe(lambda: elb.describe_load_balancers())
    out["load_balancers"] = ids(lbs, "LoadBalancers", "LoadBalancerArn")

    gd = session.client("guardduty")
    dets = safe(lambda: gd.list_detectors())
    out["guardduty_detectors"] = dets.get("DetectorIds", []) if "_error" not in dets else []

    cfg = session.client("config")
    recs = safe(lambda: cfg.describe_configuration_recorder_status())
    out["config_recorders_recording"] = (
        [r["name"] for r in recs.get("ConfigurationRecordersStatus", []) if r.get("recording")]
        if "_error" not in recs
        else []
    )

    macie = session.client("macie2")
    mst = safe(lambda: macie.get_macie_session())
    out["macie_enabled"] = (mst.get("status") == "ENABLED") if "_error" not in mst else False

    kms = session.client("kms")
    keys = safe(lambda: kms.list_keys())
    # Only customer keys cost money; we can't cheaply filter AWS-managed here, so
    # we just count and let you inspect. Print IDs, never key material.
    out["kms_key_ids"] = ids(keys, "Keys", "KeyId")

    sm = session.client("secretsmanager")
    secs = safe(lambda: sm.list_secrets())
    out["secret_names"] = ids(secs, "SecretList", "Name")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", default=None)
    p.add_argument(
        "--apply",
        action="store_true",
        help="Disable detectors (GuardDuty/Config/Macie). Confirms per service.",
    )
    args = p.parse_args()

    session = boto3.Session(profile_name=args.profile)
    data = report(session)

    print("=== Billable-resource sweep (IDs only, no secrets) ===")
    for k, v in data.items():
        print(f"  {k}: {v}")

    if not args.apply:
        print("\n[report-only] Re-run with --apply to disable GuardDuty/Config/Macie detectors.")
        print("Terminate instances, delete ALBs/NAT GWs, and schedule KMS key deletion MANUALLY.")
        return 0

    # Disabling actions, each confirmed.
    if data["guardduty_detectors"] and confirm("Suspend GuardDuty detector(s)? [y/N] "):
        gd = session.client("guardduty")
        for d in data["guardduty_detectors"]:
            # Suspend (reversible, stops billing) rather than delete_detector
            # (permanent, wipes config) -- you re-enable in Phase 4.
            gd.update_detector(DetectorId=d, Enable=False)
            print(f"  suspended GuardDuty detector {d}")
    if data["config_recorders_recording"] and confirm("Stop Config recorder(s)? [y/N] "):
        cfg = session.client("config")
        for name in data["config_recorders_recording"]:
            cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
            print(f"  stopped Config recorder {name}")
    if data["macie_enabled"] and confirm("Disable Macie? [y/N] "):
        session.client("macie2").disable_macie()
        print("  disabled Macie")

    print("\nDone. Instances, ALBs, NAT GWs, KMS keys, and secrets are left for manual removal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
