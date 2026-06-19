#!/usr/bin/env python3
"""GuardDuty-triggered NACL block Lambda (scenario 3.3).

Read this *after* you've sketched the logic yourself (challenge B3.3).

EventBridge invokes this function on a GuardDuty Finding. It extracts the remote
attacker IPv4 from the finding, then adds a *deny* ingress entry for that /32 to
the configured subnet NACL — idempotently (it skips IPs already denied) and using
a deterministic free rule number to avoid collisions.

Config via environment variables:
  NACL_ID        the network ACL to add deny entries to (e.g. acl-0123...)
  BASE_RULE_NUM  starting NACL rule number for managed denies (default 100)
  IGNORE_SAMPLE  if "true" (the safe default), [SAMPLE] findings are logged and
                 skipped. The lab's setup script deploys "false" on purpose so the
                 create-sample-findings drill actually exercises the NACL block.

No secrets are handled or logged — only the attacker IP and the NACL entry added.
"""

import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

NACL_ID = os.environ.get("NACL_ID", "")
BASE_RULE_NUM = int(os.environ.get("BASE_RULE_NUM", "100"))
IGNORE_SAMPLE = os.environ.get("IGNORE_SAMPLE", "true").lower() == "true"
# NACL deny rules occupy [BASE_RULE_NUM, MANAGED_CEILING). Stay well under the
# 32766 max and below any allow rules you keep at higher numbers.
MANAGED_CEILING = BASE_RULE_NUM + 20


def extract_attacker_ip(finding: dict) -> str | None:
    """Pull the remote IPv4 from the finding's action block, if present."""
    action = finding.get("service", {}).get("action", {})
    for key in (
        "networkConnectionAction",
        "awsApiCallAction",
        "portProbeAction",
        "kubernetesApiCallAction",
    ):
        block = action.get(key, {})
        remote = block.get("remoteIpDetails")
        if remote and remote.get("ipAddressV4"):
            return remote["ipAddressV4"]
        # portProbeAction nests details in a list of probes.
        for probe in block.get("portProbeDetails", []) or []:
            ip = probe.get("remoteIpDetails", {}).get("ipAddressV4")
            if ip:
                return ip
    return None


def _existing_denies(ec2) -> tuple[set, set]:
    """Return (already-denied CIDRs, used rule numbers) for the managed range."""
    acl = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])["NetworkAcls"][0]
    denied_cidrs = set()
    used_numbers = set()
    for entry in acl["Entries"]:
        if entry["Egress"]:
            continue
        num = entry["RuleNumber"]
        if BASE_RULE_NUM <= num < MANAGED_CEILING:
            used_numbers.add(num)
            if entry.get("RuleAction") == "deny":
                denied_cidrs.add(entry.get("CidrBlock"))
    return denied_cidrs, used_numbers


def block_ip(ec2, ip: str) -> bool:
    """Add a deny entry for ip/32 if not already present. Returns True if added."""
    cidr = f"{ip}/32"
    denied, used = _existing_denies(ec2)
    if cidr in denied:
        logger.info("IP %s already denied in %s; no-op", ip, NACL_ID)
        return False
    rule_number = next((n for n in range(BASE_RULE_NUM, MANAGED_CEILING) if n not in used), None)
    if rule_number is None:
        logger.error("No free managed NACL rule numbers in %s; consider a WAF IP set", NACL_ID)
        return False
    ec2.create_network_acl_entry(
        NetworkAclId=NACL_ID,
        RuleNumber=rule_number,
        Protocol="-1",
        RuleAction="deny",
        Egress=False,
        CidrBlock=cidr,
    )
    logger.info("Added deny for %s as rule %s in %s", cidr, rule_number, NACL_ID)
    return True


def lambda_handler(event, context):
    finding = event.get("detail", {})
    title = finding.get("title", "")
    if IGNORE_SAMPLE and (
        "[SAMPLE]" in title or finding.get("service", {}).get("additionalInfo", {}).get("sample")
    ):
        logger.info("Sample finding received; logging only, not blocking")
        return {"blocked": False, "reason": "sample"}
    if not NACL_ID:
        raise ValueError("NACL_ID environment variable is not set")

    ip = extract_attacker_ip(finding)
    if not ip:
        logger.info("No remote IPv4 in finding type=%s; nothing to block", finding.get("type"))
        return {"blocked": False, "reason": "no-ip"}

    ec2 = boto3.client("ec2")
    added = block_ip(ec2, ip)
    return {"blocked": added, "ip": ip}
