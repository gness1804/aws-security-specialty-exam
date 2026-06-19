#!/usr/bin/env python3
"""Custom AWS Config rule Lambda — flag SSH/RDP open to the world (scenario 3.2).

Read this *after* you've sketched the evaluation logic yourself (challenge B3.2).

Config invokes this function with an `invokingEvent` containing a security group's
configuration item. The function marks the group NON_COMPLIANT if any ingress
permission opens TCP 22 or 3389 to 0.0.0.0/0 (or ::/0), COMPLIANT otherwise, and
NOT_APPLICABLE for any non-security-group resource. It reports the result by
calling config:PutEvaluations with the event's ResultToken.

No secrets are handled or logged — only resource ids and the offending ports.
"""

import json
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SENSITIVE_PORTS = {22, 3389}
OPEN_CIDRS = {"0.0.0.0/0"}
OPEN_CIDRS_V6 = {"::/0"}


def _permission_is_open(perm: dict) -> bool:
    """True if this ingress permission exposes 22/3389 to the world."""
    from_port = perm.get("fromPort")
    to_port = perm.get("toPort")
    # A null port range means "all ports" — that covers 22 and 3389 too.
    covers_sensitive = (
        from_port is None
        or to_port is None
        or any(from_port <= p <= to_port for p in SENSITIVE_PORTS)
    )
    if not covers_sensitive:
        return False
    v4_open = any(r.get("cidrIp") in OPEN_CIDRS for r in perm.get("ipRanges", []))
    v6_open = any(r.get("cidrIpv6") in OPEN_CIDRS_V6 for r in perm.get("ipv6Ranges", []))
    return v4_open or v6_open


def evaluate_compliance(config_item: dict) -> str:
    """Return COMPLIANT / NON_COMPLIANT / NOT_APPLICABLE for one resource."""
    if config_item.get("resourceType") != "AWS::EC2::SecurityGroup":
        return "NOT_APPLICABLE"
    # A deleted resource can't be evaluated.
    if config_item.get("configurationItemStatus") in ("ResourceDeleted",):
        return "NOT_APPLICABLE"

    configuration = config_item.get("configuration", {})
    ingress = configuration.get("ipPermissions", [])
    for perm in ingress:
        if _permission_is_open(perm):
            logger.info(
                "SG %s NON_COMPLIANT: ports %s open to world",
                config_item.get("resourceId"),
                perm.get("fromPort"),
            )
            return "NON_COMPLIANT"
    return "COMPLIANT"


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    config_item = invoking_event["configurationItem"]
    compliance = evaluate_compliance(config_item)

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": config_item["resourceType"],
                "ComplianceResourceId": config_item["resourceId"],
                "ComplianceType": compliance,
                "OrderingTimestamp": config_item["configurationItemCaptureTime"],
            }
        ],
        ResultToken=event["resultToken"],
    )
    logger.info("Reported %s for %s", compliance, config_item.get("resourceId"))
    return compliance
