#!/usr/bin/env python3
"""Create a WAF v2 Web ACL (SQLi + XSS) and associate it with an ALB (scenario 4.1).

Builds a REGIONAL Web ACL with default action Allow, two AWS managed rule groups
(common set -> XSS, SQLi set), and one custom XssMatchStatement on the query string
with URL_DECODE + HTML_ENTITY_DECODE transformations, then associates it with the
ALB ARN you pass. Creating actions are gated behind --apply (default: dry run).
--teardown disassociates and deletes the Web ACL.

The rule definitions mirror policies/phase-4/4.1-webacl-rules.json. WAF for an ALB
uses scope REGIONAL in the ALB's region (CloudFront would use scope CLOUDFRONT in
us-east-1). No secrets are handled or printed -- ARNs and names only.

Usage:
  python setup_waf_alb.py --alb-arn <ARN> --profile scs-member            # dry run
  python setup_waf_alb.py --alb-arn <ARN> --profile scs-member --apply
  python setup_waf_alb.py --alb-arn <ARN> --profile scs-member --teardown --apply
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

WEB_ACL_NAME = "scs-phase4-web-acl"
SCOPE = "REGIONAL"

RULES = [
    {
        "Name": "AWS-CommonRuleSet",
        "Priority": 0,
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        },
        "OverrideAction": {"None": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "AWSCommonRuleSet",
        },
    },
    {
        "Name": "AWS-SQLiRuleSet",
        "Priority": 1,
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesSQLiRuleSet",
            }
        },
        "OverrideAction": {"None": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "AWSSQLiRuleSet",
        },
    },
    {
        "Name": "Custom-XSS-QueryString",
        "Priority": 2,
        "Statement": {
            "XssMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 1, "Type": "HTML_ENTITY_DECODE"},
                ],
            }
        },
        "Action": {"Block": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "CustomXSSQueryString",
        },
    },
]

ACL_VISIBILITY = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": WEB_ACL_NAME,
}


def _find_web_acl(waf) -> dict | None:
    for acl in waf.list_web_acls(Scope=SCOPE).get("WebACLs", []):
        if acl["Name"] == WEB_ACL_NAME:
            return acl
    return None


def build(session: boto3.Session, alb_arn: str, apply: bool) -> int:
    print("Plan: create Web ACL (default Allow) + 2 managed groups + 1 custom XSS rule")
    print(f"  name={WEB_ACL_NAME}, scope={SCOPE}, rules={[r['Name'] for r in RULES]}")
    print(f"  associate -> {alb_arn}")
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0
    if not alb_arn:
        print("[error] --alb-arn is required with --apply")
        return 1

    waf = session.client("wafv2")
    try:
        existing = _find_web_acl(waf)
        if existing:
            acl_arn = existing["ARN"]
            print(f"[ok] reusing existing Web ACL {WEB_ACL_NAME}")
        else:
            acl_arn = waf.create_web_acl(
                Name=WEB_ACL_NAME,
                Scope=SCOPE,
                DefaultAction={"Allow": {}},
                Rules=RULES,
                VisibilityConfig=ACL_VISIBILITY,
                Description="Phase 4: SQLi/XSS protection for the lab ALB",
            )["Summary"]["ARN"]
            print(f"[ok] created Web ACL {WEB_ACL_NAME}")
        waf.associate_web_acl(WebAclArn=acl_arn, ResourceArn=alb_arn)
        print(f"[ok] associated Web ACL with {alb_arn}")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, alb_arn: str, apply: bool) -> int:
    print("Plan: disassociate Web ACL from ALB, then delete the Web ACL")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    waf = session.client("wafv2")
    try:
        if alb_arn:
            try:
                waf.disassociate_web_acl(ResourceArn=alb_arn)
                print(f"[ok] disassociated from {alb_arn}")
            except ClientError as e:
                print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        acl = _find_web_acl(waf)
        if not acl:
            print("[ok] no Web ACL to delete")
            return 0
        # delete_web_acl needs the current LockToken to prevent concurrent edits.
        detail = waf.get_web_acl(Name=WEB_ACL_NAME, Scope=SCOPE, Id=acl["Id"])
        waf.delete_web_acl(
            Name=WEB_ACL_NAME, Scope=SCOPE, Id=acl["Id"], LockToken=detail["LockToken"]
        )
        print(f"[ok] deleted Web ACL {WEB_ACL_NAME}")
    except ClientError as e:
        print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--alb-arn", default=None, help="ARN of the ALB to protect")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.alb_arn, args.apply)
    return build(session, args.alb_arn, args.apply)


if __name__ == "__main__":
    sys.exit(main())
