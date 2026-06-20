#!/usr/bin/env python3
"""Stand up Athena tables over CloudTrail (+ Flow Logs) and run a query (scenario 4.4).

Creates the `security_audit` database and a partition-projected CloudTrail external
table pointing at your trail's S3 prefix, then (optionally) runs the "denied API
calls today" query so you can see results and the data-scanned figure. The full DDL
reference, including the Flow Logs table, lives in athena_security_queries.sql.

Athena needs a query-results S3 location (--results-bucket); it's created if absent.
Creating actions are gated behind --apply (default: dry run). --teardown drops the
tables and database (it never touches the source CloudTrail/Flow-Log data in S3).
No secrets are handled or printed -- bucket names, table names, and row counts only.

Usage:
  python setup_athena_security.py --cloudtrail-bucket scs-trail-<ACCT> \
      --results-bucket scs-athena-<ACCT> --profile scs-member            # dry run
  python setup_athena_security.py --cloudtrail-bucket scs-trail-<ACCT> \
      --results-bucket scs-athena-<ACCT> --profile scs-member --apply --run-query
  python setup_athena_security.py --results-bucket scs-athena-<ACCT> \
      --profile scs-member --teardown --apply
"""

import argparse
import re
import sys
import time

import boto3
from botocore.exceptions import ClientError

DATABASE = "security_audit"
TABLE = "cloudtrail_logs"

# The DDL/queries are string-built from these args, so validate them before they're
# interpolated into Athena SQL (defense against DDL injection from a bad arg).
_BUCKET_RE = re.compile(r"^[a-z0-9.-]{3,63}$")
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d$")


def _validate(bucket: str, region: str) -> str | None:
    if not _BUCKET_RE.match(bucket):
        return f"invalid bucket name: {bucket!r}"
    if not _REGION_RE.match(region):
        return f"invalid region: {region!r}"
    return None


def _ddl(bucket: str, account: str, region: str) -> str:
    base = f"s3://{bucket}/AWSLogs/{account}/CloudTrail/"
    template = f"{base}${{region}}/${{dt}}/"
    return f"""
CREATE EXTERNAL TABLE IF NOT EXISTS {DATABASE}.{TABLE} (
    eventversion STRING,
    useridentity STRUCT<type:STRING, principalid:STRING, arn:STRING,
        accountid:STRING, username:STRING, invokedby:STRING,
        sessioncontext:STRUCT<attributes:STRUCT<mfaauthenticated:STRING, creationdate:STRING>>>,
    eventtime STRING, eventsource STRING, eventname STRING, awsregion STRING,
    sourceipaddress STRING, useragent STRING, errorcode STRING, errormessage STRING,
    requestparameters STRING, responseelements STRING, eventtype STRING,
    recipientaccountid STRING
)
PARTITIONED BY (region STRING, dt STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION '{base}'
TBLPROPERTIES (
    'projection.enabled'='true',
    'projection.region.type'='enum',
    'projection.region.values'='{region}',
    'projection.dt.type'='date',
    'projection.dt.range'='2026/01/01,NOW',
    'projection.dt.format'='yyyy/MM/dd',
    'storage.location.template'='{template}'
)
""".strip()


_DENIED_CODES = (
    "'AccessDenied','AccessDeniedException','UnauthorizedOperation','Client.UnauthorizedOperation'"
)
DENIED_QUERY = f"""
SELECT eventtime, useridentity.arn AS principal, eventname, sourceipaddress, errorcode
FROM {DATABASE}.{TABLE}
WHERE dt = date_format(current_date, '%Y/%m/%d')
  AND errorcode IN ({_DENIED_CODES})
ORDER BY eventtime DESC
LIMIT 100
""".strip()


def _ensure_bucket(s3, bucket: str, region: str) -> None:
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        kwargs = {"Bucket": bucket}
        if region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**kwargs)


def _run(athena, sql: str, output: str) -> dict:
    """Run a statement and block until it finishes; return the execution detail."""
    qid = athena.start_query_execution(
        QueryString=sql, ResultConfiguration={"OutputLocation": output}
    )["QueryExecutionId"]
    while True:
        ex = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = ex["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return ex
        time.sleep(2)


def build(
    session: boto3.Session,
    region: str,
    account: str,
    ct_bucket: str,
    results_bucket: str,
    run_query: bool,
    apply: bool,
) -> int:
    print("Plan:")
    for s in (
        f"ensure Athena results bucket {results_bucket}",
        f"create database {DATABASE}",
        f"create projected table {DATABASE}.{TABLE} over the CloudTrail prefix in {ct_bucket}",
        ("run the denied-API-calls query" if run_query else "skip query (pass --run-query)"),
    ):
        print("  -", s)
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0
    if not ct_bucket or not results_bucket:
        print("[error] --cloudtrail-bucket and --results-bucket are required with --apply")
        return 1
    err = _validate(ct_bucket, region) or _validate(results_bucket, region)
    if err:
        print(f"[error] {err}")
        return 1

    output = f"s3://{results_bucket}/athena-results/"
    s3 = session.client("s3")
    athena = session.client("athena")
    try:
        _ensure_bucket(s3, results_bucket, region)
        _run(athena, f"CREATE DATABASE IF NOT EXISTS {DATABASE}", output)
        print(f"[ok] database {DATABASE} ready")
        ex = _run(athena, _ddl(ct_bucket, account, region), output)
        if ex["Status"]["State"] != "SUCCEEDED":
            print(f"[error] table DDL failed: {ex['Status'].get('StateChangeReason')}")
            return 1
        print(f"[ok] table {DATABASE}.{TABLE} created")

        if run_query:
            ex = _run(athena, DENIED_QUERY, output)
            if ex["Status"]["State"] != "SUCCEEDED":
                print(f"[error] query failed: {ex['Status'].get('StateChangeReason')}")
                return 1
            scanned = ex.get("Statistics", {}).get("DataScannedInBytes", 0)
            print(f"[ok] denied-API query ran; data scanned: {scanned / 1024:.1f} KiB")
            print(f"     results in {output} (open in the Athena console to view rows)")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, results_bucket: str, apply: bool) -> int:
    print(f"Plan: drop {DATABASE}.{TABLE} and database {DATABASE} (source data untouched)")
    if not apply:
        print("\n[dry-run] Re-run with --teardown --apply.")
        return 0
    if not results_bucket:
        print("[error] --results-bucket is required with --teardown --apply")
        return 1
    output = f"s3://{results_bucket}/athena-results/"
    athena = session.client("athena")
    for sql in (
        f"DROP TABLE IF EXISTS {DATABASE}.{TABLE}",
        f"DROP DATABASE IF EXISTS {DATABASE}",
    ):
        try:
            _run(athena, sql, output)
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    print("[ok] dropped. Delete the Athena results bucket manually if you want it gone.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cloudtrail-bucket", default=None, help="Bucket holding CloudTrail logs")
    p.add_argument("--results-bucket", default=None, help="Bucket for Athena query results")
    p.add_argument("--run-query", action="store_true", help="Also run the denied-API query")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--teardown", action="store_true")
    args = p.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.teardown:
        return teardown(session, args.results_bucket, args.apply)
    account = session.client("sts").get_caller_identity()["Account"]
    return build(
        session,
        args.region,
        account,
        args.cloudtrail_bucket,
        args.results_bucket,
        args.run_query,
        args.apply,
    )


if __name__ == "__main__":
    sys.exit(main())
