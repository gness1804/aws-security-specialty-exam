-- Phase 4.4 — Athena security queries over CloudTrail + VPC Flow Logs.
-- These are query STARTERS for the B4.4 / D4.4 challenges. Read after you've
-- sketched the queries yourself. Replace <...> placeholders. The CREATE TABLE
-- statements use partition projection so a dated query scans only that day's
-- objects (Athena bills per TB scanned -- partitioning is the cost lever).
--
-- setup_athena_security.py creates the database + these tables for you; this file
-- is the human-readable reference and the source the script reads its DDL from.

-- ============================================================================
-- 1. CloudTrail external table (partition projection on region + date)
-- ============================================================================
CREATE EXTERNAL TABLE IF NOT EXISTS security_audit.cloudtrail_logs (
    eventversion      STRING,
    useridentity      STRUCT<
        type:STRING, principalid:STRING, arn:STRING, accountid:STRING,
        username:STRING, invokedby:STRING,
        sessioncontext:STRUCT<attributes:STRUCT<mfaauthenticated:STRING, creationdate:STRING>>>,
    eventtime         STRING,
    eventsource       STRING,
    eventname         STRING,
    awsregion         STRING,
    sourceipaddress   STRING,
    useragent         STRING,
    errorcode         STRING,
    errormessage      STRING,
    requestparameters STRING,
    responseelements  STRING,
    eventtype         STRING,
    recipientaccountid STRING
)
PARTITIONED BY (region STRING, dt STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION 's3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.region.type' = 'enum',
    'projection.region.values' = 'us-east-1,us-west-2',
    'projection.dt.type' = 'date',
    'projection.dt.range' = '2026/01/01,NOW',
    'projection.dt.format' = 'yyyy/MM/dd',
    'storage.location.template' =
        's3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/${region}/${dt}/'
);

-- B4.4 #2 — every denied API call in the last day: who, what, from where.
SELECT eventtime,
       useridentity.arn AS principal,
       eventname,
       sourceipaddress,
       errorcode
FROM security_audit.cloudtrail_logs
WHERE dt = date_format(current_date, '%Y/%m/%d')        -- partition predicate (cheap)
  AND errorcode IN ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'Client.UnauthorizedOperation')
ORDER BY eventtime DESC
LIMIT 100;

-- Any root usage (pairs with the 4.5 metric filter; here it's the query/pull view).
SELECT eventtime, eventname, sourceipaddress, awsregion
FROM security_audit.cloudtrail_logs
WHERE dt = date_format(current_date, '%Y/%m/%d')
  AND useridentity.type = 'Root'
  AND eventtype != 'AwsServiceEvent'
ORDER BY eventtime DESC;

-- D4.4 #1 — the EXPENSIVE version: no partition predicate, scans the whole prefix.
-- Run this, note "Data scanned", then compare to the dated query above.
SELECT count(*)
FROM security_audit.cloudtrail_logs
WHERE errorcode = 'AccessDenied';

-- ============================================================================
-- 2. VPC Flow Logs external table (default text format, v2 fields)
-- ============================================================================
CREATE EXTERNAL TABLE IF NOT EXISTS security_audit.vpc_flow_logs (
    version       INT,
    account_id    STRING,
    interface_id  STRING,
    srcaddr       STRING,
    dstaddr       STRING,
    srcport       INT,
    dstport       INT,
    protocol      BIGINT,
    packets       BIGINT,
    bytes         BIGINT,
    start         BIGINT,
    `end`         BIGINT,
    action        STRING,
    log_status    STRING
)
PARTITIONED BY (dt STRING)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '
LOCATION 's3://<FLOWLOG_BUCKET>/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/<REGION>/'
TBLPROPERTIES (
    'skip.header.line.count' = '1',
    'projection.enabled' = 'true',
    'projection.dt.type' = 'date',
    'projection.dt.range' = '2026/01/01,NOW',
    'projection.dt.format' = 'yyyy/MM/dd',
    'storage.location.template' =
        's3://<FLOWLOG_BUCKET>/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/<REGION>/${dt}/'
);

-- B4.4 #3 — top source IPs whose traffic was REJECTed (port-scan signal: one
-- srcaddr hitting many distinct dstports).
SELECT srcaddr,
       count(*)                 AS rejected_flows,
       count(DISTINCT dstport)  AS distinct_ports
FROM security_audit.vpc_flow_logs
WHERE dt = date_format(current_date, '%Y/%m/%d')
  AND action = 'REJECT'
GROUP BY srcaddr
ORDER BY rejected_flows DESC
LIMIT 50;
