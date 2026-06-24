#!/usr/bin/env python3
"""Stand up the Phase 2 rotation demo: secret + rotation Lambda + rotation schedule.

Creates a demo secret, packages secrets_rotation_lambda.py into a Lambda function
with a least-privilege execution role, grants Secrets Manager permission to invoke
it, and enables 30-day rotation. Everything destructive/creating is gated behind
--apply; the default is a dry run that prints the plan only. No secret value is
ever printed — the initial password is generated with GetRandomPassword and passed
straight into create_secret.

Usage:
  python setup_secret_rotation.py --profile scs-member               # dry run
  python setup_secret_rotation.py --profile scs-member --apply       # build it
  python setup_secret_rotation.py --profile scs-member --teardown --apply
"""

import argparse
import io
import json
import sys
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

SECRET_ID = "scs/phase2/demo"
FUNCTION_NAME = "scs-phase2-rotation"
ROLE_NAME = "scs-phase2-rotation-role"
HANDLER_FILE = Path(__file__).with_name("secrets_rotation_lambda.py")

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def execution_policy(region: str, account: str) -> dict:
    secret_arn = f"arn:aws:secretsmanager:{region}:{account}:secret:{SECRET_ID}-*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SecretAccess",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                ],
                "Resource": secret_arn,
            },
            {
                "Sid": "RandomPassword",
                "Effect": "Allow",
                "Action": "secretsmanager:GetRandomPassword",
                "Resource": "*",
            },
            {
                "Sid": "Logs",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
    }


def _zip_handler() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Lambda expects the module at the root; handler = "<module>.lambda_handler".
        zf.write(HANDLER_FILE, arcname="secrets_rotation_lambda.py")
    return buf.getvalue()


def build(session: boto3.Session, region: str, account: str, apply: bool) -> int:
    sm = session.client("secretsmanager")
    iam = session.client("iam")
    lam = session.client("lambda")

    plan = [
        f"create secret {SECRET_ID} (initial password via GetRandomPassword, not printed)",
        f"create IAM role {ROLE_NAME} + inline execution policy",
        f"create Lambda {FUNCTION_NAME} from secrets_rotation_lambda.py",
        f"add_permission: allow secretsmanager.amazonaws.com to invoke {FUNCTION_NAME}",
        f"rotate-secret: enable 30-day rotation on {SECRET_ID}",
    ]
    print("Plan:")
    for step in plan:
        print(f"  - {step}")
    if not apply:
        print("\n[dry-run] Nothing created. Re-run with --apply.")
        return 0

    try:
        # 1. Secret — initial value generated and passed without printing.
        init_password = sm.get_random_password(ExcludeCharacters="/@\"'\\")["RandomPassword"]
        sm.create_secret(
            Name=SECRET_ID,
            SecretString=json.dumps({"username": "app", "password": init_password}),
            Description="Phase 2 rotation demo (no real backend)",
        )
        print(f"[ok] created secret {SECRET_ID}")

        # 2. Execution role.
        role = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
            Description="Phase 2 rotation Lambda execution role",
        )
        iam.put_role_policy(
            RoleName=ROLE_NAME,
            PolicyName="rotation-exec",
            PolicyDocument=json.dumps(execution_policy(region, account)),
        )
        role_arn = role["Role"]["Arn"]
        print(f"[ok] created role {ROLE_NAME}")

        # 3. Lambda function.
        fn = lam.create_function(
            FunctionName=FUNCTION_NAME,
            Runtime="python3.12",
            Role=role_arn,
            Handler="secrets_rotation_lambda.lambda_handler",
            Code={"ZipFile": _zip_handler()},
            Timeout=30,
            Description="Phase 2 Secrets Manager rotation demo",
        )
        fn_arn = fn["FunctionArn"]
        print(f"[ok] created function {FUNCTION_NAME}")

        # 4. Resource policy so Secrets Manager can invoke it. SourceAccount scopes
        #    the grant to this account (confused-deputy guard) so a Secrets Manager
        #    principal in another account can't trigger this rotation function.
        lam.add_permission(
            FunctionName=FUNCTION_NAME,
            StatementId="SecretsManagerInvoke",
            Action="lambda:InvokeFunction",
            Principal="secretsmanager.amazonaws.com",
            SourceAccount=account,
        )
        print("[ok] granted secretsmanager.amazonaws.com invoke permission (SourceAccount-scoped)")

        # 5. Enable rotation.
        sm.rotate_secret(
            SecretId=SECRET_ID,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
        )
        print("[ok] enabled 30-day rotation")
    except ClientError as e:
        print(f"\n[error] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return 1
    return 0


def teardown(session: boto3.Session, apply: bool) -> int:
    print("Plan: delete Lambda, IAM role, and secret (force, no recovery window)")
    if not apply:
        print("\n[dry-run] Nothing deleted. Re-run with --teardown --apply.")
        return 0
    lam = session.client("lambda")
    iam = session.client("iam")
    sm = session.client("secretsmanager")
    for action in (
        lambda: lam.delete_function(FunctionName=FUNCTION_NAME),
        lambda: iam.delete_role_policy(RoleName=ROLE_NAME, PolicyName="rotation-exec"),
        lambda: iam.delete_role(RoleName=ROLE_NAME),
        lambda: sm.delete_secret(SecretId=SECRET_ID, ForceDeleteWithoutRecovery=True),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    print("[ok] teardown complete")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", default=None, help="AWS named profile (Account B)")
    p.add_argument("--region", default="us-east-1", help="Region (must match secret)")
    p.add_argument("--apply", action="store_true", help="Actually act (default: dry run)")
    p.add_argument("--teardown", action="store_true", help="Delete the demo resources")
    args = p.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]

    if args.teardown:
        return teardown(session, args.apply)
    return build(session, args.region, account, args.apply)


if __name__ == "__main__":
    sys.exit(main())
