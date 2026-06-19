"""Shared Lambda-deploy helpers for the Phase 3 setup scripts.

Local-only (these run on your machine, not inside Lambda). Keeps the three
setup_* scripts DRY: zip a handler, create an execution role, create the function,
grant a service permission to invoke it, and tear it all down.

No secrets are handled here; nothing is printed except resource names/ids.
"""

import io
import json
import time
import zipfile
from pathlib import Path

from botocore.exceptions import ClientError

LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def build_zip(handler_path: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(handler_path, arcname=handler_path.name)
    return buf.getvalue()


def ensure_role(iam, role_name: str, policy_name: str, policy_doc: dict) -> str:
    """Create (or reuse) a Lambda execution role with one inline policy."""
    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST),
            Description="Phase 3 lab role",
        )
        arn = role["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )
    return arn


def create_lambda(
    lam,
    name: str,
    role_arn: str,
    handler_module: str,
    zip_bytes: bytes,
    env: dict | None = None,
    timeout: int = 30,
) -> str:
    """Create the function, retrying while the new role propagates."""
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": f"{handler_module}.lambda_handler",
        "Code": {"ZipFile": zip_bytes},
        "Timeout": timeout,
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    for _ in range(10):
        try:
            return lam.create_function(**kwargs)["FunctionArn"]
        except ClientError as e:
            # IAM role isn't propagated yet — retry a few times.
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def add_service_invoke(
    lam, name: str, statement_id: str, principal: str, source_arn: str | None = None
) -> None:
    kwargs = {
        "FunctionName": name,
        "StatementId": statement_id,
        "Action": "lambda:InvokeFunction",
        "Principal": principal,
    }
    if source_arn:
        kwargs["SourceArn"] = source_arn
    try:
        lam.add_permission(**kwargs)
    except lam.exceptions.ResourceConflictException:
        pass  # permission already present (idempotent re-run)


def delete_function_and_role(lam, iam, name: str, role_name: str, policy_name: str) -> None:
    for action in (
        lambda: lam.delete_function(FunctionName=name),
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            action()
        except ClientError as e:
            print(f"[warn] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
