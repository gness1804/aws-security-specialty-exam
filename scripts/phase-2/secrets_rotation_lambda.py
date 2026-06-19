#!/usr/bin/env python3
"""Reference Secrets Manager rotation Lambda — the four-step contract.

Read this *after* you've sketched the four steps yourself (lab challenge B2.1).
This is a single-user rotation template for a generic JSON secret of the shape
{"username": "...", "password": "..."}. The `setSecret` and `testSecret` steps
are where you'd talk to the backing service (DB, API); they're stubbed with
explanatory comments because the demo secret has no real backend.

SECURITY: this function NEVER logs the secret value. It logs only the secret ARN,
the rotation step, the version token, and staging labels — per the house rule that
secrets must never reach stdout/stderr/logs. `get_random_password` output goes
straight into `put_secret_value` and is never printed.

Deploy with setup_secret_rotation.py. Secrets Manager invokes this function four
times per rotation, once per Step value.
"""

import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Exclude characters that commonly break shell/DB connection strings.
EXCLUDE_CHARS = os.environ.get("EXCLUDE_CHARACTERS", "/@\"'\\")


def lambda_handler(event, context):
    """Entry point. Routes to the step named in the event."""
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    client = boto3.client("secretsmanager")
    metadata = client.describe_secret(SecretId=arn)

    if not metadata.get("RotationEnabled"):
        raise ValueError(f"Secret {arn} is not enabled for rotation")

    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        raise ValueError(f"Version {token} has no stage for secret {arn}")
    if "AWSCURRENT" in versions[token]:
        # This version is already current; nothing to do.
        logger.info("createSecret: version already AWSCURRENT, no-op")
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"Version {token} not AWSPENDING for secret {arn}")

    # Dispatch — never log the secret itself, only the step/version.
    logger.info("Rotation step=%s for secret=%s version=%s", step, arn, token)
    if step == "createSecret":
        create_secret(client, arn, token)
    elif step == "setSecret":
        set_secret(client, arn, token)
    elif step == "testSecret":
        test_secret(client, arn, token)
    elif step == "finishSecret":
        finish_secret(client, arn, token)
    else:
        raise ValueError(f"Invalid step parameter: {step}")


def create_secret(client, arn: str, token: str) -> None:
    """Step 1: generate a new value and stage it as AWSPENDING (idempotent)."""
    # If an AWSPENDING value already exists, leave it (idempotency).
    try:
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: AWSPENDING already present, skipping")
        return
    except ClientError:
        pass

    current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    # Build the new secret from the current structure, swapping only the password.
    import json

    data = json.loads(current["SecretString"])
    new_password = client.get_random_password(ExcludeCharacters=EXCLUDE_CHARS)["RandomPassword"]
    data["password"] = new_password  # never logged

    client.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(data),
        VersionStages=["AWSPENDING"],
    )
    logger.info("createSecret: staged new AWSPENDING version (value not logged)")


def set_secret(client, arn: str, token: str) -> None:
    """Step 2: make the AWSPENDING value valid on the backing service.

    For a real DB you would connect with the AWSCURRENT credential and run
    something like `ALTER USER app WITH PASSWORD <pending>` so the new password
    becomes accepted. The demo secret has no backend, so this is a no-op.
    """
    logger.info("setSecret: no backing service in demo; would update DB here")


def test_secret(client, arn: str, token: str) -> None:
    """Step 3: verify the AWSPENDING value actually works.

    For a real DB you would open a connection using the AWSPENDING credential and
    run a trivial query. Fail loudly here so a broken secret is never promoted.
    """
    logger.info("testSecret: no backing service in demo; would test connection here")


def finish_secret(client, arn: str, token: str) -> None:
    """Step 4: promote AWSPENDING to AWSCURRENT (atomic re-label)."""
    metadata = client.describe_secret(SecretId=arn)
    current_version = None
    for version, stages in metadata["VersionIdsToStages"].items():
        if "AWSCURRENT" in stages:
            current_version = version
            break

    if current_version == token:
        logger.info("finishSecret: already current, no-op")
        return

    client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info("finishSecret: promoted version=%s to AWSCURRENT", token)
