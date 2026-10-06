"""Shared bearer-token validation for protected API operations."""

import hmac
import logging

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


def require_bearer_token(authorization: str, expected_token: str | None, environment: str) -> None:
    """Validate a configured token; permit an unset token only in local/test mode."""
    if environment.lower() == "production" and expected_token and expected_token.strip().lower() in {
        "change_collector_token_secret",
        "change_admin_token_secret",
        "change_this_in_production",
    }:
        logger.error("Protected API access denied because a template bearer key is configured.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured.",
        )

    if not expected_token:
        if environment.lower() not in {"development", "testing"}:
            logger.error("Protected API access denied because its bearer key is not configured.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured.",
            )
        logger.debug("API bearer authentication is disabled outside production.")
        return

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing or malformed Authorization header.",
        )
    supplied = authorization[len("Bearer "):]
    if not supplied or not hmac.compare_digest(supplied, expected_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bearer token.",
        )
