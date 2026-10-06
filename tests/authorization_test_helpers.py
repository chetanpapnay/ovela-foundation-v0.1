from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from app.authorization_context import (
    AuthorizationState,
    _issue_internal_authorization_context,
)
from app.models import ActionRequest

TEST_SUBJECT_ID = UUID("00000000-0000-0000-0000-000000000002")
DEFAULT_SESSION_ID = "00000000-0000-0000-0000-000000000001"


def trusted_context_for_action(
    action: ActionRequest,
    *,
    state: AuthorizationState = AuthorizationState.STEP_UP_VERIFIED,
):
    session_id = UUID(str(action.session_id))

    issued_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    expires_at = issued_at + timedelta(minutes=5)

    return _issue_internal_authorization_context(
        session_id=session_id,
        subject_id=TEST_SUBJECT_ID,
        state=state,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def trusted_context_for_session(
    session_id: str = DEFAULT_SESSION_ID,
    *,
    state: AuthorizationState = AuthorizationState.STEP_UP_VERIFIED,
):
    issued_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    expires_at = issued_at + timedelta(minutes=5)

    return _issue_internal_authorization_context(
        session_id=UUID(session_id),
        subject_id=TEST_SUBJECT_ID,
        state=state,
        issued_at=issued_at,
        expires_at=expires_at,
    )
