from datetime import datetime, timedelta, timezone
from uuid import UUID

from app.approval_evidence import _issue_internal_approval_evidence


def trusted_approval_for_action(action, authorization_context, ttl_minutes=5):
    approved_at = datetime.now(timezone.utc)
    return _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=UUID(action.session_id),
        subject_id=authorization_context.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency.upper(),
        approved_at=approved_at,
        expires_at=approved_at + timedelta(minutes=ttl_minutes),
    )


def execute_with_trusted_approval(executor, action, authorization_context=None):
    if authorization_context is None:
        from tests.authorization_test_helpers import trusted_context_for_action

        authorization_context = trusted_context_for_action(action)

    approval = trusted_approval_for_action(action, authorization_context)
    return executor.execute(action, authorization_context, approval)
