"""
Build-enforced issuer boundary.

Only specific modules may touch the private hooks that mint trusted
AuthorizationContext / ApprovalEvidence objects. Any other module under
app/ or scripts/ that references them (including JURIX or API code) fails
this test.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CONTEXT_NAMES = {
    "_issue_internal_authorization_context",
    "_INTERNAL_ISSUER_CAPABILITY",
    "_INTERNAL_CONTEXT_MARKER",
    "TrustedAuthorizationContextIssuer",
}

APPROVAL_NAMES = {
    "_issue_internal_approval_evidence",
    "_INTERNAL_APPROVAL_ISSUER_CAPABILITY",
    "_INTERNAL_APPROVAL_MARKER",
    "TrustedApprovalEvidenceIssuer",
}

PROTECTED = CONTEXT_NAMES | APPROVAL_NAMES

ALLOWED = {
    "app/authorization_context.py": CONTEXT_NAMES,
    "app/approval_evidence.py": APPROVAL_NAMES,
    "app/session_service.py": {"_issue_internal_authorization_context"},
}


def _used_names(source: str) -> set[str]:
    names: set[str] = set()

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name.split(".")[-1])

            if node.asname:
                names.add(node.asname)

    return names


def _violations(source: str, allowed: set[str]) -> set[str]:
    return (_used_names(source) & PROTECTED) - allowed


def _source_files():
    for folder in ("app", "scripts"):
        directory = ROOT / folder

        if directory.exists():
            yield from sorted(directory.rglob("*.py"))


def test_only_allowed_modules_use_private_issuer_hooks():
    problems = []

    for path in _source_files():
        relative = path.relative_to(ROOT).as_posix()
        found = _violations(
            path.read_text(encoding="utf-8"),
            ALLOWED.get(relative, set()),
        )

        if found:
            problems.append(f"{relative}: {sorted(found)}")

    assert problems == []


def test_session_service_really_uses_the_context_hook():
    source = (ROOT / "app" / "session_service.py").read_text(encoding="utf-8")

    assert "_issue_internal_authorization_context" in _used_names(source)


def test_scanner_detects_import_use_and_attribute_access():
    assert _violations(
        "from app.authorization_context import _issue_internal_authorization_context",
        set(),
    )
    assert _violations(
        "import app.approval_evidence as a\na._issue_internal_approval_evidence()",
        set(),
    )
    assert _violations("x = TrustedAuthorizationContextIssuer", set())
    assert not _violations("x = 1", set())


def test_session_module_may_not_issue_approval_evidence():
    assert _violations(
        "_issue_internal_approval_evidence()",
        ALLOWED["app/session_service.py"],
    )