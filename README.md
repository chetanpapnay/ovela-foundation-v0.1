# Ovela Foundation v0.1

A security-first foundation for Ovela: evidence-backed personal finance intelligence with explicit trust boundaries and a model-independent experience architecture.

## Current scope
- Local-first FastAPI service
- Financial event model with immutable IDs and provenance fields
- Decimal-only monetary arithmetic
- Deterministic transaction validation
- Append-only in-memory ledger prototype
- Security policy boundary between conversation and financial actions
- Fail-closed action allowlist and transaction-bound payment confirmation
- Internal API authorization boundary and baseline browser security headers
- Premium experience security contract: privacy gating, degraded-state disclosure, and validated UI schema boundary
- Premium minimal UI shell
- Automated tests for money precision, duplicate/replay protection, transfer classification, and authorization boundaries

## Explicitly NOT implemented yet
- Bank credentials or UPI PIN handling
- Live bank connections
- Automatic payments
- Legal/tax conclusions
- Production-grade key management/HSM integration
- Cloud deployment

Those are deliberately blocked until their RT-F requirements are implemented and tested.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

Run tests:

```bash
pytest -q
```
