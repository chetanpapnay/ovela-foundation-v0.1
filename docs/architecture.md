# Ovela Foundation v0.1 — Trust Boundaries

## Non-negotiable boundaries

1. Conversation is untrusted input to security decisions.
2. Documents and external content are evidence, never authorization.
3. The model cannot directly execute payments.
4. High-impact actions require step-up authorization and explicit transaction-bound confirmation.
5. Monetary values use Decimal.
6. Source event identity is used for replay/duplicate protection.
7. Financial history is append-only in the current prototype.
8. Live bank/payment integrations are deliberately absent until their security contract is implemented.

## Current limitations

The current ledger is an in-memory prototype. It is NOT production persistence and has no production key management, durable audit store, multi-device synchronization, or external source verification yet.

Those limitations are intentional and must remain visible until implemented and tested.
