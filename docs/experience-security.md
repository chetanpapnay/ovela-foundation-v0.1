# Ovela Experience v0.1 — Security Contract

The premium interface is a presentation layer, not an authorization layer.

## Non-negotiable rules

1. The home view must not reveal high-sensitivity financial values until the session has the required privilege.
2. Unknown users receive a neutral Ovela surface; the UI must not confirm whether Chetan has accounts, investments, devices, balances, or pending actions.
3. Voice recognition may personalize the experience but never authorizes a sensitive action.
4. AI-generated text/cards/actions are untrusted until validated by Ovela Core.
5. The model cannot generate arbitrary executable UI, JavaScript, URLs, QR actions, or privileged controls.
6. Every high-impact action card is bound to an immutable action ID and current authorization context.
7. Confirmation is explicit, transaction-bound, and invalidated if amount, destination, purpose, or material risk changes.
8. UI must expose source freshness and degraded/offline state when a decision depends on current data.
9. Sensitive screens support privacy/masking mode and must avoid sensitive data in notifications, titles, previews, or accessibility labels where inappropriate.
10. Navigation does not grant privilege. Privilege comes from the security layer only.
11. Security settings are not permanently exposed; authenticated intent can temporarily reveal the relevant control surface.
12. Destructive or irreversible actions require stronger friction than reversible/read-only actions.

## Model-generated UI boundary

The model may propose a structured presentation, but only a fixed Ovela UI schema may render it. Unknown components, event handlers, links, or action types are rejected.

## Degraded state

If live sources are unavailable, the interface must say so and distinguish cached verified information from current information. It must not display stale data as current.
