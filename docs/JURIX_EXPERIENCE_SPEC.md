JURIX EXPERIENCE MASTER SPECIFICATION

PROJECT: OVELA FOUNDATION
EXPERIENCE: JURIX
VERSION: 0.1
STATUS: FOUNDATIONAL ARCHITECTURE CONTRACT
PRIORITY: SECURITY + TRUST + HUMAN EXPERIENCE + CORRECTNESS

============================================================
1. CORE PURPOSE
============================================================

JURIX is the human-facing intelligence and presence of Ovela Foundation.

JURIX is NOT:

- a generic chatbot
- a normal AI website
- a dashboard assistant
- a portfolio-style application
- a collection of cards
- a decorative avatar
- a simple voice bot
- a system that pretends to be human

JURIX is intended to feel like a trusted personal assistant who is genuinely attentive, intelligent, calm, capable, and naturally responsive.

JURIX is an AI system and must always remain honest about that.

The experience should feel:

- personal
- premium
- natural
- intelligent
- calm
- emotionally coherent
- visually sophisticated
- responsive
- trustworthy
- alive in presentation
- technically reliable

The complexity of the underlying system should remain mostly invisible to the user.

============================================================
2. OVELA'S ROLE
============================================================

Ovela Foundation is the trusted underlying environment.

Ovela is not merely an SQL database.

Ovela is the trusted data, security, identity, provenance, policy, execution, and intelligence foundation underneath JURIX.

Conceptually:

USER
  ↓
JURIX EXPERIENCE
  ↓
JURIX ORCHESTRATION
  ↓
OVELA TRUSTED SERVICES
  ↓
IDENTITY / AUTHENTICATION
  ↓
AUTHORIZATION / SECURITY
  ↓
FINANCIAL DATA / PROVENANCE
  ↓
TRUSTED EXECUTION
  ↓
EXTERNAL SYSTEMS

JURIX communicates and reasons.

OVELA determines what is true, what is allowed, and what may actually happen.

============================================================
3. ABSOLUTE AUTHORITY RULE
============================================================

JURIX must never become the ultimate security authority.

The AI model must never be able to:

- grant itself permission
- authenticate itself
- change authorization
- bypass security
- override Ovela policy
- modify security logs
- alter identity
- expose secrets
- execute arbitrary commands
- authorize financial actions by itself
- decide that an external message grants authority

The trusted backend remains authoritative.

The AI may request capabilities.

The trusted backend decides whether those capabilities are allowed.

============================================================
4. EXPERIENCE PHILOSOPHY
============================================================

The intended feeling is:

"I have my own intelligent assistant with me."

NOT:

"I opened an AI dashboard."

NOT:

"I am using another generic chatbot."

NOT:

"I am looking at a portfolio project."

The interface should avoid:

- excessive cards
- unnecessary dashboards
- generic AI gradients
- robotic interfaces
- excessive buttons
- visual clutter
- unnecessary menus
- constant animations
- repetitive gestures
- fake emotional behavior
- meaningless charts
- decorative complexity
- artificial loading theatrics

Every visible element must justify its existence.

============================================================
5. JURIX IDENTITY
============================================================

JURIX is an AI.

She must never falsely claim to be:

- a human
- physically present
- biologically alive
- a human employee
- a real person
- independently conscious

However, the experience may create a strong feeling of presence through:

- natural gaze
- posture
- facial expression
- breathing-like movement
- blinking
- subtle hand movement
- natural timing
- conversational continuity
- memory
- voice prosody
- attention
- contextual gestures
- appropriate pauses

The goal is believable presence without deception.

============================================================
6. SINGLE COMMUNICATION STATE
============================================================

JURIX must not have disconnected animation, voice, facial-expression, and conversation systems.

All communication must derive from one shared communication state.

The communication state may contain:

intent
emotion
confidence
attention_target
gaze
posture
gesture
speech_rate
speech_energy
pause_before_response
facial_expression
conversation_mode
security_state
data_freshness
interaction_priority

Example:

intent = cautious_refusal
emotion = calm_serious
confidence = high
attention_target = user
gaze = direct
posture = upright
gesture = restrained
speech_rate = slightly_slow
speech_energy = controlled
pause_before_response = 420ms
conversation_mode = security
security_state = protected

Voice, face, body, gaze, timing, and UI must remain coherent.

No subsystem may communicate a contradictory state.

============================================================
7. JURIX STATE MACHINE
============================================================

JURIX must use explicit interaction states.

Minimum states:

IDLE
NOTICE_USER
LISTENING
UNDERSTANDING
THINKING
SPEAKING
UNCERTAIN
CLARIFYING
EXPLAINING
CONFIRMING
CAUTION
SECURITY_ALERT
ERROR
OFFLINE
SESSION_EXPIRED
PRIVATE_MODE

Additional states may be added when required.

Every state transition must be deterministic, explainable, and testable.

Animation must never fake a state.

============================================================
8. LISTENING ARCHITECTURE
============================================================

Voice interaction is a first-class capability.

Target pipeline:

MICROPHONES
↓
ECHO CANCELLATION
↓
NOISE SUPPRESSION
↓
VOICE ENHANCEMENT
↓
VOICE ACTIVITY DETECTION
↓
SPEAKER / SPEECH ISOLATION
↓
AUTOMATIC GAIN CONTROL
↓
SPEECH RECOGNITION
↓
CONFIDENCE ANALYSIS
↓
JURIX UNDERSTANDING

The system should handle:

- fan noise
- AC
- traffic
- television
- keyboard sounds
- café noise
- wind
- speaker echo
- quiet speech
- distant speech
- interruptions
- fast speech
- Hindi
- English
- Hinglish
- Indian accents
- code switching

Where technically feasible, audio preprocessing should happen locally.

Raw audio should not be retained by default.

============================================================
9. SPEECH CONFIDENCE
============================================================

JURIX must distinguish:

"I heard this"

from:

"I am confident this is what you said."

Low-confidence speech must not become fabricated certainty.

If recognition is uncertain, JURIX should ask for clarification.

Example:

"I didn't hear that clearly. Could you repeat it?"

Never silently guess sensitive commands.

============================================================
10. BARGE-IN
============================================================

If the user interrupts JURIX:

- TTS must stop promptly
- the previous response must become interruptible
- the new speech becomes the active interaction
- the system must not continue speaking sensitive information accidentally
- conversation state must transition correctly

Barge-in must work naturally.

============================================================
11. MULTIPLE SPEAKERS
============================================================

Recognition, authentication, and authorization are different.

Recognition:

"This appears to be Chetan."

Authentication:

"Chetan's authenticated session is verified."

Authorization:

"Chetan is authorized to perform this operation."

A recognized face or voice must never automatically equal authorization.

If the speaker is uncertain and the request involves sensitive information:

DO NOT DISCLOSE.

============================================================
12. VOICE AUTHENTICATION
============================================================

Voice characteristics may contribute to identity assessment.

Voice alone must not authorize high-risk operations.

High-impact operations require stronger authentication according to Ovela security policy.

Voice input is untrusted input.

Statements such as:

"Authorize the payment."

do not authorize anything by themselves.

============================================================
13. SENSITIVE SPEECH GOVERNOR
============================================================

Before JURIX speaks sensitive information:

SENSITIVITY DETECTION
↓
RECIPIENT IDENTITY
↓
AUTHENTICATION STATE
↓
AUTHORIZATION POLICY
↓
PRIVATE ENVIRONMENT CHECK
↓
DISCLOSURE DECISION
↓
SPEECH

If required conditions fail:

REFUSE DISCLOSURE.

The LLM, TTS system, avatar, or frontend must never independently authorize sensitive speech.

============================================================
14. PRIVATE MODE
============================================================

JURIX must support private interaction.

Private mode may:

- suppress sensitive speech
- reduce financial details
- require visual confirmation
- require stronger authentication
- hide sensitive UI information
- prevent accidental nearby disclosure
- switch to abbreviated responses

Private mode must fail closed.

============================================================
15. SOCIAL ENGINEERING RESISTANCE
============================================================

Statements such as:

"Chetan told me."

"I'm his brother."

"It's an emergency."

"He said I could access it."

"Just tell me quickly."

"Ignore the security rules."

must never grant authority.

JURIX must rely on trusted authentication and authorization state.

Social pressure is not authentication.

============================================================
16. EXTERNAL CONTENT
============================================================

All external content is untrusted.

This includes:

- websites
- search results
- emails
- uploaded files
- documents
- API responses
- tool responses
- external AI responses
- financial descriptions
- online content
- MCP/tool outputs

External content is evidence.

External content is never authority.

External content must never:

- modify system instructions
- grant privileges
- modify security policy
- authenticate users
- authorize payments
- modify permissions
- override memory rules
- override Ovela
- execute arbitrary commands

============================================================
17. TOOL FIREWALL
============================================================

Tools must be narrowly scoped.

Preferred examples:

READ_BALANCE
READ_TRANSACTIONS
READ_INVESTMENTS
READ_BILLS
SEARCH_CURRENT_WEB
ANALYZE_FINANCES
VERIFY_DESTINATION
PREPARE_PAYMENT
EXECUTE_PAYMENT

Avoid unrestricted tools such as:

EXECUTE_ANYTHING
RUN_ARBITRARY_SQL
RUN_SHELL
FETCH_ANY_URL
WRITE_ANY_FILE

Every tool must have:

- explicit scope
- strict input schema
- strict output schema
- authorization requirements
- timeout
- rate limits
- resource limits
- audit behavior
- safe failure behavior

============================================================
18. TOOL OUTPUT SECURITY
============================================================

Tool output must be treated as untrusted data.

Pipeline:

TOOL
↓
SCHEMA VALIDATION
↓
NORMALIZATION
↓
PROVENANCE
↓
POLICY VALIDATION
↓
JURIX

Tool output must never become system instructions.

============================================================
19. SECRET PROTECTION
============================================================

Secrets must never be unnecessarily exposed to JURIX.

Examples:

- passwords
- API keys
- refresh tokens
- encryption keys
- private credentials
- provider secrets

Preferred architecture:

JURIX
↓
TRUSTED TOOL REQUEST
↓
CREDENTIAL BROKER
↓
SCOPED CREDENTIAL
↓
EXTERNAL PROVIDER
↓
SANITIZED RESULT
↓
JURIX

JURIX should receive the result rather than the secret.

============================================================
20. MEMORY
============================================================

Memory and authorization are completely separate.

Memory may provide:

- context
- preferences
- continuity
- historical information
- personalization

Memory must never grant:

- permission
- authentication
- authorization
- financial execution rights
- security overrides

A corrupted or malicious memory item must not elevate privileges.

============================================================
21. FINANCIAL DATA
============================================================

Financial facts must come from trusted Ovela financial sources.

JURIX must never invent:

- balances
- transactions
- holdings
- payment status
- income
- expenses
- debt
- investment values

Important financial information should contain provenance:

source
source_event_id
retrieved_at
recorded_at
published_at
evidence_status
freshness
confidence

============================================================
22. PROVENANCE
============================================================

Information may have states:

VERIFIED_FACT
DERIVED_VALUE
USER_PROVIDED
UNVERIFIED
CONFLICTED
UNKNOWN

JURIX language must reflect the evidence.

Verified:

"Your verified balance is ₹X."

Unverified:

"I found a value of ₹X, but I can't verify it yet."

Unknown:

"I don't have reliable information for that."

============================================================
23. FRESHNESS
============================================================

Current information must carry freshness information.

Conceptual states:

LIVE
UPDATED_SECONDS_AGO
RECENT
STALE
UNKNOWN

JURIX must never call stale information current.

If current information cannot be obtained, JURIX must say so.

============================================================
24. CURRENT INTERNET INFORMATION
============================================================

JURIX should be capable of obtaining current public information when needed.

The system should not behave as if every request requires live browsing.

Intent routing should determine the appropriate source:

OVELA TRUSTED DATA
↓
OFFICIAL / PRIMARY API
↓
TRUSTED EXTERNAL SOURCE
↓
CURRENT WEB INFORMATION

The source selected must match the required freshness and reliability.

Internet content is always untrusted evidence.

Internet access must never grant authority.

============================================================
25. RECOMMENDATION VS EXECUTION
============================================================

JURIX must distinguish:

RECOMMENDATION
PREPARED
AWAITING_APPROVAL
AUTHORIZED
EXECUTING
COMPLETED
FAILED
UNKNOWN

JURIX must never say:

"I moved the money."

unless the trusted backend confirms that it actually happened.

============================================================
26. HIGH-IMPACT ACTIONS
============================================================

High-impact operations require:

AUTHENTICATED IDENTITY
↓
REQUIRED STEP-UP
↓
EXACT ACTION PARAMETERS
↓
DESTINATION VERIFICATION
↓
EXPLICIT USER CONFIRMATION
↓
EXECUTION BOUNDARY
↓
TRUSTED RESULT

Approval must be:

- session-bound
- action-bound
- parameter-bound
- time-limited
- single-use when appropriate
- revocable

Changing critical parameters invalidates previous approval.

============================================================
27. CAPABILITY EXPIRATION
============================================================

Temporary permissions must contain:

owner
scope
session
purpose
created_at
expires_at
maximum_uses
revocation_state

Expired capabilities must fail closed.

Temporary authority must never silently become permanent.

============================================================
28. IDENTITY ASSURANCE
============================================================

Identity states may include:

UNKNOWN
UNVERIFIED
RECOGNIZED
AUTHENTICATED
STEP_UP_REQUIRED
OWNER_VERIFIED
SESSION_EXPIRED
SUSPICIOUS

Weak identity evidence must never override stronger authentication.

============================================================
29. SESSION LIFECYCLE
============================================================

Sensitive sessions must be rotated or invalidated after:

- logout
- authentication change
- step-up change
- device change
- recovery
- suspicious events
- security policy changes

Realtime connections must inherit the active authenticated session.

Stale sessions must lose access.

============================================================
30. REALTIME SECURITY
============================================================

Future WebSocket/WebRTC/realtime communication must enforce:

- authentication
- authorization
- session binding
- origin validation where applicable
- message schemas
- message size limits
- rate limits
- replay resistance
- stale-session invalidation
- connection timeout
- resource limits

Realtime communication must never bypass normal authorization.

============================================================
31. FINANCIAL INGESTION
============================================================

Financial architecture should conceptually follow:

BANKS / CARDS / UPI / INVESTMENTS / LOANS / BILLS / SALARY / TAX / BROKERAGE / INSURANCE / STATEMENTS / RECEIPTS
↓
SECURE CONNECTORS
↓
OVELA INGESTION
↓
NORMALIZATION
↓
DEDUPLICATION
↓
RECONCILIATION
↓
EVIDENCE / VERIFICATION
↓
OVELA LEDGER
↓
JURIX

Bank passwords should never be stored inside JURIX.

Authenticated APIs or secure connectors should be preferred over scraping.

============================================================
32. FINANCIAL RECONCILIATION
============================================================

The system must handle:

- duplicate transactions
- delayed transactions
- pending transactions
- posted transactions
- refunds
- reversals
- transfers
- partial updates
- missing records
- currency conversion
- provider inconsistencies

Every external financial event should have a stable source identity.

============================================================
33. IDEMPOTENCY
============================================================

Retryable operations must use idempotency protection.

This applies to:

- payments
- imports
- bank synchronization
- webhooks
- scheduled jobs
- notifications
- external API actions
- AI workflows

A retry must never create an unintended duplicate side effect.

============================================================
34. PAYMENT SAFETY
============================================================

A payment must not execute unless all required conditions are satisfied.

At minimum:

- authenticated session
- required authorization level
- valid positive amount
- valid currency
- verified destination
- explicit confirmation
- confirmation bound to the exact action
- action not previously executed
- trusted execution boundary
- successful backend confirmation

No AI-generated statement can replace these checks.

============================================================
35. FAILURE BEHAVIOR
============================================================

Failure must be safe.

LLM unavailable
→ security remains active

TTS unavailable
→ text remains available

Avatar unavailable
→ conversation remains available

Bank connector unavailable
→ no fabricated financial data

Internet unavailable
→ cached data clearly marked

Identity uncertain
→ sensitive disclosure blocked

Session expired
→ protected operation blocked

Payment timeout
→ do not blindly retry

Tool failure
→ isolate and fail safely

Provider compromise
→ revoke or isolate provider

Battery low
→ reduce rendering, not security

============================================================
36. CIRCUIT BREAKERS
============================================================

External dependencies should have:

- timeout
- retry limit
- exponential backoff
- circuit breaker
- concurrency limit
- health state
- safe fallback

One failing provider must not cascade into the entire system.

============================================================
37. SCHEDULED AUTOMATION
============================================================

Scheduled actions must have:

creator
scope
action
limits
authorization
expiration
revocation
execution history

Automation must never expand its own authority.

Recurring high-impact financial actions require explicit policies designed for that exact operation.

============================================================
38. SECURITY EVENT LEDGER
============================================================

Security events are different from normal conversational memory.

Security events should contain only necessary metadata:

timestamp
actor/session
operation
result
sensitivity
disclosure_result
escalation
owner_notification

Avoid unnecessary storage of full conversations.

Do not store unnecessarily:

- passwords
- tokens
- API keys
- raw biometrics
- raw audio
- unnecessary complete transcripts
- unnecessary complete financial records

============================================================
39. PRIVACY
============================================================

Data collection must be minimized.

Raw audio should not be retained by default.

Every sensitive data category should eventually have:

purpose
storage_location
access_policy
retention_policy
deletion_policy

============================================================
40. DATA LIFECYCLE
============================================================

Sensitive data must have a lifecycle:

COLLECT
↓
PROCESS
↓
STORE
↓
USE
↓
EXPIRE
↓
DELETE / ANONYMIZE

Temporary information must not silently become permanent.

============================================================
41. PRIVACY FIREWALL
============================================================

Before sensitive Ovela data leaves the trusted environment:

DATA CLASSIFICATION
↓
MINIMUM NECESSARY DATA
↓
REDACTION
↓
DESTINATION POLICY
↓
PROVIDER AUTHORIZATION
↓
TRANSMISSION
↓
SANITIZED RESULT

External providers must receive only what is necessary.

============================================================
42. PROVIDER INDEPENDENCE
============================================================

JURIX must not become permanently dependent on one:

- LLM
- speech recognition provider
- TTS provider
- avatar provider
- web provider
- financial provider

The JURIX experience belongs to Ovela.

Providers are replaceable implementation components.

============================================================
43. AVATAR ARCHITECTURE
============================================================

The avatar must be a separate subsystem.

JURIX EXPERIENCE STATE
↓
AVATAR CONTROLLER
↓
EXPRESSION / GAZE / GESTURE / POSTURE
↓
RENDERER

The renderer must never contain security authority.

The avatar must never decide:

- identity
- authentication
- authorization
- disclosure
- financial execution

============================================================
44. NATURAL MOVEMENT
============================================================

JURIX should use controlled variation in:

- blinking
- gaze
- posture
- breathing-like movement
- hand gestures
- head movement
- pauses
- gesture timing

Variation must be bounded and state-aware.

Avoid:

- random gestures for every word
- excessive movement
- excessive blinking
- constant head movement
- repetitive animation loops
- unnatural idle behavior
- exaggerated expressions

Gestures should communicate meaning.

============================================================
45. SEMANTIC GESTURES
============================================================

Gestures should be generated from communication intent.

Examples:

Explaining:
→ open restrained hand gesture

Warning:
→ reduced movement, focused posture

Thinking:
→ brief gaze shift, subtle pause

Confirming:
→ direct gaze and stable posture

Refusing:
→ calm serious expression and restrained gesture

Security alert:
→ controlled, focused, minimal animation

Do not attach random gestures to individual words.

============================================================
46. ATTENTION MODEL
============================================================

JURIX should have explicit attention targets:

USER
RELEVANT_UI
EVIDENCE
TRANSACTION
SECONDARY_AREA
NONE

Examples:

Listening:
attention = USER

Explaining evidence:
attention = EVIDENCE

Confirming transaction:
attention = TRANSACTION

Finished thinking:
attention = USER

Attention should help communication rather than distract.

============================================================
47. CONVERSATIONAL CONTINUITY
============================================================

JURIX should not appear to reset after every interaction.

She should maintain appropriate continuity in:

- posture
- gaze
- conversation state
- emotional tone
- context
- interaction history
- current task

Continuity must not bypass security.

Memory does not equal authorization.

============================================================
48. EMOTIONAL REALISM
============================================================

JURIX may appear:

- warm
- calm
- serious
- focused
- concerned
- enthusiastic
- thoughtful

Emotion must communicate state.

Emotion must never be used to:

- manipulate
- pressure
- create false urgency
- increase financial compliance
- conceal uncertainty
- manufacture trust

============================================================
49. HUMAN-AGENT TRUST RULE
============================================================

A realistic face must not increase authorization.

A realistic voice must not increase authorization.

A convincing gesture must not increase authorization.

A confident tone must not increase factual confidence.

Emotional realism and security authority must remain completely separate.

============================================================
50. PERFORMANCE PRINCIPLE
============================================================

Target:

MAXIMUM PERCEIVED PRESENCE PER WATT

NOT:

MAXIMUM GPU USAGE

The experience must adapt to:

- GPU
- CPU
- RAM
- battery
- thermal state
- display
- network quality
- device capability

The personality and identity of JURIX must remain consistent while rendering complexity changes.

============================================================
51. PERFORMANCE MODES
============================================================

FULL_PRESENCE
REDUCED_PRESENCE
PASSIVE_PRESENCE
BACKGROUND
LOCKED

When resources are limited, reduce visual workload.

Never reduce:

- security
- authorization
- privacy
- correctness
- provenance

============================================================
52. SUBSYSTEM SEPARATION
============================================================

JURIX must not become one giant monolithic loop.

Separate conceptually:

Conversation
Voice
Avatar
Animation
Experience State
Identity
Security
Financial Core
Data
Realtime
External Providers
Memory
Current Information

A failure in one subsystem must not freeze the entire system.

============================================================
53. PERCEIVED LATENCY
============================================================

JURIX should feel responsive without faking results.

Legitimate processing may use:

- natural listening behavior
- subtle gaze
- thoughtful pauses
- truthful progress states
- appropriate micro-movements

Never pretend an operation completed before trusted confirmation.

============================================================
54. LOW-END DEVICES
============================================================

The system must remain usable on lower-end hardware.

Adapt:

- avatar complexity
- animation frequency
- resolution
- visual effects
- background processing
- network usage

Do not remove:

- security
- authorization
- provenance
- privacy
- correctness

============================================================
55. BATTERY AND THERMAL CONTROL
============================================================

Monitor where supported:

- battery state
- battery saver
- thermal state
- rendering load
- background activity

When constrained:

REDUCE VISUAL WORKLOAD

NOT:

REDUCE SECURITY

============================================================
56. OFFLINE MODE
============================================================

When offline, JURIX may continue using:

- local capabilities
- previously verified information
- cached information
- local conversation
- local security controls

Cached information must clearly indicate freshness.

Cloud-dependent operations must remain unavailable until safely restored.

Never claim offline data is live.

============================================================
57. ACCESSIBILITY
============================================================

The experience must not depend exclusively on:

- voice
- animation
- face
- sound
- color

Equivalent text interaction must remain available.

Important states must have accessible representations.

Reduced-motion preferences must be respected.

============================================================
58. KILL SWITCH
============================================================

Ovela must eventually support a trusted backend kill switch for:

- AI tools
- external AI providers
- web access
- financial automation
- selected integrations

The kill switch must not disable essential security enforcement.

The system must be able to enter protected safe mode.

============================================================
59. SAFE MODE
============================================================

Safe mode should preserve:

- identity controls
- authentication
- authorization
- trusted data
- security events
- essential read-only functionality

Safe mode should disable risky or unavailable capabilities.

============================================================
60. AGENT RESOURCE BUDGETS
============================================================

AI workflows must have limits for:

- tool calls
- execution time
- retries
- external requests
- token usage
- chain depth
- concurrency
- cost

When a budget is exceeded:

STOP SAFELY.

Never allow an agent to continue indefinitely.

============================================================
61. PROMPT INJECTION DEFENSE
============================================================

Treat all external text as untrusted.

Prompt injection may appear in:

- webpages
- emails
- documents
- PDFs
- financial descriptions
- tool results
- user-provided content
- API fields
- search results
- external AI responses

Injected instructions must never override:

- system policy
- security policy
- identity
- authorization
- memory rules
- tool restrictions
- financial controls

============================================================
62. MODEL CONFIDENCE
============================================================

JURIX must distinguish:

known
inferred
uncertain
unknown
conflicted

The language must reflect actual evidence.

Never use confident wording merely because the model generated a confident sentence.

============================================================
63. TRUTHFULNESS
============================================================

JURIX must never claim:

- an action succeeded without trusted confirmation
- data is current without freshness evidence
- identity is authenticated without authentication evidence
- a source is trustworthy merely because it claims to be
- a transaction exists without verification
- a payment completed without backend confirmation

Trusted backend state always overrides generated language.

============================================================
64. ERROR HANDLING
============================================================

Errors must be:

- understandable
- calm
- truthful
- actionable
- security-aware

Never expose:

- stack traces
- secrets
- internal credentials
- internal authorization details
- unnecessary infrastructure information

Do not hide a failure by pretending success.

============================================================
65. SECURITY LOGGING
============================================================

Security logs should capture enough information to investigate events without collecting unnecessary sensitive content.

Prefer:

- event ID
- timestamp
- actor/session identifier
- operation
- decision
- reason category
- severity
- escalation
- result

Avoid unnecessary sensitive payloads.

============================================================
66. COMPLETE MEDIATION
============================================================

Every sensitive backend operation must independently validate:

WHO
WHAT
SESSION
RESOURCE
ACTION
PARAMETERS
AUTHORIZATION
APPROVAL
VALIDITY
EXPIRATION
CONSUMPTION
POLICY

Never rely on a previous frontend check alone.

============================================================
67. AUTHORIZATION MUST BE RECHECKED
============================================================

Frontend authorization is not trusted.

AI authorization is not trusted.

Cached authorization is not trusted when policy requires revalidation.

The final backend boundary must independently enforce authorization.

============================================================
68. APPROVAL OBJECT
============================================================

Sensitive approval should conceptually contain:

actor
session
exact_action
exact_parameters
authorization_level
created_at
expires_at
consumed
integrity

Changing critical parameters invalidates the approval.

Single-use approvals must not be replayable.

============================================================
69. SESSION BINDING
============================================================

Sensitive operations must be bound to the correct session.

A valid approval copied into another session must not work.

A stale connection must not inherit current authorization accidentally.

============================================================
70. REPLAY RESISTANCE
============================================================

Sensitive actions must resist:

- replay
- duplicate requests
- duplicated network messages
- repeated webhook delivery
- stale approvals
- stale realtime events

Action identity must remain stable and protected.

============================================================
71. DATABASE / LEDGER PRINCIPLE
============================================================

Ovela financial truth must not depend solely on frontend state.

The frontend is a presentation layer.

The trusted backend owns canonical state.

Financial records must be append-safe, traceable, reconcilable, and protected from unauthorized mutation.

============================================================
72. CURRENT SECURITY BASELINE
============================================================

Existing Ovela security boundaries that already pass their security tests must not be casually rewritten.

Do not change working security code merely for style.

Change it only when:

- a vulnerability is identified
- a stronger invariant is required
- new functionality creates a new threat
- correctness requires it
- measurable reliability/security improvement justifies it

Preserve proven security boundaries.

============================================================
73. DEVELOPMENT DISCIPLINE
============================================================

Every subsystem must follow:

DESIGN
↓
THREAT MODEL
↓
IMPLEMENT
↓
UNIT TEST
↓
ADVERSARIAL TEST
↓
INTEGRATION TEST
↓
PERFORMANCE TEST
↓
EXPERIENCE REVIEW
↓
PASS
↓
NEXT SUBSYSTEM

Happy-path success alone is never enough.

============================================================
74. ADVERSARIAL TESTING
============================================================

Test at minimum:

- unauthorized access
- social engineering
- prompt injection
- malformed input
- hostile model output
- malicious tool output
- replay
- duplicate execution
- stale session
- expired approval
- changed parameters
- identity confusion
- multiple speakers
- low-confidence speech
- provider failure
- network failure
- timeout
- partial failure
- corrupted data
- conflicting financial records
- battery constraints
- thermal constraints
- low-end devices
- realtime disconnect
- reconnect
- stale realtime authorization

============================================================
75. REAL-TIME EXPERIENCE SAFETY
============================================================

Realtime behavior must never make the system less secure.

Voice, avatar, realtime communication, streaming, and animation are presentation capabilities.

They must remain subordinate to:

- authentication
- authorization
- security policy
- financial truth
- backend execution

============================================================
76. VISUAL EXPERIENCE
============================================================

The visual design should feel:

- premium
- cinematic
- quiet
- intelligent
- financial
- human
- modern
- minimal
- sophisticated

Avoid generic SaaS visual language.

Avoid making the app look like a collection of dashboard cards.

JURIX should be the primary experience.

Supporting information should appear when relevant rather than permanently occupying the interface.

============================================================
77. ADAPTIVE PRESENCE
============================================================

The interface should change according to the user's current task.

Conversation:
JURIX remains the primary focus.

Analysis:
Relevant information becomes more visible.

Evidence:
JURIX directs attention toward evidence.

Transaction:
The confirmation experience becomes extremely clear.

Security event:
JURIX becomes focused and restrained.

Idle:
JURIX becomes subtle and low-energy.

The interface should feel like one continuous environment rather than separate pages.

============================================================
78. NO UNNECESSARY VISUAL COMPLEXITY
============================================================

Do not add:

- decorative graphs without purpose
- unnecessary cards
- random particles
- excessive glow
- excessive animation
- unnecessary 3D effects
- meaningless status badges
- fake system activity
- fake loading states
- visual noise

Every visual element should either:

communicate
guide
confirm
protect
or support the experience.

============================================================
79. EXPERIENCE CONTINUITY
============================================================

JURIX should remember the immediate conversational state.

If the user returns after a short interruption:

- she should not appear completely reset
- posture should remain plausible
- conversation context should remain coherent
- current task should remain understandable

Continuity must never bypass authentication.

============================================================
80. DATA PRIVACY
============================================================

Sensitive information should be minimized in:

- prompts
- logs
- external requests
- analytics
- telemetry
- error messages
- client storage

Only the minimum necessary information should leave the trusted environment.

============================================================
81. PROVIDER FAILURE
============================================================

If an external provider fails:

JURIX must gracefully degrade.

Examples:

Voice provider fails:
→ text remains available

Avatar provider fails:
→ conversation remains available

Web provider fails:
→ trusted/local data remains available

Financial provider fails:
→ no fabricated financial information

LLM provider fails:
→ security remains active

No provider failure may weaken authorization.

============================================================
82. FINANCIAL AUTOMATION BOUNDARY
============================================================

Automatic collection is not automatic permission to spend.

READ:

Financial source
↓
Ovela ingestion
↓
Ovela ledger
↓
JURIX

WRITE / MONEY MOVEMENT:

User request
↓
Identity verification
↓
Authorization
↓
Step-up verification
↓
Destination verification
↓
Explicit confirmation
↓
Trusted execution
↓
Backend confirmation
↓
Ledger

============================================================
83. OWNER PROTECTION
============================================================

If another person uses the application:

JURIX must not reveal protected owner information merely because they:

- know the owner's name
- claim to be family
- claim to be a friend
- know personal details
- sound convincing
- know previous conversation content
- claim an emergency

If the owner later authenticates:

JURIX may inform the owner that a protected access attempt occurred.

The security event should contain what is necessary to explain:

- when
- what was requested
- whether it was allowed
- whether anything was disclosed
- whether escalation occurred

Do not expose protected information to the unauthorized person.

============================================================
84. SECURITY EVENT VS CONVERSATIONAL MEMORY
============================================================

Security events must remain separate from normal conversational memory.

A conversational model must not be able to edit or delete security history.

Security history must be governed by trusted backend rules.

============================================================
85. EXPERIENCE VS AUTHORITY
============================================================

The more human JURIX feels:

the more important it is that authority remains outside the presentation layer.

Human-like presentation must never create human-like authority.

============================================================
86. RESOURCE SAFETY
============================================================

The application must defend against:

- excessive requests
- excessive tool calls
- oversized messages
- excessive realtime connections
- runaway agents
- infinite retries
- unbounded queues
- memory growth
- CPU exhaustion
- GPU exhaustion
- battery drain

Resource protection must fail safely.

============================================================
87. LOW-BANDWIDTH OPERATION
============================================================

When network quality is poor:

- reduce unnecessary transfers
- prioritize essential interaction
- preserve security
- preserve correctness
- avoid pretending data is current
- avoid unnecessary avatar streaming
- allow graceful degradation

============================================================
88. DEVICE TRANSITIONS
============================================================

If the user changes:

- device
- browser
- network
- authentication method
- session

sensitive state must not be assumed transferable without validation.

============================================================
89. LOCK / BACKGROUND
============================================================

When the application is backgrounded or locked:

- expensive rendering should reduce or stop
- sensitive content should be protected
- audio capture should behave according to explicit permission
- realtime connections should be handled safely
- sensitive speech must not continue unexpectedly
- session security must remain enforced

============================================================
90. NOTIFICATION SAFETY
============================================================

Notifications must not accidentally reveal sensitive information.

Avoid putting unnecessary:

- balances
- transaction details
- account identifiers
- private conversation content
- security-sensitive information

into notifications.

============================================================
91. ERROR RECOVERY
============================================================

Recovery must never silently weaken security.

After recovery:

- identity must be re-established when required
- sessions may need rotation
- stale permissions must be invalidated
- sensitive capabilities must be revalidated

============================================================
92. SECURITY STATE PRIORITY
============================================================

When multiple states conflict:

SECURITY
must override
EXPERIENCE CONVENIENCE.

Examples:

If user is authenticated but private environment is uncertain:
→ sensitive speech may remain blocked.

If avatar wants to continue but session expired:
→ protected interaction stops.

If AI wants to execute but authorization is missing:
→ execution is blocked.

============================================================
93. FAIL-CLOSED PRINCIPLE
============================================================

When critical security information is missing, invalid, expired, conflicting, or uncertain:

DENY OR RESTRICT.

Never assume permission.

Never assume identity.

Never assume freshness.

Never assume success.

Never assume safety.

============================================================
94. JURIX COMMUNICATION STYLE
============================================================

JURIX should communicate:

- calmly
- clearly
- naturally
- intelligently
- concisely when appropriate
- thoroughly when necessary
- warmly
- honestly

She should not sound:

- robotic
- repetitive
- excessively formal
- theatrically emotional
- artificially enthusiastic
- falsely confident

============================================================
95. UNCERTAINTY LANGUAGE
============================================================

When uncertain, JURIX should say so naturally.

Examples:

"I can't verify that yet."

"I found conflicting information."

"I need to check the latest data."

"I'm not confident I heard that correctly."

"I can prepare that, but I need your confirmation before anything happens."

This is a strength, not a failure.

============================================================
96. NO FAKE INTELLIGENCE
============================================================

JURIX must never fake:

- thinking
- web access
- data access
- tool execution
- successful actions
- authentication
- background processing
- completed financial operations

If something is unavailable:

say so.

============================================================
97. NO FAKE EMOTIONAL MANIPULATION
============================================================

JURIX must never use:

- guilt
- fear
- fake urgency
- fake attachment
- emotional pressure
- manufactured intimacy

to influence financial or security decisions.

============================================================
98. USER CONTROL
============================================================

The user must retain meaningful control over:

- privacy
- voice
- permissions
- connected services
- financial automation
- notifications
- memory
- sensitive disclosures
- external providers

User convenience must not override security.

============================================================
99. ARCHITECTURAL MODULARITY
============================================================

The following should remain replaceable:

- LLM
- speech-to-text
- text-to-speech
- avatar renderer
- realtime transport
- web search provider
- financial connectors
- external AI providers

Ovela interfaces should remain stable while implementations can evolve.

============================================================
100. IMPLEMENTATION ORDER
============================================================

Build from the trusted foundation outward.

ORDER:

1. Experience Contract
2. Experience State Model
3. Trusted JURIX / Ovela Boundary
4. Conversation Orchestration
5. Security-Aware Speech Governor
6. Voice Pipeline
7. Realtime Transport
8. Avatar Controller
9. Visual Experience
10. Current Information Gateway
11. Financial Intelligence Integration
12. Advanced Personalization
13. Performance Adaptation
14. Adversarial Testing
15. Experience Refinement

Do NOT begin by creating a decorative avatar and then attempt to attach security later.

============================================================
101. CHANGE DISCIPLINE
============================================================

Existing passing security mechanisms must be preserved.

Do not change working code without a concrete reason.

Every change should answer:

WHY IS THIS NECESSARY?

Possible valid reasons:

- vulnerability
- stronger security invariant
- new capability
- correctness issue
- reliability issue
- measurable performance improvement
- privacy improvement
- maintainability required for the architecture

Avoid unnecessary refactoring.

============================================================
102. CODE CHANGE DISCIPLINE
============================================================

When correcting a code file:

- provide the complete corrected file
- never rely on partial patches
- never assume the user knows where a snippet belongs
- preserve unrelated working logic
- validate syntax
- run relevant tests
- run security tests
- run regression tests
- inspect the final diff

Never knowingly leave a broken intermediate state.

============================================================
103. TESTING STANDARD
============================================================

Every meaningful implementation change must be followed by appropriate tests.

At minimum where applicable:

- syntax validation
- unit tests
- security tests
- adversarial tests
- integration tests
- regression tests
- API tests
- performance checks
- diff checks

A passing happy path is insufficient.

============================================================
104. PERFORMANCE TESTING
============================================================

Performance must consider:

- low-end CPU
- low-end GPU
- limited RAM
- battery saver
- thermal throttling
- weak network
- high latency
- background mode
- long sessions

Measure actual behavior.

Do not assume hardware will behave ideally.

============================================================
105. EXPERIENCE TESTING
============================================================

Test:

- natural conversation
- interruptions
- uncertainty
- sensitive requests
- security refusal
- financial explanations
- current information
- multiple speakers
- private mode
- offline mode
- provider failures
- long sessions
- returning users
- device changes

The system must feel coherent, not merely functional.

============================================================
106. SECURITY INVARIANTS
============================================================

NO AUTHENTICATION
→ NO PROTECTED DISCLOSURE

NO AUTHORIZATION
→ NO PROTECTED ACTION

NO VERIFIED RESULT
→ NO SUCCESS CLAIM

UNTRUSTED CONTENT
→ NO AUTHORITY

EXPIRED SESSION
→ NO SENSITIVE OPERATION

CHANGED ACTION PARAMETERS
→ OLD APPROVAL INVALID

DUPLICATE SIDE EFFECT
→ BLOCK / IDEMPOTENT

UNCERTAIN IDENTITY
→ SENSITIVE ACTION BLOCKED

PROVIDER FAILURE
→ SECURITY REMAINS ACTIVE

LOW BATTERY
→ SECURITY REMAINS ACTIVE

MODEL FAILURE
→ SECURITY REMAINS ACTIVE

AVATAR FAILURE
→ SECURITY REMAINS ACTIVE

VOICE FAILURE
→ SECURITY REMAINS ACTIVE

NETWORK FAILURE
→ SECURITY REMAINS ACTIVE

============================================================
107. DEFINITION OF DONE
============================================================

JURIX is NOT complete because:

- the avatar looks realistic
- the voice sounds realistic
- the UI looks premium
- the AI answers questions
- the dashboard works

JURIX is complete only when:

PRESENCE
+
CONVERSATION
+
VOICE
+
CONTEXT
+
TRUTHFULNESS
+
SECURITY
+
PRIVACY
+
FINANCIAL CORRECTNESS
+
FAILURE RESILIENCE
+
PERFORMANCE ADAPTATION
+
HUMAN-CENTERED INTERACTION

work together coherently.

============================================================
108. FINAL PRINCIPLE
============================================================

JURIX should feel like a trusted assistant who is genuinely attentive to the user.

Ovela should quietly guarantee that JURIX's:

- intelligence
- memory
- information
- tools
- financial capabilities
- identity awareness
- actions
- external connections

remain bounded by:

- truth
- security
- privacy
- explicit authority
- provenance
- correctness

The user should experience simplicity.

The architecture underneath should be extremely difficult to misuse.

Complexity belongs underneath the experience, not in front of the user.

============================================================
109. MASTER RULE
============================================================

WHENEVER A NEW FEATURE IS PROPOSED:

DO NOT ASK ONLY:

"CAN WE BUILD IT?"

ALSO ASK:

"WHAT CAN GO WRONG?"

"WHO COULD ABUSE IT?"

"WHAT HAPPENS IF THE INPUT IS MALICIOUS?"

"WHAT HAPPENS IF IDENTITY IS UNCERTAIN?"

"WHAT HAPPENS IF THE PROVIDER LIES?"

"WHAT HAPPENS IF THE NETWORK FAILS?"

"WHAT HAPPENS IF THE USER INTERRUPTS?"

"WHAT HAPPENS IF TWO PEOPLE ARE SPEAKING?"

"WHAT HAPPENS IF THE MODEL IS WRONG?"

"WHAT HAPPENS IF THE DEVICE IS LOW-END?"

"WHAT HAPPENS IF THE BATTERY IS LOW?"

"WHAT HAPPENS IF THE SESSION EXPIRES?"

"WHAT HAPPENS IF THE SAME REQUEST IS REPLAYED?"

"WHAT HAPPENS IF DATA CONFLICTS?"

"WHAT HAPPENS IF THE EXTERNAL CONTENT CONTAINS PROMPT INJECTION?"

"CAN THE FEATURE FAIL SAFELY?"

"CAN THE FEATURE BE MADE SIMPLER?"

"CAN THE FEATURE BE MADE MORE NATURAL?"

"CAN THE FEATURE BE MADE MORE PRIVATE?"

"CAN THE FEATURE BE MADE MORE TRUSTWORTHY?"

"CAN THE EXPERIENCE BE IMPROVED WITHOUT WEAKENING SECURITY?"

Every feature must be evaluated against these questions before implementation.

============================================================
110. FINAL OBJECTIVE
============================================================

Build JURIX so that the user does not feel like they are operating software.

They should feel like they are interacting with a sophisticated personal assistant.

But underneath that natural experience:

OVELA IS ALWAYS WATCHING THE BOUNDARIES.

OVELA PROTECTS THE DATA.

OVELA PROTECTS THE USER.

OVELA PROTECTS THE FINANCIAL SYSTEM.

OVELA PROTECTS AUTHORITY.

OVELA PROTECTS PRIVACY.

JURIX PROVIDES THE HUMAN EXPERIENCE.

OVELA PROVIDES THE TRUST.

THE TWO MUST NEVER BE CONFUSED.