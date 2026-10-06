export type JurixPresenceState =
  | "IDLE"
  | "LISTENING"
  | "THINKING"
  | "SPEAKING"
  | "FOCUSED"
  | "CLARIFYING"
  | "SECURITY_FOCUSED"
  | "SECURITY_BLOCKED"
  | "PRIVATE_MODE"
  | "UNAVAILABLE";

export type JurixAttention =
  | "USER"
  | "SCREEN"
  | "DATA"
  | "SECURITY"
  | "NEUTRAL";

export type JurixExpression =
  | "NEUTRAL"
  | "WARM"
  | "ATTENTIVE"
  | "CONSIDERING"
  | "SERIOUS"
  | "FIRM"
  | "CAUTIOUS";

export type JurixPosture =
  | "RESTING"
  | "ATTENTIVE"
  | "THOUGHTFUL"
  | "ENGAGED"
  | "GUARDED";

export type JurixVoiceStyle =
  | "CALM"
  | "WARM"
  | "PRECISE"
  | "CAUTIOUS"
  | "FIRM"
  | "SILENT";

export type JurixSecurityPosture =
  | "NORMAL"
  | "SENSITIVE"
  | "SUSPICIOUS"
  | "BLOCKED";

export interface JurixPresencePlan {
  state: JurixPresenceState;
  attention: JurixAttention;
  expression: JurixExpression;
  posture: JurixPosture;
  voice: JurixVoiceStyle;
  security: JurixSecurityPosture;

  listening: boolean;
  speaking: boolean;
  allowSensitiveSpeech: boolean;

  gazeIntensity: number;
  movementIntensity: number;
  breathingIntensity: number;

  interruptible: boolean;
  reducedMotion: boolean;
}

export interface JurixPresenceContext {
  authenticated: boolean;
  privateMode: boolean;
  suspiciousActivity: boolean;
  securityBlocked: boolean;
  sensitiveContent: boolean;
  speaking: boolean;
  listening: boolean;
  thinking: boolean;
  focused: boolean;
  clarifying: boolean;
  unavailable: boolean;
  reducedMotion?: boolean;
}

const clamp = (
  value: number,
  minimum = 0,
  maximum = 1,
): number => Math.min(maximum, Math.max(minimum, value));

const basePlan = (
  context: JurixPresenceContext,
): JurixPresencePlan => ({
  state: "IDLE",
  attention: "USER",
  expression: "NEUTRAL",
  posture: "RESTING",
  voice: "CALM",
  security: "NORMAL",

  listening: false,
  speaking: false,
  allowSensitiveSpeech:
    context.authenticated && !context.privateMode,

  gazeIntensity: 0.72,
  movementIntensity: 0.42,
  breathingIntensity: 0.58,

  interruptible: true,
  reducedMotion: context.reducedMotion ?? false,
});

export function deriveJurixPresence(
  context: JurixPresenceContext,
): JurixPresencePlan {
  const plan = basePlan(context);

  /*
   * Security has priority over conversational state.
   *
   * The frontend can represent a security state, but it cannot
   * authorize anything. The trusted backend remains authoritative.
   */

  if (context.unavailable) {
    return {
      ...plan,
      state: "UNAVAILABLE",
      attention: "NEUTRAL",
      expression: "CAUTIOUS",
      posture: "GUARDED",
      voice: "SILENT",
      security: "BLOCKED",
      listening: false,
      speaking: false,
      allowSensitiveSpeech: false,
      gazeIntensity: 0.2,
      movementIntensity: 0.08,
      breathingIntensity: 0.25,
      interruptible: false,
    };
  }

  if (context.securityBlocked) {
    return {
      ...plan,
      state: "SECURITY_BLOCKED",
      attention: "SECURITY",
      expression: "FIRM",
      posture: "GUARDED",
      voice: "FIRM",
      security: "BLOCKED",
      listening: false,
      speaking: false,
      allowSensitiveSpeech: false,
      gazeIntensity: 0.92,
      movementIntensity: 0.12,
      breathingIntensity: 0.38,
      interruptible: true,
    };
  }

  if (context.suspiciousActivity) {
    return {
      ...plan,
      state: "SECURITY_FOCUSED",
      attention: "SECURITY",
      expression: "SERIOUS",
      posture: "GUARDED",
      voice: "FIRM",
      security: "SUSPICIOUS",
      listening: context.listening,
      speaking: context.speaking,
      allowSensitiveSpeech: false,
      gazeIntensity: 0.96,
      movementIntensity: 0.18,
      breathingIntensity: 0.42,
      interruptible: true,
    };
  }

  if (context.privateMode) {
    return {
      ...plan,
      state: "PRIVATE_MODE",
      attention: "USER",
      expression: "ATTENTIVE",
      posture: "ATTENTIVE",
      voice: context.speaking ? "CALM" : "SILENT",
      security: "SENSITIVE",
      listening: context.listening,
      speaking: context.speaking,
      allowSensitiveSpeech: false,
      gazeIntensity: 0.94,
      movementIntensity: 0.24,
      breathingIntensity: 0.5,
      interruptible: true,
    };
  }

  if (context.sensitiveContent) {
    return {
      ...plan,
      state: context.speaking ? "SPEAKING" : "FOCUSED",
      attention: "USER",
      expression: "SERIOUS",
      posture: "ATTENTIVE",
      voice: context.speaking ? "PRECISE" : "SILENT",
      security: "SENSITIVE",
      listening: context.listening,
      speaking: context.speaking,
      allowSensitiveSpeech:
        context.authenticated && !context.privateMode,
      gazeIntensity: 0.9,
      movementIntensity: 0.28,
      breathingIntensity: 0.5,
      interruptible: true,
    };
  }

  if (context.clarifying) {
    return {
      ...plan,
      state: "CLARIFYING",
      attention: "USER",
      expression: "ATTENTIVE",
      posture: "ATTENTIVE",
      voice: "WARM",
      listening: true,
      speaking: false,
      allowSensitiveSpeech: context.authenticated,
      gazeIntensity: 0.94,
      movementIntensity: 0.34,
      breathingIntensity: 0.56,
      interruptible: true,
    };
  }

  if (context.speaking) {
    return {
      ...plan,
      state: "SPEAKING",
      attention: "USER",
      expression: "WARM",
      posture: "ENGAGED",
      voice: "CALM",
      listening: false,
      speaking: true,
      allowSensitiveSpeech: context.authenticated,
      gazeIntensity: 0.82,
      movementIntensity: 0.48,
      breathingIntensity: 0.64,
      interruptible: true,
    };
  }

  if (context.thinking) {
    return {
      ...plan,
      state: "THINKING",
      attention: "SCREEN",
      expression: "CONSIDERING",
      posture: "THOUGHTFUL",
      voice: "SILENT",
      listening: false,
      speaking: false,
      allowSensitiveSpeech: context.authenticated,
      gazeIntensity: 0.52,
      movementIntensity: 0.25,
      breathingIntensity: 0.56,
      interruptible: true,
    };
  }

  if (context.listening) {
    return {
      ...plan,
      state: "LISTENING",
      attention: "USER",
      expression: "ATTENTIVE",
      posture: "ATTENTIVE",
      voice: "SILENT",
      listening: true,
      speaking: false,
      allowSensitiveSpeech: context.authenticated,
      gazeIntensity: 0.97,
      movementIntensity: 0.34,
      breathingIntensity: 0.62,
      interruptible: true,
    };
  }

  if (context.focused) {
    return {
      ...plan,
      state: "FOCUSED",
      attention: "DATA",
      expression: "CONSIDERING",
      posture: "ENGAGED",
      voice: "SILENT",
      listening: false,
      speaking: false,
      allowSensitiveSpeech: context.authenticated,
      gazeIntensity: 0.74,
      movementIntensity: 0.3,
      breathingIntensity: 0.55,
      interruptible: true,
    };
  }

  return plan;
}

export function createDefaultJurixContext(): JurixPresenceContext {
  return {
    authenticated: false,
    privateMode: false,
    suspiciousActivity: false,
    securityBlocked: false,
    sensitiveContent: false,
    speaking: false,
    listening: false,
    thinking: false,
    focused: false,
    clarifying: false,
    unavailable: false,
    reducedMotion: false,
  };
}

export function sanitizePresencePlan(
  plan: JurixPresencePlan,
): JurixPresencePlan {
  return {
    ...plan,
    gazeIntensity: clamp(plan.gazeIntensity),
    movementIntensity: clamp(plan.movementIntensity),
    breathingIntensity: clamp(plan.breathingIntensity),
    allowSensitiveSpeech:
      plan.allowSensitiveSpeech &&
      plan.security !== "BLOCKED" &&
      plan.security !== "SUSPICIOUS" &&
      plan.state !== "PRIVATE_MODE",
  };
}