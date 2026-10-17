export type VoiceGatewayState = "idle" | "listening" | "error";

export interface VoiceGatewayCallbacks {
  onStateChange?: (state: VoiceGatewayState) => void;
  onTranscript?: (text: string) => void;
  onError?: (message: string) => void;
}

interface SpeechRecognitionErrorEvent extends Event {
  error: string;
  message?: string;
}

interface SpeechRecognitionEvent extends Event {
  resultIndex: number;
  results: SpeechRecognitionResultList;
}

interface SpeechRecognitionInstance extends EventTarget {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  start: () => void;
  stop: () => void;
  abort: () => void;
  onstart: ((this: SpeechRecognitionInstance, ev: Event) => void) | null;
  onresult: ((this: SpeechRecognitionInstance, ev: SpeechRecognitionEvent) => void) | null;
  onerror: ((this: SpeechRecognitionInstance, ev: SpeechRecognitionErrorEvent) => void) | null;
  onend: ((this: SpeechRecognitionInstance, ev: Event) => void) | null;
}

type SpeechRecognitionConstructor = new () => SpeechRecognitionInstance;

declare global {
  interface Window {
    SpeechRecognition?: SpeechRecognitionConstructor;
    webkitSpeechRecognition?: SpeechRecognitionConstructor;
  }
}

export class JurixVoiceGateway {
  private recognition: SpeechRecognitionInstance | null = null;
  private state: VoiceGatewayState = "idle";
  private callbacks: VoiceGatewayCallbacks = {};
  private shouldListen = false;
  private starting = false;
  private restartTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    const SpeechConstructor =
      typeof window !== "undefined"
        ? window.SpeechRecognition || window.webkitSpeechRecognition
        : undefined;

    if (!SpeechConstructor) return;

    try {
      const instance = new SpeechConstructor();
      instance.continuous = true;
      instance.interimResults = true;
      instance.lang = "en-US";

      instance.onstart = () => {
        this.starting = false;
        this.setState("listening");
      };

      instance.onresult = (event: SpeechRecognitionEvent) => {
        let finalTranscript = "";

        for (let i = event.resultIndex; i < event.results.length; i++) {
          const result = event.results[i];
          if (result.isFinal) {
            finalTranscript += result[0].transcript;
          }
        }

        if (finalTranscript.trim()) {
          this.callbacks.onTranscript?.(finalTranscript.trim());
        }
      };

      instance.onerror = (event: SpeechRecognitionErrorEvent) => {
        this.starting = false;

        if (
          event.error === "not-allowed" ||
          event.error === "service-not-allowed"
        ) {
          this.shouldListen = false;
          this.clearRestartTimer();
          this.setState("error");
          this.callbacks.onError?.(
            "Microphone access denied. Check browser permissions."
          );
          return;
        }

        if (event.error === "aborted" && !this.shouldListen) {
          this.setState("idle");
          return;
        }

        this.callbacks.onError?.(
          `Speech recognition error: ${event.error}`
        );
      };

      instance.onend = () => {
        this.starting = false;

        if (this.shouldListen) {
          this.scheduleRestart();
        } else {
          this.setState("idle");
        }
      };

      this.recognition = instance;
    } catch (error) {
      console.error("Unable to initialize speech recognition:", error);
    }
  }

  public setCallbacks(callbacks: VoiceGatewayCallbacks): void {
    this.callbacks = callbacks;
  }

  public isSupported(): boolean {
    return this.recognition !== null;
  }

  public getState(): VoiceGatewayState {
    return this.state;
  }

  public start(): void {
    if (!this.recognition) {
      this.callbacks.onError?.(
        "Speech recognition is not supported in this browser."
      );
      return;
    }

    this.shouldListen = true;
    this.clearRestartTimer();
    this.beginRecognition();
  }

  public stop(): void {
    this.shouldListen = false;
    this.starting = false;
    this.clearRestartTimer();

    if (this.recognition) {
      try {
        this.recognition.stop();
      } catch {
        // Recognition may already have stopped.
      }
    }

    this.setState("idle");
  }

  private beginRecognition(): void {
    if (!this.shouldListen || !this.recognition || this.starting) return;

    this.starting = true;

    try {
      this.recognition.start();
    } catch {
      this.starting = false;
      this.scheduleRestart();
    }
  }

  private scheduleRestart(): void {
    if (!this.shouldListen || this.restartTimer !== null) return;

    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      this.beginRecognition();
    }, 300);
  }

  private clearRestartTimer(): void {
    if (this.restartTimer !== null) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }
  }

  private setState(state: VoiceGatewayState): void {
    this.state = state;
    this.callbacks.onStateChange?.(state);
  }
}
