const fs = require('fs');
const path = require('path');

const typesDir = path.join(__dirname, 'src', 'jurix', 'types');
fs.mkdirSync(typesDir, { recursive: true });

// 1. types/presentation.ts
const presentationTs = `export type PresentationMode =
  | "idle"
  | "listening"
  | "thinking"
  | "speaking"
  | "explaining"
  | "presenting";

export interface SpeechPlan {
  text: string;
  emphasis?: string[];
  pausesMs?: number[];
}

export interface SpatialPlan {
  jurixPosition: "center" | "left" | "right";
  workspaceVisible: boolean;
  workspacePriority: "none" | "secondary" | "primary";
}

export interface GazePlan {
  target: "user" | "workspace" | "offscreen_thinking";
}

export interface GesturePlan {
  intent: "none" | "welcome" | "present_workspace" | "indicate_metric" | "enumerate";
}

export interface ExpressionPlan {
  affect: "neutral" | "warm" | "focused" | "concerned" | "serious";
  intensity: number;
}

export interface MetricItem {
  label: string;
  value: string;
  delta?: string;
}

export interface ChartSeriesItem {
  label: string;
  value: number;
}

export interface WorkspacePayload {
  type: "none" | "financial_chart" | "comparison" | "timeline" | "document";
  title?: string;
  metrics?: MetricItem[];
  series?: ChartSeriesItem[];
  summary?: string;
}

export interface JurixPresentationPlan {
  id: string;
  mode: PresentationMode;
  speech?: SpeechPlan;
  spatial: SpatialPlan;
  gaze: GazePlan;
  gesture: GesturePlan;
  expression: ExpressionPlan;
  workspace: WorkspacePayload;
  allowInterruption: boolean;
}
`;
fs.writeFileSync(path.join(typesDir, 'presentation.ts'), presentationTs, 'utf8');
console.log('✓ Created src/jurix/types/presentation.ts');

// 2. JurixWebRTCStage.tsx
const jurixWebRTC = `import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";

interface JurixWebRTCStageProps {
  position: "center" | "left" | "right";
  isSpeaking: boolean;
  onPresentationEvent?: (event: unknown) => void;
  onInterrupt?: () => void;
}

export const JurixWebRTCStage: React.FC<JurixWebRTCStageProps> = ({
  position,
  isSpeaking,
  onPresentationEvent,
  onInterrupt,
}) => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const [connectionState, setConnectionState] = useState<string>("standby");

  useEffect(() => {
    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" }
      ],
    });
    pcRef.current = pc;

    pc.ontrack = (event) => {
      if (videoRef.current && event.streams[0]) {
        videoRef.current.srcObject = event.streams[0];
        setConnectionState("streaming");
      }
    };

    pc.onconnectionstatechange = () => {
      setConnectionState(pc.connectionState);
    };

    pc.ondatachannel = (event) => {
      const channel = event.channel;
      channel.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data);
          onPresentationEvent?.(payload);
        } catch {
          // ignore
        }
      };
    };

    async function initializeSignaling() {
      try {
        pc.addTransceiver("video", { direction: "recvonly" });
        pc.addTransceiver("audio", { direction: "recvonly" });

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        const response = await fetch("/api/realtime/webrtc-offer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sdp: offer.sdp, type: offer.type }),
        });

        if (response.ok) {
          const answer = await response.json();
          await pc.setRemoteDescription(new RTCSessionDescription(answer));
        } else {
          setConnectionState("standby");
        }
      } catch {
        setConnectionState("standby");
      }
    }

    initializeSignaling();

    return () => {
      pc.close();
      pcRef.current = null;
    };
  }, [onPresentationEvent]);

  const targetX = position === "left" ? -280 : position === "right" ? 280 : 0;

  return (
    <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10 overflow-hidden">
      <motion.div
        animate={{
          x: targetX,
          scale: position === "left" ? 0.94 : 1.0,
        }}
        transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        className="relative flex flex-col items-center justify-center pointer-events-auto cursor-pointer"
        onClick={onInterrupt}
      >
        <div
          className={\`absolute -inset-10 rounded-full blur-3xl transition-opacity duration-1000 pointer-events-none \${
            isSpeaking ? "bg-sky-500/20 opacity-100" : "bg-neutral-800/15 opacity-50"
          }\`}
        />

        <div className="relative w-[360px] h-[520px] md:w-[440px] md:h-[620px] overflow-hidden rounded-[2.5rem] border border-neutral-800/60 bg-gradient-to-b from-neutral-900/60 to-[#020408] shadow-[0_32px_64px_-12px_rgba(0,0,0,0.9)] backdrop-blur-xl">
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted={false}
            className="w-full h-full object-cover object-top mix-blend-screen select-none pointer-events-none"
          />

          {connectionState !== "streaming" && (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-8 text-center bg-gradient-to-b from-neutral-950 via-[#070b13] to-black">
              <div className="relative w-28 h-28 rounded-full border border-neutral-800/80 bg-neutral-900/50 flex items-center justify-center mb-6 shadow-inner">
                <span className="w-3.5 h-3.5 rounded-full bg-sky-400 animate-pulse shadow-[0_0_16px_#38bdf8]" />
              </div>
              <span className="text-xs font-mono tracking-[0.3em] text-neutral-300 uppercase font-semibold">
                JURIX NEURAL FEED
              </span>
              <p className="text-[11px] text-neutral-600 font-mono mt-2 tracking-wider">
                WEBRTC ULTRA-LOW LATENCY // READY
              </p>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
};
`;
fs.writeFileSync(path.join(__dirname, 'src', 'jurix', 'JurixWebRTCStage.tsx'), jurixWebRTC, 'utf8');
console.log('✓ Created src/jurix/JurixWebRTCStage.tsx');

// 3. OvelaConsole.tsx
const ovelaConsole = `import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic, MicOff, Paperclip, Send, X, TrendingUp } from "lucide-react";
import { JurixPresentationPlan } from "./types/presentation";
import { JurixWebRTCStage } from "./JurixWebRTCStage";

const DEMO_EXPLANATION_PLAN: JurixPresentationPlan = {
  id: "plan-demo-01",
  mode: "explaining",
  speech: {
    text: "Here is your asset trajectory. Notice the anomalous spike in July, followed by stabilized liquidity.",
    emphasis: ["asset trajectory", "spike in July"],
  },
  spatial: {
    jurixPosition: "left",
    workspaceVisible: true,
    workspacePriority: "primary",
  },
  gaze: {
    target: "workspace",
  },
  gesture: {
    intent: "indicate_metric",
  },
  expression: {
    affect: "focused",
    intensity: 0.85,
  },
  workspace: {
    type: "financial_chart",
    title: "Operating Liquidity Invariants",
    metrics: [
      { label: "Reserve Net", value: "₹ 1,48,250", delta: "+14.2%" },
      { label: "July Inflow", value: "₹ 52,100", delta: "Settled" },
      { label: "Burn Rate", value: "₹ 38,000/mo", delta: "Nominal" },
    ],
    series: [
      { label: "Apr", value: 32 },
      { label: "May", value: 44 },
      { label: "Jun", value: 38 },
      { label: "Jul", value: 88 },
      { label: "Aug", value: 46 },
      { label: "Sep", value: 42 },
    ],
    summary: "Ledger-confirmed balances. Execution boundary authenticated via capability signatures.",
  },
  allowInterruption: true,
};

const DEFAULT_CONVERSATION_PLAN: JurixPresentationPlan = {
  id: "plan-default",
  mode: "idle",
  speech: { text: "Good evening, Chetan. What shall we inspect?" },
  spatial: {
    jurixPosition: "center",
    workspaceVisible: false,
    workspacePriority: "none",
  },
  gaze: { target: "user" },
  gesture: { intent: "none" },
  expression: { affect: "warm", intensity: 0.5 },
  workspace: { type: "none" },
  allowInterruption: true,
};

export const OvelaConsole: React.FC = () => {
  const [currentPlan, setCurrentPlan] = useState<JurixPresentationPlan>(DEFAULT_CONVERSATION_PLAN);
  const [isVoiceActive, setIsVoiceActive] = useState<boolean>(false);
  const [showHiddenChat, setShowHiddenChat] = useState<boolean>(false);
  const [chatMessage, setChatMessage] = useState<string>("");
  const [attachments, setAttachments] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setShowHiddenChat((prev) => !prev);
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "u") {
        e.preventDefault();
        fileInputRef.current?.click();
      }
      if (e.key === "Escape") {
        setShowHiddenChat(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleInterrupt = () => {
    setCurrentPlan((prev) => ({
      ...prev,
      mode: "listening",
      gaze: { target: "user" },
      gesture: { intent: "none" },
      speech: { text: "Listening..." },
    }));
  };

  const handleToggleVoice = () => {
    if (isVoiceActive) {
      setIsVoiceActive(false);
      setCurrentPlan(DEFAULT_CONVERSATION_PLAN);
    } else {
      setIsVoiceActive(true);
      setCurrentPlan((prev) => ({
        ...prev,
        mode: "listening",
        gaze: { target: "user" },
        speech: { text: "Listening..." },
      }));
    }
  };

  const handleToggleChoreography = () => {
    if (currentPlan.spatial.workspaceVisible) {
      setCurrentPlan(DEFAULT_CONVERSATION_PLAN);
    } else {
      setCurrentPlan(DEMO_EXPLANATION_PLAN);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      setAttachments((prev) => [...prev, ...files]);
      setCurrentPlan((prev) => ({
        ...prev,
        mode: "thinking",
        gaze: { target: "workspace" },
        speech: { text: \`Attached \${files.length} document\${files.length > 1 ? "s" : ""}. Parsing invariants...\` },
      }));
      setTimeout(() => {
        setCurrentPlan(DEFAULT_CONVERSATION_PLAN);
      }, 2000);
    }
  };

  return (
    <main className="relative w-screen h-screen overflow-hidden bg-[#030508] text-neutral-100 select-none">
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleFileUpload}
      />

      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_35%,rgba(14,23,42,0.4)_0%,rgba(3,5,8,0.98)_80%)] pointer-events-none" />

      <div className="relative w-full h-full flex items-center justify-center p-8 lg:p-16">
        <JurixWebRTCStage
          position={currentPlan.spatial.jurixPosition}
          isSpeaking={currentPlan.mode === "speaking" || currentPlan.mode === "explaining"}
          onInterrupt={handleInterrupt}
        />

        <div className="absolute bottom-28 left-0 right-0 flex justify-center pointer-events-none z-20 px-6">
          <AnimatePresence mode="wait">
            {currentPlan.speech && (
              <motion.p
                key={currentPlan.speech.text}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.35 }}
                className="max-w-xl text-center text-sm md:text-base font-light text-neutral-300 tracking-wide leading-relaxed drop-shadow-md"
              >
                {currentPlan.speech.text}
              </motion.p>
            )}
          </AnimatePresence>
        </div>

        <AnimatePresence>
          {currentPlan.spatial.workspaceVisible && currentPlan.workspace.type === "financial_chart" && (
            <motion.section
              initial={{ opacity: 0, x: 100, scale: 0.96 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 80, scale: 0.96 }}
              transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
              className="absolute right-8 lg:right-24 top-20 bottom-24 w-[480px] max-w-[92vw] z-20 flex flex-col justify-center pointer-events-auto"
            >
              <div className="bg-[#080d16]/90 backdrop-blur-3xl border border-neutral-800/80 rounded-3xl p-7 shadow-[0_32px_64px_-12px_rgba(0,0,0,0.95)]">
                <div className="flex justify-between items-start border-b border-neutral-800/60 pb-4 mb-5">
                  <div>
                    <h2 className="text-sm font-semibold tracking-wide text-neutral-100 font-mono uppercase">
                      {currentPlan.workspace.title}
                    </h2>
                    <p className="text-[11px] text-neutral-500 font-mono mt-1">
                      SYNCHRONIZED WITH IMMUTABLE LEDGER
                    </p>
                  </div>
                  <button
                    onClick={() => setCurrentPlan(DEFAULT_CONVERSATION_PLAN)}
                    className="p-1 rounded-lg text-neutral-500 hover:text-white hover:bg-neutral-800/50 transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="grid grid-cols-3 gap-3 mb-6">
                  {currentPlan.workspace.metrics?.map((m, i) => (
                    <div key={i} className="bg-neutral-950/70 border border-neutral-800/60 rounded-2xl p-3.5 shadow-inner">
                      <span className="text-[9px] text-neutral-500 uppercase tracking-widest block font-mono">
                        {m.label}
                      </span>
                      <span className="text-sm font-bold font-mono text-neutral-200 mt-1 block">
                        {m.value}
                      </span>
                      {m.delta && (
                        <span className="text-[10px] text-emerald-400 mt-0.5 flex items-center font-mono">
                          <TrendingUp className="w-2.5 h-2.5 mr-1" />
                          {m.delta}
                        </span>
                      )}
                    </div>
                  ))}
                </div>

                <div className="h-44 flex items-end justify-between px-3 pt-6 pb-2 bg-neutral-950/50 rounded-2xl border border-neutral-800/40 shadow-inner">
                  {currentPlan.workspace.series?.map((item, idx) => (
                    <div key={idx} className="flex-1 flex flex-col items-center gap-2 group">
                      <div className="w-6 relative flex items-end justify-center h-32">
                        <motion.div
                          initial={{ height: 0 }}
                          animate={{ height: \`\${item.value}%\` }}
                          transition={{ duration: 0.9, delay: idx * 0.08, ease: "easeOut" }}
                          className={\`w-full rounded-t-sm transition-all \${
                            item.label === "Jul"
                              ? "bg-gradient-to-t from-sky-600 via-sky-400 to-amber-300 shadow-[0_0_16px_rgba(56,189,248,0.4)]"
                              : "bg-gradient-to-t from-neutral-800 to-neutral-600 group-hover:from-sky-700 group-hover:to-sky-400"
                          }\`}
                        />
                      </div>
                      <span className={\`text-[10px] font-mono \${item.label === "Jul" ? "text-amber-300 font-bold" : "text-neutral-500"}\`}>
                        {item.label}
                      </span>
                    </div>
                  ))}
                </div>

                {currentPlan.workspace.summary && (
                  <p className="text-xs text-neutral-400 leading-relaxed mt-4 pt-4 border-t border-neutral-800/60 font-light">
                    {currentPlan.workspace.summary}
                  </p>
                )}
              </div>
            </motion.section>
          )}
        </AnimatePresence>
      </div>

      <nav className="absolute bottom-6 left-0 right-0 flex justify-center items-center z-30 pointer-events-auto">
        <div className="flex items-center space-x-3 bg-neutral-950/80 backdrop-blur-3xl border border-neutral-800/80 px-4 py-2.5 rounded-full shadow-2xl">
          <button
            onClick={handleToggleVoice}
            className={\`p-3 rounded-full transition-all duration-300 \${
              isVoiceActive
                ? "bg-amber-400 text-black shadow-[0_0_20px_rgba(251,191,36,0.4)] scale-105"
                : "bg-neutral-900 text-neutral-400 hover:text-white hover:bg-neutral-800"
            }\`}
            title={isVoiceActive ? "Mute Voice Engine" : "Activate Voice Engine"}
          >
            {isVoiceActive ? <Mic className="w-4 h-4" /> : <MicOff className="w-4 h-4" />}
          </button>

          <button
            onClick={() => fileInputRef.current?.click()}
            title="Attach File (Ctrl+U)"
            className="p-3 text-neutral-400 hover:text-white hover:bg-neutral-800/60 rounded-full transition-colors"
          >
            <Paperclip className="w-4 h-4" />
          </button>

          <button
            onClick={() => setShowHiddenChat((prev) => !prev)}
            title="Summon Terminal (Ctrl+K)"
            className={\`px-3 py-1.5 rounded-full text-xs font-mono transition-colors \${
              showHiddenChat ? "bg-neutral-800 text-white" : "text-neutral-400 hover:text-white"
            }\`}
          >
            Ctrl+K
          </button>

          <button
            onClick={handleToggleChoreography}
            className="text-[11px] px-3.5 py-1.5 rounded-full bg-neutral-900 border border-neutral-800 text-neutral-300 hover:text-white hover:border-neutral-700 transition-colors font-mono"
          >
            {currentPlan.spatial.workspaceVisible ? "Reset Stage" : "Demo Choreography"}
          </button>
        </div>
      </nav>

      <AnimatePresence>
        {showHiddenChat && (
          <motion.aside
            initial={{ opacity: 0, y: 24, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.98 }}
            transition={{ duration: 0.2 }}
            className="absolute bottom-24 left-1/2 -translate-x-1/2 w-[540px] max-w-[92vw] z-40 bg-[#060a12]/95 backdrop-blur-3xl border border-neutral-800 rounded-3xl shadow-[0_24px_48px_rgba(0,0,0,0.8)] p-4 pointer-events-auto"
          >
            <div className="flex justify-between items-center mb-3">
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-neutral-500">
                SOVEREIGN COMMAND TRAY
              </span>
              <button
                onClick={() => setShowHiddenChat(false)}
                className="text-neutral-500 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {attachments.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {attachments.map((f, i) => (
                  <span
                    key={i}
                    className="text-[11px] bg-neutral-900 border border-neutral-800 px-2.5 py-1 rounded-lg text-neutral-300 flex items-center gap-1 font-mono"
                  >
                    {f.name}
                  </span>
                ))}
              </div>
            )}

            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Direct intent or instruction..."
                value={chatMessage}
                onChange={(e) => setChatMessage(e.target.value)}
                className="flex-1 bg-neutral-950/90 border border-neutral-800/80 rounded-2xl px-4 py-2.5 text-sm text-neutral-100 placeholder-neutral-600 outline-none focus:border-neutral-600 font-light"
                autoFocus
              />
              <button
                onClick={() => {
                  if (chatMessage.trim()) {
                    setChatMessage("");
                    setShowHiddenChat(false);
                  }
                }}
                className="p-3 bg-neutral-800 hover:bg-neutral-700 text-white rounded-2xl transition-colors"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </main>
  );
};
`;
fs.writeFileSync(path.join(__dirname, 'src', 'jurix', 'OvelaConsole.tsx'), ovelaConsole, 'utf8');
console.log('✓ Created src/jurix/OvelaConsole.tsx');

// 4. App.tsx
const appTsx = `import React from "react";
import { OvelaConsole } from "./jurix/OvelaConsole";

export function App() {
  return <OvelaConsole />;
}

export default App;
`;
fs.writeFileSync(path.join(__dirname, 'src', 'App.tsx'), appTsx, 'utf8');
console.log('✓ Updated src/App.tsx');
