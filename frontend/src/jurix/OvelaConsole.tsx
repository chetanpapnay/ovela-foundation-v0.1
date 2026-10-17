import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic, MicOff, Paperclip, Send, X, TrendingUp, ShieldAlert, Radio } from "lucide-react";
import { JurixDirector, type DirectorPerformancePlan } from "./JurixDirector";

const FINANCIAL_PLAN: DirectorPerformancePlan = {
  planId: "exec-plan-001",
  totalDurationMs: 9000,
  speechText: "Reviewing institutional liquidity invariants. Note the anomalous settlement peak in July, followed by normalized runway.",
  postureSequence: [
    { ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "GREETING_NOD" },
    { ptsMs: 1200, posture: "STAND_TRANSITION", gaze: "HOLOGRAM_DATA", gesture: "STAND_UP" },
    { ptsMs: 2800, posture: "PRESENT_HOLOGRAM", gaze: "HOLOGRAM_DATA", gesture: "POINT_DELTA", activeNodeId: "node-peak" },
    { ptsMs: 7200, posture: "SEATED_TRANSITION", gaze: "CAMERA_USER", gesture: "RETURN_SEAT" },
    { ptsMs: 8800, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "IDLE_BREATHING" },
  ],
  hologram: {
    title: "Operating Reserve Trajectory",
    metrics: [
      { id: "node-base", label: "Reserve Net", value: "₹ 1,48,250", delta: "+14.2%" },
      { id: "node-peak", label: "July Inflow", value: "₹ 52,100", delta: "Anomalous Settlement", isAnomalous: true },
      { id: "node-rate", label: "Burn Run-Rate", value: "₹ 38,000/mo", delta: "Nominal" },
    ],
    series: [
      { label: "Apr", value: 32 },
      { label: "May", value: 44 },
      { label: "Jun", value: 38 },
      { label: "Jul", value: 88 },
      { label: "Aug", value: 46 },
      { label: "Sep", value: 42 },
    ],
  },
};

export const OvelaConsole: React.FC = () => {
  const directorRef = useRef(new JurixDirector());
  const [isStanding, setIsStanding] = useState(false);
  const [activeNode, setActiveNode] = useState<string | undefined>(undefined);
  const [subtitle, setSubtitle] = useState<string>("Ready. Awaiting executive directives.");
  const [isVoiceActive, setIsVoiceActive] = useState<boolean>(false);
  const [showConsole, setShowConsole] = useState<boolean>(false);
  const [chatMessage, setChatMessage] = useState<string>("");
  const [connectionStatus, setConnectionStatus] = useState<"CONNECTED" | "STREAMING" | "STANDBY">("CONNECTED");
  const [attachments, setAttachments] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const videoElementRef = useRef<HTMLVideoElement>(null);

  // Synchronize Director Clock
  useEffect(() => {
    let animId: number;
    const tick = () => {
      const state = directorRef.current.getCurrentState();
      const standing = state.posture === "STAND_TRANSITION" || state.posture === "PRESENT_HOLOGRAM";
      setIsStanding(standing);
      setActiveNode(state.activeNodeId);
      animId = requestAnimationFrame(tick);
    };
    animId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animId);
  }, []);

  // Keyboard Shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setShowConsole((prev) => !prev);
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "u") {
        e.preventDefault();
        fileInputRef.current?.click();
      }
      if (e.key === "Escape") setShowConsole(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const handleInterrupt = () => {
    directorRef.current.interrupt();
    setSubtitle("Listening...");
    setConnectionStatus("CONNECTED");
  };

  const handleTriggerChoreography = () => {
    if (isStanding) {
      handleInterrupt();
    } else {
      directorRef.current.loadPlan(FINANCIAL_PLAN);
      setSubtitle(FINANCIAL_PLAN.speechText);
      setConnectionStatus("STREAMING");
    }
  };

  return (
    <div style={{ position: "relative", width: "100vw", height: "100vh", overflow: "hidden", backgroundColor: "#020408", color: "#f8fafc", userSelect: "none" }}>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: "none" }}
        onChange={(e) => {
          if (e.target.files) setAttachments(Array.from(e.target.files));
        }}
      />

      {/* 1. Full-Bleed Neural Media Stream */}
      <motion.div
        animate={{
          scale: isStanding ? 1.04 : 1.0,
          x: isStanding ? "-6%" : "0%",
        }}
        transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
        style={{
          position: "absolute",
          inset: 0,
          width: "100%",
          height: "100%",
          zIndex: 1,
        }}
      >
        <video
          ref={videoElementRef}
          src="/video/exec_seated.mp4"
          autoPlay
          loop
          muted
          playsInline
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover",
            display: "block",
            filter: "brightness(0.9) contrast(1.06)",
          }}
        />
        {/* Cinematic Vignette */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            background: isStanding
              ? "radial-gradient(ellipse at 75% 50%, rgba(14, 165, 233, 0.15) 0%, transparent 65%), linear-gradient(180deg, rgba(2,6,14,0.6) 0%, transparent 35%, transparent 70%, rgba(2,6,14,0.9) 100%)"
              : "linear-gradient(180deg, rgba(2,6,14,0.6) 0%, transparent 35%, transparent 70%, rgba(2,6,14,0.9) 100%)",
            transition: "background 0.8s ease",
            pointerEvents: "none",
          }}
        />
      </motion.div>

      {/* 2. Top Header HUD */}
      <header
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          padding: "20px 32px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "linear-gradient(180deg, rgba(2,6,14,0.85) 0%, rgba(2,6,14,0.4) 70%, transparent 100%)",
          backdropFilter: "blur(8px)",
          zIndex: 30,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "#38bdf8", boxShadow: "0 0 12px #38bdf8" }} />
          <span style={{ fontSize: "12px", letterSpacing: "0.2em", fontFamily: "monospace", color: "#e2e8f0", fontWeight: 600 }}>
            OVELA EXECUTIVE // SOVEREIGN
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "11px", fontFamily: "monospace", color: "#38bdf8", background: "rgba(14, 165, 233, 0.12)", backdropFilter: "blur(12px)", padding: "6px 14px", borderRadius: "9999px", border: "1px solid rgba(56, 189, 248, 0.25)" }}>
          <Radio size={12} />
          <span>LIVE WEBRTC : {connectionStatus}</span>
        </div>
      </header>

      {/* 3. Floating Holographic Presentation Array */}
      <AnimatePresence>
        {isStanding && (
          <motion.div
            initial={{ opacity: 0, x: 120, scale: 0.92 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 100, scale: 0.9, filter: "blur(8px)" }}
            transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
            style={{
              position: "absolute",
              right: "4%",
              top: "14%",
              bottom: "16%",
              width: "560px",
              maxWidth: "92vw",
              zIndex: 25,
              borderRadius: "32px",
              border: "1px solid rgba(56, 189, 248, 0.35)",
              background: "linear-gradient(135deg, rgba(8, 20, 42, 0.84) 0%, rgba(2, 6, 16, 0.94) 100%)",
              backdropFilter: "blur(32px)",
              boxShadow: "0 40px 80px rgba(0, 0, 0, 0.85), 0 0 50px rgba(14, 165, 233, 0.2)",
              padding: "32px",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
            }}
          >
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(56, 189, 248, 0.2)", paddingBottom: "16px", marginBottom: "22px" }}>
                <div>
                  <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#38bdf8", letterSpacing: "0.2em", textTransform: "uppercase" }}>
                    SPATIAL PROJECTION
                  </span>
                  <h2 style={{ fontSize: "20px", fontWeight: 600, color: "#f8fafc", margin: "4px 0 0 0", fontFamily: "monospace" }}>
                    Operating Reserve Trajectory
                  </h2>
                </div>
                <button
                  onClick={handleInterrupt}
                  style={{ background: "rgba(255,255,255,0.06)", border: "none", color: "#94a3b8", cursor: "pointer", padding: "6px", borderRadius: "50%" }}
                >
                  <X size={18} />
                </button>
              </div>

              {/* Holographic Metric Nodes */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "24px" }}>
                {FINANCIAL_PLAN.hologram.metrics.map((m) => {
                  const isActive = activeNode === m.id;
                  return (
                    <motion.div
                      key={m.id}
                      animate={{
                        scale: isActive ? 1.04 : 1.0,
                        borderColor: isActive ? "#38bdf8" : "rgba(56, 189, 248, 0.2)",
                        backgroundColor: isActive ? "rgba(14, 165, 233, 0.25)" : "rgba(2, 6, 16, 0.6)",
                      }}
                      style={{
                        padding: "16px",
                        borderRadius: "18px",
                        border: "1px solid rgba(56, 189, 248, 0.2)",
                        boxShadow: isActive ? "0 0 25px rgba(56, 189, 248, 0.45)" : "none",
                        transition: "all 0.3s ease",
                      }}
                    >
                      <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#94a3b8", textTransform: "uppercase", display: "block" }}>
                        {m.label}
                      </span>
                      <span style={{ fontSize: "16px", fontWeight: 700, fontFamily: "monospace", color: "#f8fafc", marginTop: "4px", display: "block" }}>
                        {m.value}
                      </span>
                      <span style={{ fontSize: "11px", fontFamily: "monospace", color: m.isAnomalous ? "#fbbf24" : "#34d399", marginTop: "4px", display: "flex", alignItems: "center", gap: "4px" }}>
                        {m.isAnomalous ? <ShieldAlert size={12} /> : <TrendingUp size={12} />}
                        {m.delta}
                      </span>
                    </motion.div>
                  );
                })}
              </div>
            </div>

            {/* Glowing Volumetric Bar Chart */}
            <div style={{ height: "160px", display: "flex", alignItems: "flex-end", justifyContent: "space-between", padding: "20px 12px 10px", background: "rgba(0, 0, 0, 0.5)", borderRadius: "20px", border: "1px solid rgba(56, 189, 248, 0.15)" }}>
              {FINANCIAL_PLAN.hologram.series.map((item, idx) => {
                const isPeak = item.label === "Jul";
                const barHeight = item.value + "%";
                return (
                  <div key={idx} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "10px" }}>
                    <div style={{ width: "28px", height: "100px", display: "flex", alignItems: "flex-end" }}>
                      <div
                        style={{
                          width: "100%",
                          height: barHeight,
                          borderRadius: "6px 6px 0 0",
                          background: isPeak ? "linear-gradient(180deg, #38bdf8 0%, #0284c7 100%)" : "linear-gradient(180deg, #334155 0%, #0f172a 100%)",
                          boxShadow: isPeak ? "0 0 24px rgba(56, 189, 248, 0.7)" : "none",
                        }}
                      />
                    </div>
                    <span style={{ fontSize: "11px", fontFamily: "monospace", color: isPeak ? "#38bdf8" : "#64748b", fontWeight: isPeak ? "bold" : "normal" }}>
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 4. Subtitle Capsule */}
      <div style={{ position: "absolute", bottom: "100px", left: 0, right: 0, display: "flex", justifyContent: "center", pointerEvents: "none", zIndex: 30, padding: "0 24px" }}>
        <p style={{ maxWidth: "700px", textAlign: "center", fontSize: "15px", color: "#f8fafc", fontWeight: 400, letterSpacing: "0.02em", background: "rgba(4, 10, 22, 0.65)", backdropFilter: "blur(16px)", border: "1px solid rgba(56, 189, 248, 0.2)", padding: "10px 24px", borderRadius: "9999px", boxShadow: "0 10px 25px rgba(0,0,0,0.5)" }}>
          {subtitle}
        </p>
      </div>

      {/* 5. Command Dock */}
      <nav
        style={{
          position: "absolute",
          bottom: "28px",
          left: 0,
          right: 0,
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          zIndex: 35,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            background: "rgba(6, 12, 24, 0.85)",
            backdropFilter: "blur(24px)",
            border: "1px solid rgba(56, 189, 248, 0.25)",
            padding: "8px 20px",
            borderRadius: "9999px",
            boxShadow: "0 20px 40px rgba(0, 0, 0, 0.8)",
          }}
        >
          <button
            onClick={() => setIsVoiceActive(!isVoiceActive)}
            style={{
              padding: "10px",
              borderRadius: "50%",
              border: "none",
              backgroundColor: isVoiceActive ? "#38bdf8" : "rgba(255, 255, 255, 0.08)",
              color: isVoiceActive ? "#020408" : "#94a3b8",
              cursor: "pointer",
            }}
          >
            {isVoiceActive ? <Mic size={15} /> : <MicOff size={15} />}
          </button>

          <button
            onClick={() => fileInputRef.current?.click()}
            style={{ padding: "10px", borderRadius: "50%", border: "none", background: "transparent", color: "#94a3b8", cursor: "pointer" }}
            title="Attach Document (Ctrl+U)"
          >
            <Paperclip size={15} />
          </button>

          <button
            onClick={() => setShowConsole(!showConsole)}
            style={{
              padding: "6px 14px",
              borderRadius: "9999px",
              border: "1px solid rgba(56, 189, 248, 0.2)",
              background: showConsole ? "rgba(56, 189, 248, 0.2)" : "transparent",
              color: "#e2e8f0",
              fontSize: "12px",
              fontFamily: "monospace",
              cursor: "pointer",
            }}
          >
            Command (Ctrl+K)
          </button>

          <button
            onClick={handleTriggerChoreography}
            style={{
              padding: "8px 18px",
              borderRadius: "9999px",
              border: "none",
              background: isStanding ? "rgba(239, 68, 68, 0.25)" : "rgba(14, 165, 233, 0.25)",
              color: isStanding ? "#f87171" : "#38bdf8",
              fontSize: "12px",
              fontFamily: "monospace",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            {isStanding ? "Interrupt & Sit" : "Initiate Holographic Projection"}
          </button>
        </div>
      </nav>

      {/* 6. Ephemeral Command Drawer */}
      <AnimatePresence>
        {showConsole && (
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.98 }}
            transition={{ duration: 0.15 }}
            style={{
              position: "absolute",
              bottom: "86px",
              left: "50%",
              transform: "translateX(-50%)",
              width: "520px",
              maxWidth: "92vw",
              background: "rgba(6, 12, 24, 0.96)",
              backdropFilter: "blur(28px)",
              border: "1px solid rgba(56, 189, 248, 0.3)",
              borderRadius: "24px",
              padding: "16px",
              boxShadow: "0 25px 50px rgba(0, 0, 0, 0.9)",
              zIndex: 45,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <span style={{ fontSize: "11px", color: "#64748b", fontFamily: "monospace" }}>
                EXECUTIVE DIRECTIVE
              </span>
              <button onClick={() => setShowConsole(false)} style={{ background: "transparent", border: "none", color: "#64748b", cursor: "pointer" }}>
                <X size={15} />
              </button>
            </div>

            {attachments.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "10px" }}>
                {attachments.map((f, i) => (
                  <span key={i} style={{ fontSize: "11px", background: "rgba(15, 23, 42, 0.8)", border: "1px solid #334155", padding: "4px 8px", borderRadius: "6px", color: "#cbd5e1", fontFamily: "monospace" }}>
                    {f.name}
                  </span>
                ))}
              </div>
            )}

            <div style={{ display: "flex", gap: "8px" }}>
              <input
                type="text"
                placeholder="Ask about revenue, burn, or audit invariants..."
                value={chatMessage}
                onChange={(e) => setChatMessage(e.target.value)}
                style={{
                  flex: 1,
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(56, 189, 248, 0.2)",
                  borderRadius: "14px",
                  padding: "10px 14px",
                  fontSize: "13px",
                  color: "#f8fafc",
                  outline: "none",
                }}
                autoFocus
              />
              <button
                onClick={() => {
                  if (chatMessage.trim()) {
                    setChatMessage("");
                    setShowConsole(false);
                  }
                }}
                style={{
                  padding: "10px 14px",
                  background: "#0284c7",
                  border: "none",
                  borderRadius: "14px",
                  color: "white",
                  cursor: "pointer",
                }}
              >
                <Send size={14} />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
