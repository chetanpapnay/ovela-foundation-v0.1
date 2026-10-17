const fs = require("fs");
const path = "src/jurix/OvelaConsole.tsx";

const content = `import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic, MicOff, Paperclip, Send, X, TrendingUp, ShieldAlert, Cpu } from "lucide-react";
import { JurixDirector, type DirectorPerformancePlan } from "./JurixDirector";

const FINANCIAL_PLAN: DirectorPerformancePlan = {
  planId: "exec-plan-001",
  totalDurationMs: 9000,
  speechText: "Analyzing sovereign reserves across Q2 and Q3. July registered an anomalous liquidity settlement before burn rate stabilized.",
  postureSequence: [
    { ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "GREETING_NOD" },
    { ptsMs: 1200, posture: "STAND_TRANSITION", gaze: "HOLOGRAM_DATA", gesture: "STAND_UP" },
    { ptsMs: 2800, posture: "PRESENT_HOLOGRAM", gaze: "HOLOGRAM_DATA", gesture: "POINT_DELTA", activeNodeId: "node-peak" },
    { ptsMs: 7200, posture: "SEATED_TRANSITION", gaze: "CAMERA_USER", gesture: "RETURN_SEAT" },
    { ptsMs: 8800, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "IDLE_BREATHING" },
  ],
  hologram: {
    title: "OPERATING RESERVE TRAJECTORY",
    metrics: [
      { id: "node-base", label: "RESERVE NET", value: "₹ 1,48,250", delta: "+14.2%" },
      { id: "node-peak", label: "JULY INFLOW", value: "₹ 52,100", delta: "ANOMALY", isAnomalous: true },
      { id: "node-rate", label: "BURN RATE", value: "₹ 38,000/mo", delta: "NOMINAL" },
    ],
    series: [
      { label: "APR", value: 34 },
      { label: "MAY", value: 46 },
      { label: "JUN", value: 38 },
      { label: "JUL", value: 92 },
      { label: "AUG", value: 48 },
      { label: "SEP", value: 44 },
    ],
  },
};

export const OvelaConsole: React.FC = () => {
  const directorRef = useRef(new JurixDirector());
  const [isStanding, setIsStanding] = useState(false);
  const [activeNode, setActiveNode] = useState<string | undefined>(undefined);
  const [subtitle, setSubtitle] = useState<string>("Executive console standby. State your objective.");
  const [isVoiceActive, setIsVoiceActive] = useState<boolean>(false);
  const [showConsole, setShowConsole] = useState<boolean>(false);
  const [chatMessage, setChatMessage] = useState<string>("");
  const [attachments, setAttachments] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
    setSubtitle("Standing by...");
  };

  const handleTriggerChoreography = () => {
    if (isStanding) {
      handleInterrupt();
    } else {
      directorRef.current.loadPlan(FINANCIAL_PLAN);
      setSubtitle(FINANCIAL_PLAN.speechText);
    }
  };

  return (
    <div style={{ position: "relative", width: "100vw", height: "100vh", overflow: "hidden", backgroundColor: "#010408", color: "#f8fafc", userSelect: "none" }}>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: "none" }}
        onChange={(e) => {
          if (e.target.files) setAttachments(Array.from(e.target.files));
        }}
      />

      {/* 1. Full-Bleed Video Stage (Fills 100% of any desktop or mobile display) */}
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
            filter: "brightness(0.92) contrast(1.08)",
          }}
        />
        {/* Holographic Cyan Ambient Light Tint */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            background: isStanding
              ? "radial-gradient(ellipse at 80% 40%, rgba(34, 211, 238, 0.18) 0%, transparent 60%), linear-gradient(180deg, rgba(1,4,8,0.4) 0%, transparent 30%, rgba(1,4,8,0.8) 100%)"
              : "linear-gradient(180deg, rgba(1,4,8,0.4) 0%, transparent 30%, rgba(1,4,8,0.7) 100%)",
            transition: "background 1s ease",
            pointerEvents: "none",
          }}
        />
      </motion.div>

      {/* 2. Sleek Architectural Top Header */}
      <header
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          padding: "24px 32px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          zIndex: 30,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ width: "7px", height: "7px", borderRadius: "50%", backgroundColor: "#38bdf8", boxShadow: "0 0 10px #38bdf8" }} />
          <span style={{ fontSize: "11px", letterSpacing: "0.22em", fontFamily: "monospace", color: "#94a3b8", textTransform: "uppercase" }}>
            JURIX // CORE REPOSITORY
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", fontFamily: "monospace", color: "#38bdf8", background: "rgba(14, 165, 233, 0.1)", backdropFilter: "blur(12px)", padding: "5px 14px", borderRadius: "9999px", border: "1px solid rgba(56, 189, 248, 0.25)" }}>
          <Cpu size={12} />
          <span>REAL-TIME TELEMETRY</span>
        </div>
      </header>

      {/* 3. The Futuristic Volumetric Hologram (Floating in 3D Space) */}
      <AnimatePresence>
        {isStanding && (
          <motion.div
            initial={{ opacity: 0, x: 100, scale: 0.92, rotateY: 8 }}
            animate={{ opacity: 1, x: 0, scale: 1, rotateY: 0 }}
            exit={{ opacity: 0, x: 80, scale: 0.9, filter: "blur(8px)" }}
            transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
            style={{
              position: "absolute",
              right: "5%",
              top: "14%",
              bottom: "16%",
              width: "580px",
              maxWidth: "92vw",
              zIndex: 25,
              borderRadius: "32px",
              border: "1px solid rgba(56, 189, 248, 0.4)",
              background: "linear-gradient(135deg, rgba(4, 16, 36, 0.78) 0%, rgba(1, 6, 18, 0.92) 100%)",
              backdropFilter: "blur(28px)",
              boxShadow: "0 30px 80px rgba(0, 0, 0, 0.85), 0 0 60px rgba(14, 165, 233, 0.25)",
              padding: "32px",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
            }}
          >
            {/* Holographic Hexagonal Grid Background */}
            <div
              style={{
                position: "absolute",
                inset: 0,
                backgroundImage: "radial-gradient(#38bdf8 0.75px, transparent 0.75px)",
                backgroundSize: "20px 20px",
                opacity: 0.12,
                borderRadius: "32px",
                pointerEvents: "none",
              }}
            />

            <div style={{ position: "relative", zIndex: 2 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(56, 189, 248, 0.2)", paddingBottom: "16px", marginBottom: "22px" }}>
                <div>
                  <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#38bdf8", letterSpacing: "0.25em", textTransform: "uppercase" }}>
                    VOLUMETRIC LEDGER INTERFACE
                  </span>
                  <h2 style={{ fontSize: "19px", fontWeight: 600, color: "#f8fafc", margin: "4px 0 0 0", fontFamily: "monospace", letterSpacing: "0.02em" }}>
                    Operating Reserve Trajectory
                  </h2>
                </div>
                <button
                  onClick={handleInterrupt}
                  style={{ background: "rgba(255,255,255,0.06)", border: "none", color: "#94a3b8", cursor: "pointer", padding: "6px", borderRadius: "50%" }}
                >
                  <X size={17} />
                </button>
              </div>

              {/* Holographic Floating Data Cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "24px" }}>
                {FINANCIAL_PLAN.hologram.metrics.map((m) => {
                  const isActive = activeNode === m.id;
                  return (
                    <motion.div
                      key={m.id}
                      animate={{
                        scale: isActive ? 1.05 : 1.0,
                        borderColor: isActive ? "#38bdf8" : "rgba(56, 189, 248, 0.2)",
                        backgroundColor: isActive ? "rgba(14, 165, 233, 0.25)" : "rgba(2, 8, 20, 0.6)",
                      }}
                      style={{
                        padding: "16px 14px",
                        borderRadius: "18px",
                        border: "1px solid rgba(56, 189, 248, 0.2)",
                        boxShadow: isActive ? "0 0 30px rgba(56, 189, 248, 0.5)" : "none",
                        transition: "all 0.3s ease",
                      }}
                    >
                      <span style={{ fontSize: "9px", fontFamily: "monospace", color: "#94a3b8", letterSpacing: "0.1em", textTransform: "uppercase", display: "block" }}>
                        {m.label}
                      </span>
                      <span style={{ fontSize: "16px", fontWeight: 700, fontFamily: "monospace", color: "#f8fafc", marginTop: "4px", display: "block" }}>
                        {m.value}
                      </span>
                      <span style={{ fontSize: "10px", fontFamily: "monospace", color: m.isAnomalous ? "#fbbf24" : "#34d399", marginTop: "4px", display: "flex", alignItems: "center", gap: "4px" }}>
                        {m.isAnomalous ? <ShieldAlert size={12} /> : <TrendingUp size={12} />}
                        {m.delta}
                      </span>
                    </motion.div>
                  );
                })}
              </div>
            </div>

            {/* Glowing Volumetric Bar Chart */}
            <div style={{ position: "relative", zIndex: 2, height: "160px", display: "flex", alignItems: "flex-end", justifyContent: "space-between", padding: "20px 14px 10px", background: "rgba(0, 0, 0, 0.45)", borderRadius: "20px", border: "1px solid rgba(56, 189, 248, 0.15)" }}>
              {FINANCIAL_PLAN.hologram.series.map((item, idx) => {
                const isPeak = item.label === "JUL";
                const barHeight = item.value + "%";
                return (
                  <div key={idx} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "8px" }}>
                    <div style={{ width: "30px", height: "100px", display: "flex", alignItems: "flex-end" }}>
                      <div
                        style={{
                          width: "100%",
                          height: barHeight,
                          borderRadius: "6px 6px 0 0",
                          background: isPeak ? "linear-gradient(180deg, #38bdf8 0%, #0284c7 100%)" : "linear-gradient(180deg, #1e293b 0%, #0f172a 100%)",
                          boxShadow: isPeak ? "0 0 25px rgba(56, 189, 248, 0.8)" : "none",
                        }}
                      />
                    </div>
                    <span style={{ fontSize: "10px", fontFamily: "monospace", color: isPeak ? "#38bdf8" : "#64748b", fontWeight: isPeak ? "bold" : "normal" }}>
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 4. Subtitle Stream */}
      <div style={{ position: "absolute", bottom: "96px", left: 0, right: 0, display: "flex", justifyContent: "center", pointerEvents: "none", zIndex: 30, padding: "0 24px" }}>
        <p style={{ maxWidth: "700px", textAlign: "center", fontSize: "16px", color: "#f8fafc", fontWeight: 300, lineHeight: 1.6, textShadow: "0 2px 14px rgba(0, 0, 0, 0.95)" }}>
          {subtitle}
        </p>
      </div>

      {/* 5. Minimal High-End Command Pill */}
      <nav
        style={{
          position: "absolute",
          bottom: "24px",
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
            background: "rgba(4, 12, 24, 0.82)",
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
              color: isVoiceActive ? "#010408" : "#94a3b8",
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
              bottom: "82px",
              left: "50%",
              transform: "translateX(-50%)",
              width: "520px",
              maxWidth: "92vw",
              background: "rgba(4, 12, 24, 0.96)",
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
                placeholder="Direct order or inquiry..."
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
`;

fs.writeFileSync(path, content, "utf8");
console.log("✓ Deployed Holographic HUD Engine");
