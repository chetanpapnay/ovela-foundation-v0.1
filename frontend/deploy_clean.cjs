const fs = require("fs");
const path = "src/jurix/OvelaConsole.tsx";

const content = `import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic, MicOff, Paperclip, Send, X, TrendingUp, ShieldAlert } from "lucide-react";
import { JurixDirector, type DirectorPerformancePlan } from "./JurixDirector";

const FINANCIAL_PLAN: DirectorPerformancePlan = {
  planId: "exec-plan-001",
  totalDurationMs: 9000,
  speechText: "Reviewing our liquid reserves. Note the anomalous settlement peak in July, followed by stabilized operational runway.",
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
  const [subtitle, setSubtitle] = useState<string>("Good evening, Chetan. What shall we inspect?");
  const [isVoiceActive, setIsVoiceActive] = useState<boolean>(false);
  const [showConsole, setShowConsole] = useState<boolean>(false);
  const [chatMessage, setChatMessage] = useState<string>("");
  const [attachments, setAttachments] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const videoRef = useRef<HTMLVideoElement>(null);

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
    setSubtitle("Listening...");
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

      {/* Clean Architectural Backplate */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: "radial-gradient(ellipse at 50% 30%, #081120 0%, #020408 70%)",
          zIndex: 0,
        }}
      />

      {/* Stage: Presenter & Floating Data */}
      <div style={{ position: "relative", width: "100%", height: "100%", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 10 }}>
        
        {/* Presenter Video Window */}
        <motion.div
          animate={{
            x: isStanding ? -290 : 0,
            scale: isStanding ? 0.94 : 1.0,
          }}
          transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
          onClick={handleInterrupt}
          style={{
            position: "relative",
            width: "440px",
            height: "620px",
            maxWidth: "92vw",
            maxHeight: "75vh",
            borderRadius: "32px",
            border: "1px solid rgba(56, 189, 248, 0.2)",
            backgroundColor: "#000",
            boxShadow: "0 30px 60px rgba(0,0,0,0.9), 0 0 40px rgba(14, 165, 233, 0.12)",
            overflow: "hidden",
            cursor: "pointer",
          }}
        >
          {/* Real Full-Bleed Video Element */}
          <video
            ref={videoRef}
            src="/video/exec_seated.mp4"
            autoPlay
            loop
            muted
            playsInline
            style={{
              position: "absolute",
              inset: 0,
              width: "100%",
              height: "100%",
              objectFit: "cover",
            }}
          />

          {/* Subdued Glass Gradient on Video */}
          <div
            style={{
              position: "absolute",
              inset: 0,
              background: "linear-gradient(180deg, transparent 70%, rgba(2, 4, 8, 0.85) 100%)",
              pointerEvents: "none",
            }}
          />
        </motion.div>

        {/* Financial Board */}
        <AnimatePresence>
          {isStanding && (
            <motion.div
              initial={{ opacity: 0, x: 80, scale: 0.95 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 60, scale: 0.95 }}
              transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
              style={{
                position: "absolute",
                right: "6%",
                width: "540px",
                maxWidth: "90vw",
                borderRadius: "28px",
                border: "1px solid rgba(56, 189, 248, 0.25)",
                background: "rgba(5, 10, 20, 0.92)",
                backdropFilter: "blur(28px)",
                boxShadow: "0 30px 60px rgba(0, 0, 0, 0.9), 0 0 40px rgba(14, 165, 233, 0.12)",
                padding: "32px",
                zIndex: 20,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "1px solid rgba(255, 255, 255, 0.08)", paddingBottom: "16px", marginBottom: "22px" }}>
                <div>
                  <h2 style={{ fontSize: "18px", fontWeight: 600, color: "#f8fafc", margin: 0, letterSpacing: "-0.01em" }}>
                    Operating Reserve Trajectory
                  </h2>
                </div>
                <button
                  onClick={handleInterrupt}
                  style={{ background: "transparent", border: "none", color: "#64748b", cursor: "pointer", padding: "4px" }}
                >
                  <X size={18} />
                </button>
              </div>

              {/* Verified Metrics */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "24px" }}>
                {FINANCIAL_PLAN.hologram.metrics.map((m) => {
                  const isActive = activeNode === m.id;
                  return (
                    <div
                      key={m.id}
                      style={{
                        padding: "14px",
                        borderRadius: "16px",
                        background: isActive ? "rgba(14, 165, 233, 0.15)" : "rgba(255, 255, 255, 0.03)",
                        border: isActive ? "1px solid #38bdf8" : "1px solid rgba(255, 255, 255, 0.06)",
                        boxShadow: isActive ? "0 0 20px rgba(56, 189, 248, 0.3)" : "none",
                        transition: "all 0.3s ease",
                      }}
                    >
                      <span style={{ fontSize: "11px", color: "#64748b", display: "block" }}>
                        {m.label}
                      </span>
                      <span style={{ fontSize: "16px", fontWeight: 600, color: "#f1f5f9", marginTop: "4px", display: "block" }}>
                        {m.value}
                      </span>
                      <span style={{ fontSize: "11px", color: m.isAnomalous ? "#fbbf24" : "#34d399", marginTop: "4px", display: "flex", alignItems: "center", gap: "4px" }}>
                        {m.isAnomalous ? <ShieldAlert size={12} /> : <TrendingUp size={12} />}
                        {m.delta}
                      </span>
                    </div>
                  );
                })}
              </div>

              {/* Trajectory Bars */}
              <div style={{ height: "140px", display: "flex", alignItems: "flex-end", justifyContent: "space-between", padding: "16px 8px 8px", background: "rgba(0, 0, 0, 0.3)", borderRadius: "16px" }}>
                {FINANCIAL_PLAN.hologram.series.map((item, idx) => {
                  const isPeak = item.label === "Jul";
                  const barHeight = item.value + "%";
                  return (
                    <div key={idx} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "8px" }}>
                      <div style={{ width: "26px", height: "90px", display: "flex", alignItems: "flex-end" }}>
                        <div
                          style={{
                            width: "100%",
                            height: barHeight,
                            borderRadius: "4px 4px 0 0",
                            background: isPeak ? "linear-gradient(180deg, #38bdf8 0%, #0284c7 100%)" : "#1e293b",
                            boxShadow: isPeak ? "0 0 16px rgba(56, 189, 248, 0.5)" : "none",
                          }}
                        />
                      </div>
                      <span style={{ fontSize: "11px", color: isPeak ? "#38bdf8" : "#64748b", fontWeight: isPeak ? 600 : 400 }}>
                        {item.label}
                      </span>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Clean Subtitle Stream */}
        <div style={{ position: "absolute", bottom: "100px", left: 0, right: 0, display: "flex", justifyContent: "center", pointerEvents: "none", padding: "0 24px" }}>
          <p style={{ maxWidth: "600px", textAlign: "center", fontSize: "15px", color: "#e2e8f0", fontWeight: 300, lineHeight: 1.6, textShadow: "0 2px 10px rgba(0, 0, 0, 0.9)" }}>
            {subtitle}
          </p>
        </div>
      </div>

      {/* Understated Minimal Dock */}
      <nav
        style={{
          position: "absolute",
          bottom: "28px",
          left: 0,
          right: 0,
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          zIndex: 30,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            background: "rgba(10, 16, 28, 0.9)",
            backdropFilter: "blur(20px)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            padding: "8px 18px",
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
              backgroundColor: isVoiceActive ? "#38bdf8" : "rgba(255, 255, 255, 0.05)",
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
              padding: "6px 12px",
              borderRadius: "9999px",
              border: "1px solid rgba(255, 255, 255, 0.08)",
              background: showConsole ? "rgba(255, 255, 255, 0.12)" : "transparent",
              color: "#94a3b8",
              fontSize: "12px",
              cursor: "pointer",
            }}
          >
            Command (Ctrl+K)
          </button>

          <button
            onClick={handleTriggerChoreography}
            style={{
              padding: "8px 16px",
              borderRadius: "9999px",
              border: "none",
              background: isStanding ? "rgba(239, 68, 68, 0.2)" : "rgba(14, 165, 233, 0.2)",
              color: isStanding ? "#f87171" : "#38bdf8",
              fontSize: "12px",
              fontWeight: 500,
              cursor: "pointer",
            }}
          >
            {isStanding ? "Interrupt" : "Present Trajectory"}
          </button>
        </div>
      </nav>

      {/* Discrete Command Drawer */}
      <AnimatePresence>
        {showConsole && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            transition={{ duration: 0.15 }}
            style={{
              position: "absolute",
              bottom: "84px",
              left: "50%",
              transform: "translateX(-50%)",
              width: "520px",
              maxWidth: "92vw",
              background: "rgba(10, 16, 28, 0.98)",
              backdropFilter: "blur(24px)",
              border: "1px solid rgba(255, 255, 255, 0.1)",
              borderRadius: "20px",
              padding: "14px",
              boxShadow: "0 20px 40px rgba(0, 0, 0, 0.9)",
              zIndex: 40,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
              <span style={{ fontSize: "11px", color: "#64748b" }}>
                Executive Query
              </span>
              <button onClick={() => setShowConsole(false)} style={{ background: "transparent", border: "none", color: "#64748b", cursor: "pointer" }}>
                <X size={15} />
              </button>
            </div>

            {attachments.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "10px" }}>
                {attachments.map((f, i) => (
                  <span key={i} style={{ fontSize: "11px", background: "rgba(255, 255, 255, 0.05)", padding: "4px 8px", borderRadius: "6px", color: "#cbd5e1" }}>
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
                  border: "1px solid rgba(255, 255, 255, 0.08)",
                  borderRadius: "12px",
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
                  borderRadius: "12px",
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
console.log("✓ Applied clean executive layout");
