const fs = require("fs");
const path = "src/jurix/OvelaConsole.tsx";

const content = `import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic, MicOff, Paperclip, Send, X, TrendingUp, ShieldAlert, Sparkles } from "lucide-react";
import { JurixDirector, type DirectorPerformancePlan } from "./JurixDirector";

const EXECUTIVE_DEMO_PLAN: DirectorPerformancePlan = {
  planId: "exec-plan-001",
  totalDurationMs: 8000,
  speechText: "Reviewing our liquid reserves. Note the settlement spike in July, after which runway normalized.",
  postureSequence: [
    { ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "GREETING_NOD" },
    { ptsMs: 1500, posture: "STAND_TRANSITION", gaze: "HOLOGRAM_DATA", gesture: "STAND_UP" },
    { ptsMs: 3000, posture: "PRESENT_HOLOGRAM", gaze: "HOLOGRAM_DATA", gesture: "POINT_DELTA", activeNodeId: "node-peak" },
    { ptsMs: 6500, posture: "SEATED_TRANSITION", gaze: "CAMERA_USER", gesture: "RETURN_SEAT" },
    { ptsMs: 7800, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "IDLE_BREATHING" },
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
  const [posture, setPosture] = useState<string>("SEATED_DESK");
  const [activeNode, setActiveNode] = useState<string | undefined>(undefined);
  const [subtitle, setSubtitle] = useState<string>("Good evening, Chetan. What shall we inspect?");
  const [isVoiceActive, setIsVoiceActive] = useState<boolean>(false);
  const [showConsole, setShowConsole] = useState<boolean>(false);
  const [chatMessage, setChatMessage] = useState<string>("");
  const [attachments, setAttachments] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let animId: number;
    const tick = () => {
      const state = directorRef.current.getCurrentState();
      setPosture(state.posture);
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
    if (posture !== "SEATED_DESK") {
      handleInterrupt();
    } else {
      directorRef.current.loadPlan(EXECUTIVE_DEMO_PLAN);
      setSubtitle(EXECUTIVE_DEMO_PLAN.speechText);
    }
  };

  const isStanding = posture === "STAND_TRANSITION" || posture === "PRESENT_HOLOGRAM";

  return (
    <div style={{ position: "relative", width: "100vw", height: "100vh", overflow: "hidden", backgroundColor: "#020408", color: "#f8fafc" }}>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: "none" }}
        onChange={(e) => {
          if (e.target.files) setAttachments(Array.from(e.target.files));
        }}
      />

      <div
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage: "radial-gradient(circle at 50% 30%, rgba(14, 30, 58, 0.5) 0%, rgba(2, 4, 8, 0.98) 75%), linear-gradient(180deg, #070d18 0%, #020408 100%)",
          backgroundSize: "cover",
          backgroundPosition: "center",
          zIndex: 0,
        }}
      >
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage: "linear-gradient(rgba(56, 189, 248, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(56, 189, 248, 0.03) 1px, transparent 1px)",
            backgroundSize: "60px 60px",
            opacity: 0.8,
          }}
        />
      </div>

      <header
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          padding: "24px 36px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          zIndex: 20,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "#38bdf8", boxShadow: "0 0 12px #38bdf8" }} />
          <span style={{ fontFamily: "monospace", fontSize: "11px", letterSpacing: "0.25em", color: "#94a3b8", textTransform: "uppercase" }}>
            JURIX EXECUTIVE PRESENCE // BOARDROOM STAGE
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "11px", fontFamily: "monospace", color: "#38bdf8", background: "rgba(14, 165, 233, 0.08)", padding: "6px 14px", borderRadius: "9999px", border: "1px solid rgba(56, 189, 248, 0.2)" }}>
          <Sparkles size={13} />
          <span>ZERO-TRUST IMMUTABLE LEDGER</span>
        </div>
      </header>

      <div style={{ position: "relative", width: "100%", height: "100%", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 10 }}>
        <motion.div
          animate={{
            x: isStanding ? -280 : 0,
            scale: isStanding ? 0.92 : 1.0,
          }}
          transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
          onClick={handleInterrupt}
          style={{
            position: "relative",
            width: "380px",
            height: "560px",
            borderRadius: "32px",
            border: "1px solid rgba(56, 189, 248, 0.25)",
            background: "linear-gradient(180deg, rgba(15, 23, 42, 0.7) 0%, rgba(2, 6, 14, 0.95) 100%)",
            boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.9), 0 0 40px rgba(14, 165, 233, 0.1)",
            backdropFilter: "blur(20px)",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "36px 24px",
            cursor: "pointer",
          }}
        >
          <div style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.15em" }}>
              FEED: ENCRYPTED
            </span>
            <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#38bdf8", background: "rgba(14, 165, 233, 0.12)", padding: "2px 8px", borderRadius: "6px" }}>
              {posture.replace("_", " ")}
            </span>
          </div>

          <div style={{ position: "relative", width: "180px", height: "180px", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div
              style={{
                position: "absolute",
                inset: -10,
                borderRadius: "50%",
                background: "radial-gradient(circle, rgba(56, 189, 248, 0.25) 0%, transparent 70%)",
              }}
            />
            <div
              style={{
                width: "140px",
                height: "140px",
                borderRadius: "50%",
                border: "2px solid rgba(56, 189, 248, 0.4)",
                background: "radial-gradient(circle at 50% 30%, #1e293b 0%, #020617 100%)",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "inset 0 0 20px rgba(0, 0, 0, 0.8)",
              }}
            >
              <div
                style={{
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  backgroundColor: isStanding ? "#22d3ee" : "#38bdf8",
                  boxShadow: "0 0 16px #38bdf8",
                  marginBottom: "8px",
                }}
              />
              <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#cbd5e1", letterSpacing: "0.15em" }}>
                JURIX
              </span>
            </div>
          </div>

          <div style={{ textAlign: "center" }}>
            <p style={{ fontSize: "13px", color: "#94a3b8", fontWeight: 300 }}>
              {isStanding ? "Presenting live board invariants..." : "Seated at desk. Tap anytime to interrupt."}
            </p>
          </div>
        </motion.div>

        <AnimatePresence>
          {isStanding && (
            <motion.div
              initial={{ opacity: 0, x: 80, scale: 0.94 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 60, scale: 0.94 }}
              transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
              style={{
                position: "absolute",
                right: "8%",
                width: "520px",
                maxWidth: "90vw",
                borderRadius: "28px",
                border: "1px solid rgba(56, 189, 248, 0.35)",
                background: "linear-gradient(180deg, rgba(8, 14, 28, 0.88) 0%, rgba(3, 7, 16, 0.96) 100%)",
                backdropFilter: "blur(24px)",
                boxShadow: "0 30px 60px -15px rgba(0, 0, 0, 0.95), 0 0 40px rgba(14, 165, 233, 0.15)",
                padding: "32px",
                zIndex: 20,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "1px solid rgba(56, 189, 248, 0.15)", paddingBottom: "16px", marginBottom: "20px" }}>
                <div>
                  <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#38bdf8", letterSpacing: "0.2em", textTransform: "uppercase" }}>
                    LIVE BOARDROOM LEDGER
                  </span>
                  <h2 style={{ fontSize: "18px", fontWeight: 600, color: "#f8fafc", margin: "4px 0 0 0", fontFamily: "monospace" }}>
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

              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "24px" }}>
                {EXECUTIVE_DEMO_PLAN.hologram.metrics.map((m) => {
                  const isActive = activeNode === m.id;
                  return (
                    <div
                      key={m.id}
                      style={{
                        padding: "14px",
                        borderRadius: "16px",
                        background: isActive ? "rgba(14, 165, 233, 0.15)" : "rgba(2, 6, 14, 0.6)",
                        border: isActive ? "1px solid #38bdf8" : "1px solid rgba(56, 189, 248, 0.15)",
                        boxShadow: isActive ? "0 0 20px rgba(56, 189, 248, 0.3)" : "none",
                        transition: "all 0.3s ease",
                      }}
                    >
                      <span style={{ fontSize: "9px", fontFamily: "monospace", color: "#64748b", textTransform: "uppercase", display: "block" }}>
                        {m.label}
                      </span>
                      <span style={{ fontSize: "15px", fontWeight: 700, fontFamily: "monospace", color: "#f1f5f9", marginTop: "4px", display: "block" }}>
                        {m.value}
                      </span>
                      <span style={{ fontSize: "10px", fontFamily: "monospace", color: m.isAnomalous ? "#fbbf24" : "#34d399", marginTop: "4px", display: "flex", alignItems: "center", gap: "4px" }}>
                        {m.isAnomalous ? <ShieldAlert size={11} /> : <TrendingUp size={11} />}
                        {m.delta}
                      </span>
                    </div>
                  );
                })}
              </div>

              <div style={{ height: "140px", display: "flex", alignItems: "flex-end", justifyContent: "space-between", padding: "16px 8px 8px", background: "rgba(0, 0, 0, 0.4)", borderRadius: "16px", border: "1px solid rgba(56, 189, 248, 0.1)" }}>
                {EXECUTIVE_DEMO_PLAN.hologram.series.map((item, idx) => {
                  const isPeak = item.label === "Jul";
                  const barHeight = item.value + "%";
                  return (
                    <div key={idx} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "8px" }}>
                      <div style={{ width: "22px", height: "90px", display: "flex", alignItems: "flex-end" }}>
                        <div
                          style={{
                            width: "100%",
                            height: barHeight,
                            borderRadius: "4px 4px 0 0",
                            background: isPeak ? "linear-gradient(180deg, #38bdf8 0%, #0369a1 100%)" : "linear-gradient(180deg, #334155 0%, #0f172a 100%)",
                            boxShadow: isPeak ? "0 0 16px rgba(56, 189, 248, 0.6)" : "none",
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

        <div style={{ position: "absolute", bottom: "100px", left: 0, right: 0, display: "flex", justifyContent: "center", pointerEvents: "none", padding: "0 20px" }}>
          <p style={{ maxWidth: "600px", textAlign: "center", fontSize: "15px", color: "#e2e8f0", fontWeight: 300, lineHeight: 1.6, textShadow: "0 2px 10px rgba(0, 0, 0, 0.8)" }}>
            {subtitle}
          </p>
        </div>
      </div>

      <nav
        style={{
          position: "absolute",
          bottom: "24px",
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
            background: "rgba(8, 14, 28, 0.85)",
            backdropFilter: "blur(20px)",
            border: "1px solid rgba(56, 189, 248, 0.2)",
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
              backgroundColor: isVoiceActive ? "#22d3ee" : "rgba(30, 41, 59, 0.8)",
              color: isVoiceActive ? "#020408" : "#94a3b8",
              cursor: "pointer",
            }}
          >
            {isVoiceActive ? <Mic size={16} /> : <MicOff size={16} />}
          </button>

          <button
            onClick={() => fileInputRef.current?.click()}
            style={{ padding: "10px", borderRadius: "50%", border: "none", background: "transparent", color: "#94a3b8", cursor: "pointer" }}
            title="Attach Invariants (Ctrl+U)"
          >
            <Paperclip size={16} />
          </button>

          <button
            onClick={() => setShowConsole(!showConsole)}
            style={{
              padding: "6px 12px",
              borderRadius: "9999px",
              border: "1px solid rgba(56, 189, 248, 0.2)",
              background: showConsole ? "rgba(56, 189, 248, 0.2)" : "rgba(15, 23, 42, 0.6)",
              color: "#f1f5f9",
              fontSize: "11px",
              fontFamily: "monospace",
              cursor: "pointer",
            }}
          >
            Ctrl+K
          </button>

          <button
            onClick={handleTriggerChoreography}
            style={{
              padding: "8px 16px",
              borderRadius: "9999px",
              border: "1px solid rgba(56, 189, 248, 0.4)",
              background: "rgba(14, 165, 233, 0.15)",
              color: "#38bdf8",
              fontSize: "11px",
              fontFamily: "monospace",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            {isStanding ? "Interrupt & Sit" : "Initiate Boardroom Choreography"}
          </button>
        </div>
      </nav>

      <AnimatePresence>
        {showConsole && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 15, scale: 0.98 }}
            transition={{ duration: 0.2 }}
            style={{
              position: "absolute",
              bottom: "84px",
              left: "50%",
              transform: "translateX(-50%)",
              width: "540px",
              maxWidth: "92vw",
              background: "rgba(6, 12, 24, 0.96)",
              backdropFilter: "blur(24px)",
              border: "1px solid rgba(56, 189, 248, 0.3)",
              borderRadius: "24px",
              padding: "16px",
              boxShadow: "0 25px 50px rgba(0, 0, 0, 0.9)",
              zIndex: 40,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#64748b", letterSpacing: "0.2em", textTransform: "uppercase" }}>
                SOVEREIGN COMMAND INTERFACE
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
                placeholder="Direct executive order..."
                value={chatMessage}
                onChange={(e) => setChatMessage(e.target.value)}
                style={{
                  flex: 1,
                  background: "rgba(2, 6, 14, 0.8)",
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
console.log("Successfully wrote OvelaConsole.tsx");
