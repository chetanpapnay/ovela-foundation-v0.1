const fs = require("fs");

const code = `import React, { useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  Radio,
  Lock,
  Volume2,
  VolumeX,
  Terminal,
  Send,
  Zap,
  Globe,
  Database
} from "lucide-react";

interface TelemetryMetric {
  id: string;
  label: string;
  val: string;
  sub: string;
  isAlert?: boolean;
}

export default function SovereignExecutiveOS() {
  const [activeCamera, setActiveCamera] = useState<"frontal" | "isometric" | "director" | "boardroom">("frontal");
  const [audioMuted, setAudioMuted] = useState(false);
  const [isAuditing, setIsAuditing] = useState(false);
  const [activeFocalNode, setActiveFocalNode] = useState<string | null>("node-july");
  const [executiveCommand, setExecutiveCommand] = useState("");
  const [subtitle, setSubtitle] = useState(
    "Sovereign command channel initialized. Standing by for multi-asset stress test or liquidity anomaly audit."
  );

  const [auditLogs, setAuditLogs] = useState<string[]>([
    "[SYSTEM_INIT] Neural telemetry linked: SHA-384 cryptographic seed valid.",
    "[PERSPECTIVE] ARRI Volumetric Spatial Matrix calibrated to 65mm focal field.",
    "[SECURITY] Zero-Trust Ledger invariants nominal. Zero uncommitted drift."
  ]);

  const metrics: TelemetryMetric[] = [
    { id: "node-depth", label: "SOVEREIGN LIQUIDITY DEPTH", val: "$14.82B", sub: "Gov-Liq 48-Mo" },
    { id: "node-july", label: "JULY SETTLEMENT DELTA", val: "₹52,100M", sub: "ANOM-782-X Surge", isAlert: true },
    { id: "node-burn", label: "ALGORITHMIC BURN RUN-RATE", val: "$38.4M/mo", sub: "Model V2" },
    { id: "node-zkp", label: "ZERO-KNOWLEDGE INVARIANTS", val: "99.9998%", sub: "ZK-VALID" }
  ];

  const seriesData = [
    { label: "MAR", h: 42, active: false },
    { label: "APR", h: 56, active: false },
    { label: "MAY", h: 48, active: false },
    { label: "JUN", h: 62, active: false },
    { label: "JUL", h: 96, active: true },
    { label: "AUG", h: 54, active: false },
    { label: "SEP", h: 50, active: false },
    { label: "OCT", h: 68, active: false }
  ];

  const triggerAudit = () => {
    setIsAuditing(true);
    setActiveFocalNode("node-july");
    setSubtitle("Isolating July capital surge. Cross-referencing ₹52,100M settlement anomaly against Basel IV capital buffer invariants.");
    setAuditLogs((prev) => [
      "[EXEC_CHOREOGRAPHY] Volumetric focal pane targeted at July Anomaly (node: ANOM-782-X).",
      "[ROUTING] Synchronized multi-region sovereign gateways (Latency: 1.4ms mean).",
      ...prev.slice(0, 5)
    ]);
    setTimeout(() => setIsAuditing(false), 3800);
  };

  const submitCommand = (e: React.FormEvent) => {
    e.preventDefault();
    if (!executiveCommand.trim()) return;
    setSubtitle(\`Directive parsed: "\${executiveCommand}". Invariant validation dispatched across cluster nodes.\`);
    setAuditLogs((prev) => [\`[DIRECTIVE] "\${executiveCommand}" - Signed & Broadcast to consensus layer.\`, ...prev.slice(0, 5)]);
    setExecutiveCommand("");
  };

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-[#02050c] text-slate-100 font-mono select-none flex flex-col justify-between p-4 md:p-6">
      {/* Background Matrix Grid */}
      <div className="absolute inset-0 bg-[radial-gradient(#0e7490_1px,transparent_1px)] [background-size:32px_32px] opacity-20 pointer-events-none" />
      <div className="absolute inset-0 bg-gradient-to-b from-[#02050c]/80 via-transparent to-[#02050c]/90 pointer-events-none" />

      {/* 1. TOP STATUS BAR */}
      <header className="relative z-30 flex items-center justify-between border-b border-cyan-500/20 pb-3 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_10px_#22d3ee]" />
          <div>
            <h1 className="text-xs tracking-[0.25em] text-cyan-300 font-bold">OVELA // SOVEREIGN CORE</h1>
            <p className="text-[10px] text-slate-400">MULTI-TENANT HOLOGRAPHIC EXECUTIVE INTERFACE • SESSION: 0x9AE8-D43</p>
          </div>
        </div>

        <div className="flex items-center gap-2 md:gap-4 text-[11px]">
          <span className="px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 flex items-center gap-1.5">
            <Lock className="w-3 h-3 text-cyan-400" /> ZKP INVARIANT: LOCKED
          </span>
          <span className="px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-950/40 text-emerald-400 flex items-center gap-1.5">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" /> WEBRTC DUPLEX: 8.8ms
          </span>
          <button
            onClick={() => setAudioMuted(!audioMuted)}
            className="p-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/40 transition"
          >
            {audioMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </header>

      {/* 2. MAIN VOLUMETRIC STAGE */}
      <main className="relative z-20 flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center my-3 min-h-0">
        
        {/* LEFT COLUMN: LIQUIDITY TRAJECTORY PANE */}
        <motion.div
          animate={{
            x: activeCamera === "isometric" ? -25 : 0,
            rotateY: activeCamera === "isometric" ? 12 : 0,
            scale: activeCamera === "director" ? 0.94 : 1
          }}
          transition={{ duration: 0.6 }}
          className="lg:col-span-3 h-full flex flex-col justify-between bg-gradient-to-b from-[#061224]/85 to-[#020712]/90 border border-cyan-500/30 rounded-2xl p-4 shadow-[0_0_35px_rgba(6,182,212,0.12)] backdrop-blur-xl overflow-y-auto"
        >
          <div>
            <div className="flex justify-between items-center border-b border-cyan-500/20 pb-2 mb-3">
              <span className="text-[10px] tracking-widest text-cyan-400 font-bold">OPERATING LIQUIDITY TRAJECTORY</span>
              <span className="text-[9px] px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30">REAL-TIME Q2-Q3</span>
            </div>

            {/* Glowing Histogram */}
            <div className="h-44 flex items-end justify-between gap-1.5 pt-6 pb-2 px-1">
              {seriesData.map((bar, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end">
                  {bar.active && (
                    <span className="text-[8px] bg-amber-500 text-black font-bold px-1 rounded animate-pulse">
                      SURGE
                    </span>
                  )}
                  <motion.div
                    animate={{ height: \`\${bar.h}%\` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={\`w-full rounded-t-sm transition-all duration-300 \${
                      bar.active
                        ? "bg-gradient-to-t from-amber-500 to-amber-300 shadow-[0_0_20px_#f59e0b]"
                        : "bg-gradient-to-t from-cyan-900/60 to-cyan-500/40 hover:from-cyan-700 hover:to-cyan-400"
                    }\`}
                  />
                  <span className={\`text-[9px] \${bar.active ? "text-amber-300 font-bold" : "text-slate-400"}\`}>
                    {bar.label}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Metric Tiles */}
          <div className="grid grid-cols-2 gap-2 mt-3">
            {metrics.map((m) => {
              const selected = activeFocalNode === m.id;
              return (
                <div
                  key={m.id}
                  onClick={() => setActiveFocalNode(m.id)}
                  className={\`p-2.5 rounded-xl border transition-all cursor-pointer \${
                    m.isAlert
                      ? "border-amber-500/50 bg-amber-950/20 shadow-[0_0_15px_rgba(245,158,11,0.2)]"
                      : selected
                      ? "border-cyan-400 bg-cyan-950/40 shadow-[0_0_15px_rgba(6,182,212,0.2)]"
                      : "border-cyan-500/20 bg-slate-900/40 hover:border-cyan-500/40"
                  }\`}
                >
                  <span className="text-[8px] text-slate-400 block truncate">{m.label}</span>
                  <span className={\`text-xs font-bold block mt-0.5 \${m.isAlert ? "text-amber-300" : "text-cyan-200"}\`}>
                    {m.val}
                  </span>
                  <span className="text-[8px] text-slate-400 block mt-0.5 truncate">{m.sub}</span>
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* CENTER COLUMN: REAL PHOTOREALISTIC EXECUTIVE PRESENCE */}
        <div className="lg:col-span-6 h-full flex flex-col items-center justify-center relative overflow-hidden rounded-3xl border border-cyan-500/25 bg-gradient-to-b from-[#040e1e]/60 via-[#02050c]/80 to-[#02050c] p-2">
          {/* Radial ambient lighting */}
          <div className="absolute inset-0 bg-radial from-cyan-500/25 via-transparent to-transparent blur-3xl pointer-events-none" />

          <div className="relative w-full h-full flex items-center justify-center overflow-hidden rounded-2xl">
            <img
              src="/images/executive_hero.png"
              alt="Sovereign AI Executive"
              className="w-full h-full object-cover object-center filter contrast-105 brightness-95 opacity-90 transition-transform duration-700 hover:scale-[1.02]"
              style={{
                maskImage: "radial-gradient(ellipse 95% 95% at 50% 50%, black 70%, transparent 100%)",
                WebkitMaskImage: "radial-gradient(ellipse 95% 95% at 50% 50%, black 70%, transparent 100%)"
              }}
              onError={(e) => {
                (e.target as HTMLImageElement).src =
                  "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=1600&q=80";
              }}
            />

            {/* Scanning Grid Overlay */}
            <div className="absolute inset-0 bg-[radial-gradient(rgba(56,189,248,0.12)_1px,transparent_1px)] [background-size:24px_24px] pointer-events-none" />

            {/* Floating Fingertip Touch Ring */}
            <motion.div
              animate={{ scale: [1, 1.25, 1], opacity: [0.6, 1, 0.6] }}
              transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
              className="absolute top-[39%] left-[23%] w-7 h-7 rounded-full border-2 border-cyan-400 bg-cyan-400/20 shadow-[0_0_25px_#38bdf8] flex items-center justify-center pointer-events-none"
            >
              <div className="w-2 h-2 rounded-full bg-cyan-100 shadow-[0_0_8px_#ffffff]" />
            </motion.div>
          </div>

          {/* PRESENCE TELEMETRY PILL */}
          <div className="absolute bottom-4 px-4 py-1.5 rounded-full border border-cyan-500/30 bg-[#020712]/80 backdrop-blur-md flex items-center gap-3 text-[10px] text-cyan-300">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              PRESENCE DUPLEX
            </span>
            <span className="text-slate-500">|</span>
            <span className="font-mono text-cyan-200">96.4 kHz SPATIAL ACOUSTICS</span>
          </div>
        </div>

        {/* RIGHT COLUMN: SOVEREIGN CROSS-BORDER NODES & AUDIT LOGS */}
        <motion.div
          animate={{
            x: activeCamera === "isometric" ? 25 : 0,
            rotateY: activeCamera === "isometric" ? -12 : 0,
            scale: activeCamera === "director" ? 0.94 : 1
          }}
          transition={{ duration: 0.6 }}
          className="lg:col-span-3 h-full flex flex-col justify-between bg-gradient-to-b from-[#061224]/85 to-[#020712]/90 border border-cyan-500/30 rounded-2xl p-4 shadow-[0_0_35px_rgba(6,182,212,0.12)] backdrop-blur-xl overflow-y-auto"
        >
          <div>
            <div className="flex justify-between items-center border-b border-cyan-500/20 pb-2 mb-3">
              <span className="text-[10px] tracking-widest text-cyan-400 font-bold">SOVEREIGN CROSS-BORDER NODES</span>
              <span className="text-[9px] text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> ACTIVE
              </span>
            </div>

            {/* Region Tabs */}
            <div className="grid grid-cols-4 gap-1 mb-3 text-[9px]">
              {["Zurich", "Tokyo", "Singapore", "London"].map((city, idx) => (
                <button
                  key={city}
                  className={\`py-1 rounded text-center border transition \${
                    idx === 0
                      ? "border-cyan-400 bg-cyan-950/70 text-cyan-200 font-bold"
                      : "border-cyan-900/40 bg-slate-900/40 text-slate-400 hover:text-cyan-300"
                  }\`}
                >
                  {city}
                </button>
              ))}
            </div>

            {/* Nodes Info Card */}
            <div className="p-3 rounded-xl border border-cyan-500/20 bg-slate-950/40 space-y-2 mb-3">
              <div className="flex justify-between text-[10px]">
                <span className="text-slate-400 flex items-center gap-1">
                  <Database className="w-3 h-3 text-cyan-400" /> Throughput Capacity
                </span>
                <span className="text-cyan-300 font-bold">4.8 TB/s</span>
              </div>
              <div className="flex justify-between text-[10px]">
                <span className="text-slate-400 flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3 text-cyan-400" /> Hardware Integrity
                </span>
                <span className="text-emerald-400 font-bold">0.002% Drift</span>
              </div>
            </div>
          </div>

          {/* Cryptographic Audit Logs */}
          <div className="border-t border-cyan-500/20 pt-3">
            <span className="text-[9px] text-slate-400 tracking-wider flex items-center gap-1 mb-1.5">
              <Terminal className="w-3 h-3 text-cyan-400" /> CRYPTOGRAPHIC AUDIT LOGS
            </span>
            <div className="space-y-1 text-[9px] text-cyan-300/80 max-h-28 overflow-y-auto font-mono">
              {auditLogs.map((log, i) => (
                <div key={i} className="truncate hover:text-cyan-100 transition">
                  {log}
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </main>

      {/* 3. DYNAMIC SUBTITLE CALLOUT */}
      <div className="relative z-30 flex justify-center my-1 pointer-events-none px-4">
        <p className="max-w-3xl text-center text-[12px] md:text-[13px] text-slate-200 bg-[#061224]/85 border border-cyan-500/30 backdrop-blur-xl px-6 py-2 rounded-full shadow-[0_10px_30px_rgba(0,0,0,0.8)] pointer-events-auto">
          {subtitle}
        </p>
      </div>

      {/* 4. FOOTER EXECUTIVE COMMAND DOCK */}
      <footer className="relative z-30 flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-cyan-500/20 backdrop-blur-md">
        {/* Perspectives */}
        <div className="flex items-center gap-1.5 text-[10px]">
          <span className="text-slate-500 mr-1 hidden sm:inline">PERSPECTIVE:</span>
          {(["frontal", "isometric", "director", "boardroom"] as const).map((cam) => (
            <button
              key={cam}
              onClick={() => setActiveCamera(cam)}
              className={\`px-2.5 py-1 rounded-lg border uppercase tracking-wider transition \${
                activeCamera === cam
                  ? "border-cyan-400 bg-cyan-950/60 text-cyan-200 shadow-[0_0_12px_rgba(6,182,212,0.3)]"
                  : "border-slate-800 bg-slate-900/40 text-slate-400 hover:text-cyan-300"
              }\`}
            >
              {cam}
            </button>
          ))}
        </div>

        {/* Global Action Trigger Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={triggerAudit}
            disabled={isAuditing}
            className="px-4 py-1.5 rounded-lg border border-amber-500/40 bg-amber-950/40 text-amber-300 hover:bg-amber-900/50 text-[11px] font-bold tracking-wider flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(245,158,11,0.2)] disabled:opacity-50"
          >
            <Zap className="w-3.5 h-3.5" /> AUDIT ANOMALY
          </button>
          <button
            onClick={() => setSubtitle("Global cross-border settlement channels synchronized across Zurich, Tokyo, and Singapore nodes.")}
            className="px-4 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/50 text-[11px] font-bold tracking-wider flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(6,182,212,0.2)]"
          >
            <Globe className="w-3.5 h-3.5" /> GLOBAL SYNC
          </button>
        </div>

        {/* Executive Directives Input Form */}
        <form onSubmit={submitCommand} className="flex items-center gap-2 w-full md:w-auto">
          <input
            type="text"
            placeholder="Input executive directive (e.g., AUDIT JULY)..."
            value={executiveCommand}
            onChange={(e) => setExecutiveCommand(e.target.value)}
            className="flex-1 md:w-72 bg-black/50 border border-cyan-500/30 rounded-lg px-3 py-1.5 text-[11px] text-cyan-200 focus:outline-none focus:border-cyan-400 transition"
          />
          <button
            type="submit"
            className="p-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-[0_0_12px_#06b6d4]"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </footer>
    </div>
  );
}
\`;

fs.writeFileSync("src/App.tsx", code, "utf8");
console.log("✓ Successfully wrote src/App.tsx with clean UTF-8 encoding");
