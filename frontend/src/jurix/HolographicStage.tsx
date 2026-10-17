import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { TrendingUp, ShieldAlert, CheckCircle2 } from "lucide-react";
import type { ExecutiveLedgerMetric } from "./JurixDirector";

interface HolographicStageProps {
  visible: boolean;
  activeNodeId?: string;
  metrics: ExecutiveLedgerMetric[];
  series: { label: string; value: number }[];
  title: string;
}

export const HolographicStage: React.FC<HolographicStageProps> = ({
  visible,
  activeNodeId,
  metrics,
  series,
  title,
}) => {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9, x: 60, rotateY: 15 }}
          animate={{ opacity: 1, scale: 1, x: 0, rotateY: 0 }}
          exit={{ opacity: 0, scale: 0.85, x: 40, filter: "blur(8px)" }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="absolute right-12 lg:right-28 top-20 bottom-24 w-[520px] max-w-[90vw] z-20 flex flex-col justify-center pointer-events-auto select-none"
          style={{ perspective: 1200 }}
        >
          {/* Volumetric Hologram Container with Glassmorphic Rim-Lighting */}
          <div className="relative rounded-3xl p-8 border border-sky-500/30 bg-[#040812]/80 backdrop-blur-2xl shadow-[0_0_50px_rgba(14,165,233,0.15)] overflow-hidden">
            
            {/* Ambient Background Energy Grid */}
            <div className="absolute inset-0 bg-[radial-gradient(#0284c7_1px,transparent_1px)] [background-size:16px_16px] opacity-15 pointer-events-none" />

            {/* Header / Security Status */}
            <div className="relative flex justify-between items-start border-b border-sky-500/20 pb-4 mb-6">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                  <span className="text-[10px] font-mono tracking-[0.25em] text-cyan-400 uppercase font-semibold">
                    VOLUMETRIC LEDGER PROJECTION
                  </span>
                </div>
                <h2 className="text-base font-semibold text-neutral-100 tracking-wide mt-1.5 font-mono">
                  {title}
                </h2>
              </div>
              <div className="flex items-center space-x-1.5 text-[11px] font-mono text-cyan-300 bg-sky-950/60 border border-sky-800/50 px-3 py-1 rounded-full">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>CRYPTOGRAPHICALLY BOUND</span>
              </div>
            </div>

            {/* Metric Nodes with Dynamic Gesture Highlighting */}
            <div className="relative grid grid-cols-3 gap-3 mb-6">
              {metrics.map((m) => {
                const isActive = activeNodeId === m.id;
                return (
                  <motion.div
                    key={m.id}
                    animate={{
                      scale: isActive ? 1.05 : 1.0,
                      borderColor: isActive ? "rgba(56, 189, 248, 0.8)" : "rgba(30, 41, 59, 0.6)",
                      boxShadow: isActive ? "0 0 24px rgba(56, 189, 248, 0.35)" : "none",
                    }}
                    transition={{ duration: 0.3 }}
                    className={`relative p-3.5 rounded-2xl border bg-neutral-950/60 backdrop-blur-md transition-all ${
                      m.isAnomalous ? "border-amber-500/40" : ""
                    }`}
                  >
                    <span className="text-[9px] font-mono uppercase tracking-widest text-neutral-500 block">
                      {m.label}
                    </span>
                    <span className="text-sm font-bold font-mono text-neutral-100 mt-1 block tracking-tight">
                      {m.value}
                    </span>
                    <span
                      className={`text-[10px] font-mono mt-1 flex items-center ${
                        m.isAnomalous ? "text-amber-400 font-semibold" : "text-cyan-400"
                      }`}
                    >
                      {m.isAnomalous ? (
                        <ShieldAlert className="w-2.5 h-2.5 mr-1" />
                      ) : (
                        <TrendingUp className="w-2.5 h-2.5 mr-1" />
                      )}
                      {m.delta}
                    </span>
                  </motion.div>
                );
              })}
            </div>

            {/* Financial Trajectory Histogram */}
            <div className="relative h-44 flex items-end justify-between px-4 pt-6 pb-2 rounded-2xl bg-black/40 border border-sky-900/30 shadow-inner">
              {series.map((item, idx) => {
                const isTarget = item.label === "Jul";
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-2 group">
                    <div className="w-7 relative flex items-end justify-center h-32">
                      <motion.div
                        initial={{ height: 0 }}
                        animate={{ height: `${item.value}%` }}
                        transition={{ duration: 0.9, delay: idx * 0.08, ease: "easeOut" }}
                        className={`w-full rounded-t-sm transition-all duration-300 ${
                          isTarget
                            ? "bg-gradient-to-t from-sky-600 via-cyan-400 to-amber-300 shadow-[0_0_20px_rgba(56,189,248,0.6)]"
                            : "bg-gradient-to-t from-neutral-800 to-sky-950 group-hover:from-sky-800 group-hover:to-cyan-600"
                        }`}
                      />
                    </div>
                    <span
                      className={`text-[10px] font-mono ${
                        isTarget ? "text-cyan-300 font-bold" : "text-neutral-500"
                      }`}
                    >
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Sub-label verification badge */}
            <div className="relative mt-5 pt-3 border-t border-sky-500/15 flex justify-between items-center text-[10px] font-mono text-neutral-500">
              <span>ORCHESTRATOR // TIME SYNC VERIFIED</span>
              <span className="text-cyan-500">IMMUTABLE ZERO-TRUST LEDGER</span>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
