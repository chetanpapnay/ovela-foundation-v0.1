import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Mic, MicOff, Sparkles, Activity, X, Send } from "lucide-react";
import { JurixWebRTCStage } from "./jurix/JurixWebRTCStage";
import type { JurixAvatarMode } from "./jurix/JurixWebRTCStage";
import { JurixVoiceGateway } from "./jurix/JurixVoiceGateway";
import { JurixDirector } from "./jurix/JurixDirector";
import type { DirectorPerformancePlan } from "./jurix/JurixDirector";

interface LedgerSummary {
  total_expense: number;
  cash_expense: number;
  bank_expense: number;
  daily_cap: number;
  remaining_budget: number;
  transaction_count: number;
}

const DEFAULT_SUMMARY: LedgerSummary = {
  total_expense: 0,
  cash_expense: 0,
  bank_expense: 0,
  daily_cap: 4000,
  remaining_budget: 4000,
  transaction_count: 0,
};

export default function App() {
  const [avatarMode, setAvatarMode] = useState<JurixAvatarMode>("idle");
  const [presentationTrigger, setPresentationTrigger] = useState(0);
  const [textInput, setTextInput] = useState("");
  const handleTextSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!textInput.trim()) return;
    processVoiceDirectiveRef.current(textInput.trim());
    setTextInput("");
  };
  const [presentationActive, setPresentationActive] = useState(false);
  const [isSummoned, setIsSummoned] = useState(false);
  const [, setTranscript] = useState("");
  const [voiceActive, setVoiceActive] = useState(false);
  const [activePlan, setActivePlan] = useState<DirectorPerformancePlan | null>(null);
  const [, setLedgerSummary] = useState<LedgerSummary>(DEFAULT_SUMMARY);

  const voiceGatewayRef = useRef<JurixVoiceGateway | null>(null);
  const directorRef = useRef<JurixDirector>(new JurixDirector());
  const voiceActiveRef = useRef(false);
  const processVoiceDirectiveRef = useRef<(command: string) => void>(() => {});

  const fetchLedgerSummary = useCallback(async (): Promise<LedgerSummary> => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/summary");
      if (res.ok) {
        const raw = await res.json();
        const records = Array.isArray(raw) ? raw : (raw.value || []);
        
        let totalExp = 0;
        let bankExp = 0;
        let cashExp = 0;
        let txCount = 0;

        records.forEach((r: any) => {
          const exp = parseFloat(r.total_expenses || "0");
          totalExp += isNaN(exp) ? 0 : exp;
          if (r.account_id === "CASH") {
            cashExp += isNaN(exp) ? 0 : exp;
          } else {
            bankExp += isNaN(exp) ? 0 : exp;
          }
          txCount += Number(r.total_transactions || 0);
        });

        const dailyCap = 4000;
        const remaining = Math.max(0, dailyCap - totalExp);

        const summary: LedgerSummary = {
          total_expense: totalExp,
          cash_expense: cashExp,
          bank_expense: bankExp,
          daily_cap: dailyCap,
          remaining_budget: remaining,
          transaction_count: txCount
        };

        setLedgerSummary(summary);
        return summary;
      }
    } catch (err) {
      console.warn("Backend server not reachable on port 8000; using local cache.", err);
    }
    return DEFAULT_SUMMARY;
  }, []);

  useEffect(() => {
    fetchLedgerSummary();
  }, [fetchLedgerSummary]);

  const speakPlan = (plan: DirectorPerformancePlan, nextMode: JurixAvatarMode = "speaking") => {
    setActivePlan(plan);
    directorRef.current.loadPlan(plan);

    const mode = plan.displayMode || "written";
    if (mode === "written") {
      setIsSummoned(true);
      setPresentationActive(false);
    } else if (mode === "visual") {
      setIsSummoned(false);
      setPresentationActive(true);
      setPresentationTrigger((n) => n + 1);
    } else if (mode === "both") {
      setIsSummoned(true);
      setPresentationActive(true);
      setPresentationTrigger((n) => n + 1);
    }

    voiceGatewayRef.current?.stop();
    setAvatarMode(nextMode);

    if (!("speechSynthesis" in window)) {
      setAvatarMode("idle");
      if (voiceActiveRef.current) {
        setTimeout(() => voiceGatewayRef.current?.start(), 300);
      }
      return;
    }

    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(plan.speechText);
    utterance.rate = 1.0;
    utterance.pitch = 1.0;

    utterance.onstart = () => {
      setAvatarMode(nextMode === "greeting" ? "greeting" : "speaking");
    };

    const resumeListening = () => {
      setAvatarMode("idle");
      if (voiceActiveRef.current) {
        setTimeout(() => voiceGatewayRef.current?.start(), 300);
      }
    };

    utterance.onend = resumeListening;
    utterance.onerror = resumeListening;
    window.speechSynthesis.speak(utterance);
  };

  const triggerDailySpendsWritten = async () => {
    const summary = await fetchLedgerSummary();
    const spentStr = `₹ ${summary.total_expense.toLocaleString("en-IN")}`;
    const remStr = `₹ ${summary.remaining_budget.toLocaleString("en-IN")}`;
    const bankStr = `₹ ${summary.bank_expense.toLocaleString("en-IN")}`;
    const cashStr = `₹ ${summary.cash_expense.toLocaleString("en-IN")}`;

    const plan: DirectorPerformancePlan = {
      planId: "DAILY_SPENDS_WRITTEN",
      totalDurationMs: 4000,
      displayMode: "written",
      speechText: `Your total expense logged today is ${spentStr}. You have ${remStr} remaining in your daily budget.`,
      cardContent: {
        title: "LIVE LEDGER SPEND",
        primaryValue: spentStr,
        delta: summary.remaining_budget > 0 ? "Within Daily Cap" : "Cap Exceeded",
        bodyText: `Online/Bank: ${bankStr} | Cash Wallet: ${cashStr}. Remaining daily discretionary budget: ${remStr}.`,
        actionLabel: "VIEW AUDIT LOG",
      },
      postureSequence: [
        { ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "SPEAKING" }
      ],
      hologram: { title: "DAILY_SPENDS", metrics: [], series: [] }
    };
    speakPlan(plan);
  };

  const triggerPortfolioVisual = () => {
    const plan: DirectorPerformancePlan = {
      planId: "PORTFOLIO_RUNWAY_VISUAL",
      totalDurationMs: 5000,
      displayMode: "visual",
      speechText: "Displaying your portfolio net worth and asset distribution. Your total verified portfolio stands at ₹ 1.48 Crore.",
      visualData: {
        primaryMetric: "₹ 1.48 Cr",
        metricLabel: "TOTAL PORTFOLIO NET WORTH",
        targetDelta: "+16.8% YoY",
        monthlySavings: "₹ 1.85 L",
        monthlyBurn: "₹ 65,000",
        chartPoints: [
          { label: "Apr", value: 0.35, display: "₹ 98 L" },
          { label: "Jul", value: 0.52, display: "₹ 1.12 Cr" },
          { label: "Oct", value: 0.70, display: "₹ 1.28 Cr" },
          { label: "Jan", value: 0.88, display: "₹ 1.48 Cr" },
        ],
        allocations: [
          { category: "Equity & Mutual Funds", pct: 0.52, amount: "₹ 76.9 L", color: "#38bdf8" },
          { category: "Fixed Deposits & Debt", pct: 0.28, amount: "₹ 41.4 L", color: "#818cf8" },
          { category: "Physical Gold & SGB", pct: 0.12, amount: "₹ 17.8 L", color: "#fbbf24" },
          { category: "Liquid Savings Buffer", pct: 0.08, amount: "₹ 11.9 L", color: "#34d399" },
        ],
      },
      postureSequence: [
        { ptsMs: 0, posture: "PRESENT_HOLOGRAM", gaze: "HOLOGRAM_DATA", gesture: "PRESENT_TABLET" }
      ],
      hologram: { title: "PORTFOLIO_RUNWAY", metrics: [], series: [] }
    };
    speakPlan(plan);
  };

  const triggerNetWorthBoth = async () => {
    const summary = await fetchLedgerSummary();
    const spentStr = `₹ ${summary.total_expense.toLocaleString("en-IN")}`;

    const plan: DirectorPerformancePlan = {
      planId: "NET_WORTH_FULL_AUDIT",
      totalDurationMs: 6000,
      displayMode: "both",
      speechText: "Activating complete portfolio audit. Telemetric asset breakdown is projected, and the written summary is on your screen.",
      cardContent: {
        title: "PORTFOLIO POSITION",
        primaryValue: "₹ 1.48 Cr",
        delta: "+16.8% YoY",
        bodyText: `Verified asset holdings: Equity & Debt active. Today's live expense stream logged: ${spentStr}. Zero debt liabilities.`,
        actionLabel: "DOWNLOAD TAX AUDIT",
      },
      visualData: {
        primaryMetric: "₹ 1.48 Cr",
        metricLabel: "TOTAL PORTFOLIO NET WORTH",
        targetDelta: "+16.8% YoY",
        monthlySavings: "₹ 1.85 L",
        monthlyBurn: "₹ 65,000",
        chartPoints: [
          { label: "Apr", value: 0.35, display: "₹ 98 L" },
          { label: "Jul", value: 0.52, display: "₹ 1.12 Cr" },
          { label: "Oct", value: 0.70, display: "₹ 1.28 Cr" },
          { label: "Jan", value: 0.88, display: "₹ 1.48 Cr" },
        ],
        allocations: [
          { category: "Equity & Mutual Funds", pct: 0.52, amount: "₹ 76.9 L", color: "#38bdf8" },
          { category: "Fixed Deposits & Debt", pct: 0.28, amount: "₹ 41.4 L", color: "#818cf8" },
          { category: "Physical Gold & SGB", pct: 0.12, amount: "₹ 17.8 L", color: "#fbbf24" },
          { category: "Liquid Savings Buffer", pct: 0.08, amount: "₹ 11.9 L", color: "#34d399" },
        ],
      },
      postureSequence: [
        { ptsMs: 0, posture: "PRESENT_HOLOGRAM", gaze: "HOLOGRAM_DATA", gesture: "PRESENT_TABLET" }
      ],
      hologram: { title: "NET_WORTH_AUDIT", metrics: [], series: [] }
    };
    speakPlan(plan);
  };

  const logVoiceCashExpense = async (amount: number, category: string) => {
    try {
      const res = await fetch("http://127.0.0.1:8000/v1/transactions/cash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount, category }),
      });

      if (res.ok) {
        const summary = await fetchLedgerSummary();
        const amtStr = `₹ ${amount.toLocaleString("en-IN")}`;
        const remStr = `₹ ${summary.remaining_budget.toLocaleString("en-IN")}`;

        const plan: DirectorPerformancePlan = {
          planId: "CASH_LOGGED",
          totalDurationMs: 4000,
          displayMode: "written",
          speechText: `Recorded ${amtStr} cash for ${category}. You have ${remStr} remaining today.`,
          cardContent: {
            title: "CASH EXPENSE RECORDED",
            primaryValue: amtStr,
            delta: "CASH_WALLET",
            bodyText: `Category: ${category}. Remaining daily discretionary budget: ${remStr}.`,
            actionLabel: "CONFIRM ENTRY",
          },
          postureSequence: [
            { ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "SPEAKING" }
          ],
          hologram: { title: "CASH_RECORDED", metrics: [], series: [] }
        };
        speakPlan(plan);
        return;
      }
    } catch {
      console.error("Failed to post cash transaction to backend");
    }

    const fallbackPlan: DirectorPerformancePlan = {
      planId: "CASH_FAIL",
      totalDurationMs: 3000,
      displayMode: "written",
      speechText: "Could not connect to the local ledger. Make sure the backend service is running.",
      cardContent: {
        title: "LEDGER CONNECTION ERROR",
        primaryValue: "OFFLINE",
        delta: "PORT 8000",
        bodyText: "Please verify backend server status.",
      },
      postureSequence: [{ ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "SPEAKING" }],
      hologram: { title: "ERROR", metrics: [], series: [] }
    };
    speakPlan(fallbackPlan);
  };

  const processVoiceDirective = (command: string) => {
    const text = command.trim().toLowerCase().replace(/[.!?,]+$/g, "").trim();

    // 1. Natural Voice Cash Logging:
    // Matches: "spent 300 cash on auto", "paid 150 for tea", "log 500 cash lunch"
    const cashRegex = /(?:spent|paid|log|add)\s*(?:rs\.?|inr)?\s*([0-9]+)\s*(?:rs|rupees|inr|cash)?\s*(?:for|on|in)?\s*(.*)/i;
    const match = text.match(cashRegex);
    if (match && (text.includes("cash") || text.includes("spent") || text.includes("paid"))) {
      const amount = parseInt(match[1], 10);
      let category = match[2]?.trim() || "General Expense";
      if (!category || category === "cash") category = "Cash / General";
      logVoiceCashExpense(amount, category);
      return;
    }

    // 2. Greeting / Wake phrase
    const isGreeting = (
      /^(hi|hello|hey|good morning|good afternoon|good evening)(\s+jurix)?$/.test(text) ||
      /^jurix$/.test(text)
    );

    if (isGreeting) {
      const plan: DirectorPerformancePlan = {
        planId: "GREETING_PLAN",
        totalDurationMs: 2500,
        displayMode: "written",
        speechText: "Hello Chetan. Jurix is online and monitoring your financial portfolio. How can I assist you?",
        cardContent: {
          title: "JURIX ACTIVE",
          primaryValue: "ONLINE",
          delta: "SYSTEM READY",
          bodyText: "Voice engine connected. You can log cash by saying 'spent 200 cash on auto', or say 'show visual portfolio'.",
        },
        postureSequence: [{ ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "SPEAKING" }],
        hologram: { title: "STANDBY", metrics: [], series: [] }
      };
      speakPlan(plan, "greeting");
      return;
    }

      // 3. Dismiss command
      if (/\b(dismiss|close|hide|collapse|clear|stop)\b/.test(text)) {
        setIsSummoned(false);
        setPresentationActive(false);
        const plan: DirectorPerformancePlan = {
          planId: "DISMISS_PLAN",
          totalDurationMs: 1200,
          displayMode: "written",
          speechText: "Hiding presentation display.",
          postureSequence: [{ ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "SPEAKING" }],
          hologram: { title: "CLOSED", metrics: [], series: [] }
        };
        speakPlan(plan);
        return;
      }

      // 4. Visual 3D Projection Request
      if (/\b(visual|hologram|chart|charts|project|projection|show me visual|show visually)\b/.test(text)) {
        triggerPortfolioVisual();
        return;
      }

      // 5. Daily Spend / Ledger Query
      if (/\b(spend|spends|spent|spending|expense|expenses|summary|balance|audit|how much)\b/.test(text)) {
        triggerDailySpendsWritten();
        return;
      }

      // 6. Net Worth / Full Audit Request
      if (/\b(net worth|audit everything|both|full audit|portfolio)\b/.test(text)) {
        triggerNetWorthBoth();
        return;
      }

      // Fallback acknowledgment
      const defaultPlan: DirectorPerformancePlan = {
        planId: "GENERAL_ACK",
        totalDurationMs: 3000,
        displayMode: "written",
        speechText: `Directive noted: "${command}". Querying financial engine.`,
        cardContent: {
          title: "DIRECTIVE ACKNOWLEDGED",
          primaryValue: "PROCESSING",
          delta: "SYSTEM ACTIVE",
          bodyText: `Understood: "${command}". Available commands: 'how much did i spend', 'spent 150 cash on lunch', or 'show visual'.`,
        },
        postureSequence: [{ ptsMs: 0, posture: "SEATED_DESK", gaze: "CAMERA_USER", gesture: "SPEAKING" }],
        hologram: { title: "ACKNOWLEDGED", metrics: [], series: [] }
      };
      speakPlan(defaultPlan);
    };

  useEffect(() => {
    processVoiceDirectiveRef.current = processVoiceDirective;
  });

  useEffect(() => {
    const gateway = new JurixVoiceGateway();
    voiceGatewayRef.current = gateway;

    gateway.setCallbacks({
      onStateChange: (state) => {
        if (state === "listening") {
          setAvatarMode("listening");
        } else if (state === "idle" && (!("speechSynthesis" in window) || !window.speechSynthesis.speaking)) {
          setAvatarMode("idle");
        }
      },
      onTranscript: (userText) => {
        setTranscript(userText);
        processVoiceDirectiveRef.current(userText);
      },
      onError: (err) => {
        console.error("Voice gateway error:", err);
      }
    });

    return () => {
      voiceActiveRef.current = false;
      gateway.stop();
      if (voiceGatewayRef.current === gateway) {
        voiceGatewayRef.current = null;
      }
    };
  }, []);

  const toggleVoice = () => {
    if (!voiceGatewayRef.current) return;

    if (voiceActiveRef.current) {
      voiceActiveRef.current = false;
      voiceGatewayRef.current.stop();
      setVoiceActive(false);
      setAvatarMode("idle");
      return;
    }

    voiceActiveRef.current = true;
    setVoiceActive(true);
    voiceGatewayRef.current.start();
  };

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-[#010308] text-slate-100 font-mono select-none">
      <img
        aria-hidden="true"
        src="/images/jurix_presentation_background_v3.jpg"
        alt=""
        className="absolute inset-0 h-full w-full object-cover object-center"
        style={{ zIndex: 0, imageRendering: "auto" }}
      />

      {/* 3D AVATAR & PROJECTION STAGE */}
      <div className="absolute inset-0 z-0">
        <JurixWebRTCStage
          mode={avatarMode}
          presentationTrigger={presentationTrigger}
          presentationActive={presentationActive}
          presentationData={activePlan?.visualData}
        />
      </div>

      {/* 2D WRITTEN CARD */}
      <div className="absolute inset-0 z-20 pointer-events-none">
        <AnimatePresence>
          {isSummoned && (
            <motion.div
              initial={{ opacity: 0, scale: 0.88, x: 70, rotateY: 15 }}
              animate={{ opacity: 1, scale: 1, x: 0, rotateY: -6 }}
              exit={{ opacity: 0, scale: 0.9, x: 50 }}
              transition={{ type: "spring", stiffness: 130, damping: 20 }}
              className="pointer-events-auto absolute right-6 top-10 md:right-8 md:top-8 w-[min(340px,92vw)] bg-gradient-to-b from-[#031525]/92 via-[#020b14]/96 to-[#01060c]/98 border border-cyan-400/40 rounded-2xl p-4 shadow-[0_0_45px_rgba(6,182,212,0.22)] backdrop-blur-3xl"
              style={{ perspective: 1200 }}
            >
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-300" />
                  <span className="text-[11px] tracking-widest text-cyan-400 font-bold uppercase">
                    {activePlan?.cardContent?.title || activePlan?.hologram.title || "EXECUTIVE ADVISOR"}
                  </span>
                </div>
                <button
                  onClick={() => setIsSummoned(false)}
                  className="p-1 rounded-lg text-slate-400 hover:text-white transition"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {activePlan?.cardContent?.primaryValue && (
                <div className="mb-3 flex items-baseline justify-between">
                  <span className="text-3xl font-extrabold text-cyan-200 tracking-tight">
                    {activePlan.cardContent.primaryValue}
                  </span>
                  {activePlan.cardContent.delta && (
                    <span className="text-xs text-emerald-400 font-semibold">
                      {activePlan.cardContent.delta}
                    </span>
                  )}
                </div>
              )}

              <p className="text-[12px] leading-relaxed text-slate-300 mb-4 font-sans">
                {activePlan?.cardContent?.bodyText || activePlan?.speechText}
              </p>

              {activePlan?.cardContent?.actionLabel && (
                <button
                  onClick={() => setIsSummoned(false)}
                  className="w-full py-2.5 rounded-xl border border-cyan-500/40 bg-cyan-950/50 text-cyan-300 hover:bg-cyan-900/60 transition flex items-center justify-center gap-1.5 font-bold text-xs font-mono"
                >
                  <Activity className="w-3.5 h-3.5" /> {activePlan.cardContent.actionLabel}
                </button>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* BOTTOM DUAL INTERACTION: VOICE + CHAT DIRECTIVE */}
      <div className="absolute bottom-6 left-1/2 -translate-x-1/2 z-20 flex flex-col sm:flex-row items-center gap-3 w-[min(92vw,620px)] justify-center">
        <button
          onClick={toggleVoice}
          type="button"
          className={`shrink-0 flex items-center gap-2 px-5 py-2.5 rounded-full border text-xs tracking-wider uppercase backdrop-blur-2xl transition duration-300 cursor-pointer shadow-lg ${voiceActive ? "border-red-500 bg-red-950/80 text-red-300 shadow-[0_0_25px_rgba(239,68,68,0.4)]" : "border-cyan-500/40 bg-[#02050c]/90 text-cyan-300 hover:border-cyan-400 hover:bg-cyan-950/70 shadow-[0_0_25px_rgba(6,182,212,0.25)]"}`}
        >
          {voiceActive ? <MicOff className="w-4 h-4 text-red-400 animate-pulse" /> : <Mic className="w-4 h-4 text-cyan-400" />}
          {voiceActive ? "Mute" : "Voice"}
        </button>

        <form
          onSubmit={handleTextSubmit}
          className="flex-1 flex items-center w-full bg-[#02050c]/90 border border-cyan-500/40 hover:border-cyan-400/80 focus-within:border-cyan-400 rounded-full px-4 py-1.5 backdrop-blur-2xl shadow-[0_0_25px_rgba(6,182,212,0.2)] transition-all duration-300"
        >
          <input
            type="text"
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            placeholder="Type directive (e.g. 'how much did i spend', 'cash 150 lunch')..."
            className="flex-1 bg-transparent border-none outline-none text-xs text-cyan-100 placeholder-slate-500 font-mono tracking-wide px-2 py-1"
          />
          <button
            type="submit"
            className="p-1.5 rounded-full text-cyan-400 hover:text-white hover:bg-cyan-500/20 transition cursor-pointer"
            title="Send Directive"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
            </div>
    </div>
  );
}
