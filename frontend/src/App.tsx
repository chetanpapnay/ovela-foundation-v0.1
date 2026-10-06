import { useEffect, useRef, useState } from "react";

type PresenceState =
  | "READY"
  | "LISTENING"
  | "THINKING"
  | "FOCUSED";

function App() {
  const [presence, setPresence] = useState<PresenceState>("READY");
  const [clock, setClock] = useState("");
  const [commandOpen, setCommandOpen] = useState(false);
  const [command, setCommand] = useState("");
  const commandRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const updateClock = () => {
      setClock(
        new Intl.DateTimeFormat("en-IN", {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        }).format(new Date()),
      );
    };

    updateClock();
    const timer = window.setInterval(updateClock, 1000);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (commandOpen) {
      commandRef.current?.focus();
    }
  }, [commandOpen]);

  const beginListening = () => {
    setPresence("LISTENING");
    setCommandOpen(true);
  };

  const submitCommand = () => {
    if (!command.trim()) {
      setPresence("LISTENING");
      return;
    }

    setPresence("THINKING");

    window.setTimeout(() => {
      setPresence("FOCUSED");
    }, 850);
  };

  const presenceText = {
    READY: "Here with you",
    LISTENING: "Listening",
    THINKING: "Thinking",
    FOCUSED: "Focused",
  }[presence];

  return (
    <div className={`ovela ${presence.toLowerCase()}`}>
      <style>{`
        :root {
          color-scheme: dark;
          font-family:
            Inter,
            ui-sans-serif,
            system-ui,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
          font-synthesis: none;
          text-rendering: optimizeLegibility;
        }

        * {
          box-sizing: border-box;
        }

        html,
        body,
        #root {
          width: 100%;
          min-width: 320px;
          min-height: 100%;
          margin: 0;
          background: #08090b;
        }

        body {
          overflow: hidden;
        }

        button,
        input {
          font: inherit;
        }

        button {
          -webkit-tap-highlight-color: transparent;
        }

        .ovela {
          position: relative;
          width: 100%;
          height: 100vh;
          height: 100svh;
          min-height: 620px;
          overflow: hidden;
          color: #f1f0ed;
          background:
            radial-gradient(
              ellipse 45% 72% at 50% 52%,
              rgba(113, 108, 98, 0.17),
              transparent 68%
            ),
            radial-gradient(
              ellipse 30% 60% at 50% 100%,
              rgba(77, 72, 66, 0.16),
              transparent 75%
            ),
            #08090b;
        }

        .ovela::before {
          content: "";
          position: absolute;
          inset: 0;
          pointer-events: none;
          background:
            linear-gradient(
              90deg,
              rgba(255,255,255,0.025),
              transparent 18%,
              transparent 82%,
              rgba(255,255,255,0.018)
            ),
            radial-gradient(
              ellipse at center,
              transparent 30%,
              rgba(0,0,0,0.52) 100%
            );
          z-index: 10;
        }

        .ovela::after {
          content: "";
          position: absolute;
          inset: 0;
          pointer-events: none;
          opacity: 0.16;
          background-image:
            repeating-linear-gradient(
              0deg,
              rgba(255,255,255,0.025) 0,
              rgba(255,255,255,0.025) 1px,
              transparent 1px,
              transparent 4px
            );
          mix-blend-mode: soft-light;
          z-index: 11;
        }

        .topbar {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          z-index: 20;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 28px 34px;
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .brand-symbol {
          position: relative;
          width: 27px;
          height: 27px;
          border: 1px solid rgba(221, 217, 208, 0.22);
          border-radius: 50%;
        }

        .brand-symbol::before {
          content: "";
          position: absolute;
          width: 5px;
          height: 5px;
          left: 10px;
          top: 10px;
          border-radius: 50%;
          background: #dedbd3;
          box-shadow: 0 0 14px rgba(240, 235, 222, 0.55);
        }

        .brand-copy {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }

        .brand-name {
          color: #e9e6df;
          font-size: 11px;
          font-weight: 650;
          letter-spacing: 0.2em;
        }

        .brand-type {
          color: #66645f;
          font-size: 8px;
          letter-spacing: 0.18em;
          text-transform: uppercase;
        }

        .session {
          display: flex;
          align-items: center;
          gap: 10px;
          color: #77756f;
          font-size: 9px;
          letter-spacing: 0.16em;
          text-transform: uppercase;
        }

        .session-dot {
          width: 5px;
          height: 5px;
          border-radius: 50%;
          background: #c4c0b6;
          box-shadow: 0 0 13px rgba(220, 214, 199, 0.5);
        }

        .scene {
          position: absolute;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .portrait-stage {
          position: relative;
          width: min(58vw, 760px);
          height: min(92vh, 820px);
          min-height: 570px;
          margin-top: 42px;
          overflow: hidden;
        }

        .portrait-glow {
          position: absolute;
          width: 62%;
          height: 74%;
          left: 19%;
          top: 11%;
          border-radius: 50%;
          background:
            radial-gradient(
              ellipse,
              rgba(205, 198, 185, 0.16),
              rgba(120, 116, 108, 0.06) 43%,
              transparent 72%
            );
          filter: blur(28px);
          opacity: 0.82;
          animation: ambientBreath 7s ease-in-out infinite;
        }

        .figure {
          position: absolute;
          left: 50%;
          bottom: -7%;
          width: 76%;
          height: 92%;
          transform: translateX(-50%);
        }

        .shoulders {
          position: absolute;
          left: 50%;
          bottom: 0;
          width: 100%;
          height: 47%;
          transform: translateX(-50%);
          border-radius: 48% 48% 0 0 / 26% 26% 0 0;
          background:
            radial-gradient(
              ellipse at 50% 7%,
              rgba(222, 216, 205, 0.25),
              transparent 38%
            ),
            linear-gradient(
              112deg,
              #101113 0%,
              #292a2b 25%,
              #111214 52%,
              #2b2a28 76%,
              #0c0d0f 100%
            );
          box-shadow:
            inset 0 28px 55px rgba(255,255,255,0.025),
            0 -12px 50px rgba(195, 188, 175, 0.045);
        }

        .neck {
          position: absolute;
          z-index: 3;
          left: 50%;
          top: 45%;
          width: 21%;
          height: 17%;
          transform: translateX(-50%);
          border-radius: 40% 40% 30% 30%;
          background:
            linear-gradient(
              90deg,
              #4a4641,
              #81786d 43%,
              #5d564f 66%,
              #292725
            );
          box-shadow:
            inset 8px 0 13px rgba(255,255,255,0.07),
            inset -12px 0 20px rgba(0,0,0,0.28);
        }

        .head {
          position: absolute;
          z-index: 5;
          left: 50%;
          top: 5%;
          width: 38%;
          height: 47%;
          transform: translateX(-50%);
          border-radius: 46% 46% 48% 48% / 39% 39% 59% 59%;
          background:
            radial-gradient(
              ellipse at 34% 27%,
              rgba(255,255,255,0.21),
              transparent 22%
            ),
            radial-gradient(
              ellipse at 64% 48%,
              rgba(255,255,255,0.07),
              transparent 35%
            ),
            linear-gradient(
              105deg,
              #4b4641 0%,
              #887f74 29%,
              #a0978b 47%,
              #716960 70%,
              #393531 100%
            );
          box-shadow:
            inset 11px 8px 28px rgba(255,255,255,0.07),
            inset -19px -13px 30px rgba(0,0,0,0.3),
            0 20px 55px rgba(0,0,0,0.42);
          transition:
            transform 900ms cubic-bezier(.22,.75,.25,1),
            filter 700ms ease;
        }

        .hair {
          position: absolute;
          z-index: 7;
          left: 50%;
          top: 1%;
          width: 47%;
          height: 48%;
          transform: translateX(-50%);
          border-radius: 48% 48% 25% 25% / 44% 44% 23% 23%;
          background:
            radial-gradient(
              ellipse at 45% 14%,
              #34312e,
              #171718 47%,
              #090a0b 82%
            );
          box-shadow:
            inset 9px 6px 18px rgba(255,255,255,0.035),
            8px 18px 35px rgba(0,0,0,0.34);
        }

        .hair::after {
          content: "";
          position: absolute;
          right: -5%;
          top: 26%;
          width: 20%;
          height: 57%;
          border-radius: 0 70% 65% 0;
          background: linear-gradient(
            90deg,
            #171718,
            #090a0b
          );
        }

        .brow {
          position: absolute;
          z-index: 8;
          top: 41%;
          width: 20%;
          height: 4px;
          border-radius: 50%;
          background: rgba(39, 36, 33, 0.72);
        }

        .brow.left {
          left: 23%;
          transform: rotate(-5deg);
        }

        .brow.right {
          right: 23%;
          transform: rotate(5deg);
        }

        .eye {
          position: absolute;
          z-index: 8;
          top: 45%;
          width: 17%;
          height: 8%;
          border-radius: 50%;
          background:
            radial-gradient(
              circle at 52% 52%,
              #101112 0 18%,
              #343230 20% 28%,
              transparent 30%
            );
          opacity: 0.82;
          transition:
            transform 400ms ease,
            opacity 400ms ease;
        }

        .eye.left {
          left: 23%;
        }

        .eye.right {
          right: 23%;
        }

        .nose {
          position: absolute;
          z-index: 8;
          left: 50%;
          top: 47%;
          width: 10%;
          height: 19%;
          transform: translateX(-50%);
          border-right: 1px solid rgba(39, 36, 33, 0.28);
          border-bottom: 1px solid rgba(39, 36, 33, 0.18);
          border-radius: 0 0 65% 35%;
        }

        .mouth {
          position: absolute;
          z-index: 9;
          left: 50%;
          top: 70%;
          width: 24%;
          height: 8%;
          transform: translateX(-50%);
          border-bottom: 1px solid rgba(44, 39, 36, 0.62);
          border-radius: 0 0 50% 50%;
          transition:
            transform 450ms ease,
            height 450ms ease;
        }

        .ear {
          position: absolute;
          z-index: 4;
          top: 39%;
          width: 9%;
          height: 16%;
          border-radius: 50%;
          background: linear-gradient(
            90deg,
            #746b62,
            #8f867b
          );
        }

        .ear.left {
          left: 30%;
        }

        .ear.right {
          right: 30%;
        }

        .presence.listening .head {
          transform:
            translateX(-50%)
            translateY(-4px)
            rotate(-1deg);
        }

        .presence.listening .eye {
          transform: scaleY(1.12);
        }

        .presence.thinking .head {
          transform:
            translateX(-50%)
            translateY(-2px)
            rotate(1.4deg);
          filter: brightness(0.94);
        }

        .presence.thinking .eye.left {
          transform: translateY(-2px);
        }

        .presence.thinking .eye.right {
          transform: translateY(-4px);
        }

        .presence.focused .head {
          transform:
            translateX(-50%)
            translateY(-3px)
            rotate(-0.6deg);
        }

        .presence.focused .mouth {
          transform: translateX(-50%) scaleX(1.08);
        }

        .blink {
          position: absolute;
          z-index: 12;
          left: 50%;
          top: 48%;
          width: 45%;
          height: 8%;
          transform: translateX(-50%) scaleY(0);
          border-radius: 50%;
          background: rgba(62, 57, 52, 0.45);
          opacity: 0;
          animation: blink 6.2s infinite;
        }

        .identity {
          position: absolute;
          left: 42px;
          bottom: 42px;
          z-index: 20;
          max-width: 250px;
        }

        .identity-name {
          color: #ebe8e1;
          font-size: clamp(25px, 3vw, 38px);
          font-weight: 340;
          letter-spacing: -0.035em;
        }

        .identity-role {
          margin-top: 7px;
          color: #706e68;
          font-size: 9px;
          letter-spacing: 0.19em;
          text-transform: uppercase;
        }

        .identity-state {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-top: 19px;
          color: #8b8881;
          font-size: 10px;
          letter-spacing: 0.12em;
          text-transform: uppercase;
        }

        .state-line {
          width: 22px;
          height: 1px;
          background: #8b8881;
          opacity: 0.55;
        }

        .context {
          position: absolute;
          right: 38px;
          bottom: 42px;
          z-index: 20;
          width: 225px;
          color: #696761;
        }

        .context-label {
          margin-bottom: 13px;
          color: #85827b;
          font-size: 8px;
          letter-spacing: 0.18em;
          text-transform: uppercase;
        }

        .context-line {
          display: flex;
          justify-content: space-between;
          gap: 16px;
          padding: 9px 0;
          border-top: 1px solid rgba(255,255,255,0.06);
          font-size: 9px;
          letter-spacing: 0.07em;
        }

        .context-value {
          color: #b0ada5;
          text-align: right;
        }

        .controls {
          position: absolute;
          left: 50%;
          bottom: 34px;
          z-index: 30;
          display: flex;
          align-items: center;
          gap: 13px;
          transform: translateX(-50%);
        }

        .voice-button {
          position: relative;
          width: 68px;
          height: 68px;
          border: 1px solid rgba(228, 224, 214, 0.19);
          border-radius: 50%;
          background: rgba(18, 18, 18, 0.72);
          color: #e6e2da;
          cursor: pointer;
          box-shadow:
            0 14px 50px rgba(0,0,0,0.34),
            inset 0 1px 0 rgba(255,255,255,0.06);
          backdrop-filter: blur(18px);
          transition:
            transform 220ms ease,
            background 220ms ease,
            border-color 220ms ease;
        }

        .voice-button:hover {
          transform: translateY(-2px);
          border-color: rgba(228,224,214,0.3);
          background: rgba(30,30,30,0.8);
        }

        .voice-button:active {
          transform: scale(0.97);
        }

        .voice-icon {
          position: absolute;
          left: 50%;
          top: 50%;
          width: 13px;
          height: 21px;
          transform: translate(-50%, -58%);
          border: 1.5px solid #ddd9d0;
          border-radius: 8px;
        }

        .voice-icon::before {
          content: "";
          position: absolute;
          left: 50%;
          bottom: -8px;
          width: 17px;
          height: 9px;
          transform: translateX(-50%);
          border: 1.5px solid #ddd9d0;
          border-top: 0;
          border-radius: 0 0 12px 12px;
        }

        .voice-icon::after {
          content: "";
          position: absolute;
          left: 50%;
          bottom: -13px;
          width: 1px;
          height: 6px;
          transform: translateX(-50%);
          background: #ddd9d0;
        }

        .command-shell {
          position: absolute;
          left: 50%;
          bottom: 44px;
          z-index: 25;
          width: min(460px, calc(100vw - 40px));
          transform:
            translateX(-50%)
            translateY(18px);
          opacity: 0;
          pointer-events: none;
          transition:
            opacity 260ms ease,
            transform 260ms ease;
        }

        .command-shell.open {
          transform: translateX(-50%) translateY(0);
          opacity: 1;
          pointer-events: auto;
        }

        .command-inner {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 9px 10px 9px 18px;
          border: 1px solid rgba(221,217,207,0.14);
          border-radius: 18px;
          background: rgba(15,15,15,0.86);
          box-shadow: 0 22px 70px rgba(0,0,0,0.42);
          backdrop-filter: blur(24px);
        }

        .command-inner input {
          flex: 1;
          min-width: 0;
          border: 0;
          outline: 0;
          background: transparent;
          color: #dedbd3;
          font-size: 12px;
        }

        .command-inner input::placeholder {
          color: #66645f;
        }

        .command-send {
          width: 34px;
          height: 34px;
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 11px;
          background: rgba(255,255,255,0.06);
          color: #c9c5bd;
          cursor: pointer;
        }

        .clock {
          position: absolute;
          top: 31px;
          left: 50%;
          z-index: 20;
          transform: translateX(-50%);
          color: #68665f;
          font-size: 9px;
          letter-spacing: 0.18em;
        }

        .corner-mark {
          position: absolute;
          z-index: 20;
          width: 8px;
          height: 8px;
          border-top: 1px solid rgba(220,215,205,0.16);
          border-left: 1px solid rgba(220,215,205,0.16);
        }

        .corner-mark.one {
          top: 94px;
          left: 34px;
        }

        .corner-mark.two {
          top: 94px;
          right: 34px;
          transform: rotate(90deg);
        }

        .corner-mark.three {
          bottom: 94px;
          left: 34px;
          transform: rotate(-90deg);
        }

        .corner-mark.four {
          right: 34px;
          bottom: 94px;
          transform: rotate(180deg);
        }

        @keyframes ambientBreath {
          0%, 100% {
            transform: scale(0.97);
            opacity: 0.68;
          }

          50% {
            transform: scale(1.035);
            opacity: 0.88;
          }
        }

        @keyframes blink {
          0%,
          42%,
          44%,
          72%,
          74%,
          100% {
            opacity: 0;
            transform: translateX(-50%) scaleY(0);
          }

          43%,
          73% {
            opacity: 0.8;
            transform: translateX(-50%) scaleY(1);
          }
        }

        @media (max-width: 900px) {
          .topbar {
            padding: 22px 20px;
          }

          .portrait-stage {
            width: min(90vw, 650px);
            height: 78vh;
            min-height: 520px;
            margin-top: 58px;
          }

          .identity {
            left: 22px;
            bottom: 25px;
          }

          .context {
            display: none;
          }

          .controls {
            bottom: 25px;
          }

          .corner-mark.one {
            top: 78px;
            left: 20px;
          }

          .corner-mark.two {
            top: 78px;
            right: 20px;
          }

          .corner-mark.three,
          .corner-mark.four {
            display: none;
          }
        }

        @media (max-width: 560px) {
          .session {
            font-size: 7px;
          }

          .clock {
            top: 25px;
            font-size: 8px;
          }

          .portrait-stage {
            width: 118vw;
            height: 75vh;
            min-height: 500px;
            margin-top: 45px;
          }

          .identity {
            bottom: 24px;
          }

          .identity-name {
            font-size: 25px;
          }

          .identity-role {
            font-size: 7px;
          }

          .identity-state {
            margin-top: 12px;
            font-size: 8px;
          }

          .controls {
            bottom: 22px;
          }

          .voice-button {
            width: 60px;
            height: 60px;
          }

          .command-shell {
            bottom: 32px;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          *,
          *::before,
          *::after {
            animation-duration: 0.001ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      <header className="topbar">
        <div className="brand">
          <div className="brand-symbol" aria-hidden="true" />
          <div className="brand-copy">
            <div className="brand-name">OVELA</div>
            <div className="brand-type">Foundation</div>
          </div>
        </div>

        <div className="session">
          <span className="session-dot" />
          Protected session
        </div>
      </header>

      <div className="clock">{clock}</div>

      <span className="corner-mark one" />
      <span className="corner-mark two" />
      <span className="corner-mark three" />
      <span className="corner-mark four" />

      <main className="scene">
        <section className="portrait-stage" aria-label={`JURIX ${presenceText}`}>
          <div className="portrait-glow" />

          <div className="figure">
            <div className="shoulders" />
            <div className="neck" />

            <div className="head">
              <div className="ear left" />
              <div className="ear right" />

              <div className="brow left" />
              <div className="brow right" />

              <div className="eye left" />
              <div className="eye right" />

              <div className="nose" />
              <div className="mouth" />

              <div className="blink" />
            </div>

            <div className="hair" />
          </div>
        </section>
      </main>

      <section className="identity" aria-live="polite">
        <div className="identity-name">JURIX</div>
        <div className="identity-role">
          Ovela intelligence · personal security
        </div>

        <div className="identity-state">
          <span className="state-line" />
          {presenceText}
        </div>
      </section>

      <section className="context" aria-label="System context">
        <div className="context-label">Ovela state</div>

        <div className="context-line">
          <span>Security</span>
          <span className="context-value">Active</span>
        </div>

        <div className="context-line">
          <span>Authority</span>
          <span className="context-value">Protected</span>
        </div>

        <div className="context-line">
          <span>Intelligence</span>
          <span className="context-value">Ready</span>
        </div>
      </section>

      <div className={`command-shell ${commandOpen ? "open" : ""}`}>
        <div className="command-inner">
          <input
            ref={commandRef}
            value={command}
            onChange={(event) => setCommand(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                submitCommand();
              }

              if (event.key === "Escape") {
                setCommandOpen(false);
                setPresence("READY");
              }
            }}
            placeholder="Tell JURIX what you need..."
            aria-label="Command JURIX"
          />

          <button
            className="command-send"
            type="button"
            onClick={submitCommand}
            aria-label="Send command"
          >
            →
          </button>
        </div>
      </div>

      <div className="controls">
        <button
          className="voice-button"
          type="button"
          onClick={() => {
            if (commandOpen) {
              setCommandOpen(false);
              setPresence("READY");
              return;
            }

            beginListening();
          }}
          aria-label={
            commandOpen ? "Close JURIX command input" : "Speak with JURIX"
          }
        >
          <span className="voice-icon" />
        </button>
      </div>
    </div>
  );
}

export default App;