import { useEffect, useMemo, useRef, useState } from "react";

type PresenceMode = "idle" | "listening" | "thinking" | "speaking";
type WorkspaceMode = "none" | "financial" | "legal" | "security";

type Message = {
  id: number;
  role: "user" | "jurix";
  text: string;
};

const INITIAL_MESSAGES: Message[] = [
  {
    id: 1,
    role: "jurix",
    text: "I’m here. Tell me what you want to understand, check, or investigate.",
  },
];

const styles = `
:root {
  color-scheme: dark;
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  background: #050606;
  color: #eeeae2;
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
}

body {
  min-height: 100vh;
  overflow: hidden;
  background:
    radial-gradient(circle at 50% 42%, rgba(116, 92, 55, 0.08), transparent 31%),
    radial-gradient(circle at 72% 65%, rgba(255, 255, 255, 0.025), transparent 32%),
    #050606;
}

button,
input,
textarea {
  font: inherit;
}

button {
  border: 0;
}

.app {
  position: relative;
  min-height: 100vh;
  overflow: hidden;
  background:
    radial-gradient(circle at 50% 43%, rgba(151, 121, 78, 0.065), transparent 30%),
    linear-gradient(180deg, #070808 0%, #050606 54%, #030404 100%);
}

.app::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  opacity: 0.32;
  background-image:
    linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.014) 1px, transparent 1px);
  background-size: 88px 88px;
  mask-image: linear-gradient(to bottom, transparent, black 22%, black 78%, transparent);
}

.app::after {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(ellipse at center, transparent 34%, rgba(0,0,0,0.34) 100%);
}

.shell {
  position: relative;
  z-index: 2;
  width: min(1480px, 100%);
  min-height: 100vh;
  margin: 0 auto;
  overflow: hidden;
}

.topbar {
  position: absolute;
  z-index: 20;
  top: 0;
  left: 0;
  right: 0;
  height: 92px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 42px;
  border-bottom: 1px solid rgba(255,255,255,0.045);
  background: linear-gradient(
    180deg,
    rgba(5,6,6,0.94),
    rgba(5,6,6,0.58),
    transparent
  );
}

.brand {
  display: flex;
  align-items: center;
  gap: 13px;
}

.brand-mark {
  width: 10px;
  height: 10px;
  transform: rotate(45deg);
  border: 1px solid rgba(206,174,119,0.75);
  box-shadow: 0 0 18px rgba(206,174,119,0.08);
}

.brand-name {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.22em;
  color: #e9e2d5;
}

.brand-subtitle {
  margin-left: 2px;
  color: rgba(231,225,215,0.32);
  font-size: 9px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
}

.system-state {
  display: flex;
  align-items: center;
  gap: 9px;
  color: rgba(231,225,215,0.42);
  font-size: 9px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.state-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #b8ad91;
  box-shadow: 0 0 12px rgba(184,173,145,0.4);
}

.stage {
  position: absolute;
  inset: 92px 0 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(360px, 42%);
  transition: grid-template-columns 700ms cubic-bezier(.22,.75,.18,1);
}

.stage.has-workspace {
  grid-template-columns: minmax(0, 55%) minmax(420px, 45%);
}

.presence-zone {
  position: relative;
  min-width: 0;
  min-height: calc(100vh - 92px);
  display: flex;
  align-items: center;
  justify-content: center;
  transition:
    transform 700ms cubic-bezier(.22,.75,.18,1),
    opacity 500ms ease;
}

.stage.has-workspace .presence-zone {
  transform: translateX(-7%);
}

.atmosphere {
  position: absolute;
  width: min(680px, 72vw);
  height: min(680px, 72vw);
  border-radius: 50%;
  background:
    radial-gradient(
      circle,
      rgba(177,146,96,0.075) 0%,
      rgba(177,146,96,0.028) 24%,
      transparent 62%
    );
  filter: blur(2px);
  pointer-events: none;
}

.atmosphere-ring {
  position: absolute;
  width: min(500px, 62vw);
  height: min(500px, 62vw);
  border-radius: 50%;
  border: 1px solid rgba(198,168,113,0.07);
  box-shadow:
    0 0 70px rgba(198,168,113,0.025),
    inset 0 0 80px rgba(255,255,255,0.012);
  animation: ringBreath 7s ease-in-out infinite;
}

@keyframes ringBreath {
  0%, 100% {
    transform: scale(0.985);
    opacity: 0.65;
  }
  50% {
    transform: scale(1.015);
    opacity: 1;
  }
}

.jurix {
  position: relative;
  width: min(430px, 58vw);
  height: min(650px, 70vh);
  min-width: 300px;
  min-height: 470px;
  transform: translateY(2%);
  transition:
    transform 700ms cubic-bezier(.22,.75,.18,1),
    filter 500ms ease;
  animation: presenceFloat 8s ease-in-out infinite;
}

.stage.has-workspace .jurix {
  transform: translateY(2%) scale(0.91);
}

@keyframes presenceFloat {
  0%, 100% {
    translate: 0 0;
  }
  50% {
    translate: 0 -5px;
  }
}

.jurix-shadow {
  position: absolute;
  left: 50%;
  bottom: 2%;
  width: 55%;
  height: 8%;
  transform: translateX(-50%);
  border-radius: 50%;
  background: rgba(0,0,0,0.65);
  filter: blur(18px);
}

.jurix-halo {
  position: absolute;
  left: 50%;
  top: 8%;
  width: 68%;
  aspect-ratio: 1;
  transform: translateX(-50%);
  border-radius: 50%;
  border: 1px solid rgba(210,183,135,0.045);
  box-shadow:
    0 0 80px rgba(184,151,95,0.045),
    inset 0 0 70px rgba(255,255,255,0.018);
}

.jurix-head {
  position: absolute;
  z-index: 5;
  top: 8%;
  left: 50%;
  width: 25%;
  aspect-ratio: 0.78;
  transform: translateX(-50%);
  border-radius: 48% 48% 44% 44%;
  background:
    radial-gradient(
      ellipse at 42% 31%,
      rgba(232,215,194,0.25),
      rgba(121,103,89,0.18) 35%,
      rgba(31,30,29,0.96) 72%
    );
  box-shadow:
    -16px 20px 32px rgba(0,0,0,0.5),
    inset 8px -10px 25px rgba(0,0,0,0.45);
  animation: headIdle 8s ease-in-out infinite;
}

@keyframes headIdle {
  0%, 100% {
    rotate: 0deg;
  }
  50% {
    rotate: -0.7deg;
  }
}

.hair {
  position: absolute;
  z-index: 6;
  top: 5.2%;
  left: 50%;
  width: 30%;
  height: 25%;
  transform: translateX(-50%);
  border-radius: 48% 52% 32% 32%;
  background:
    linear-gradient(105deg, #0a0a0a 0%, #1b1917 38%, #080808 68%, #020202 100%);
  box-shadow:
    -13px 13px 26px rgba(0,0,0,0.5),
    9px 9px 22px rgba(0,0,0,0.35);
}

.hair::after {
  content: "";
  position: absolute;
  right: -11%;
  top: 17%;
  width: 22%;
  height: 78%;
  border-radius: 50%;
  background: linear-gradient(180deg, #11100f, #050505);
  transform: rotate(-4deg);
}

.face-light {
  position: absolute;
  z-index: 7;
  top: 14%;
  left: 50%;
  width: 18%;
  height: 14%;
  transform: translateX(-50%);
  border-radius: 50%;
  background:
    radial-gradient(
      ellipse,
      rgba(240,226,210,0.15),
      rgba(240,226,210,0.035) 48%,
      transparent 70%
    );
  filter: blur(5px);
}

.eyes {
  position: absolute;
  z-index: 9;
  top: 20%;
  left: 50%;
  width: 16%;
  height: 3%;
  transform: translateX(-50%);
  display: flex;
  justify-content: space-between;
}

.eye {
  width: 27%;
  height: 100%;
  border-radius: 50%;
  background: rgba(229,220,206,0.24);
  box-shadow: 0 0 9px rgba(224,208,178,0.12);
  animation: blink 6s infinite;
}

.eye:last-child {
  animation-delay: 120ms;
}

@keyframes blink {
  0%, 45%, 48%, 100% {
    transform: scaleY(1);
  }
  46%, 47% {
    transform: scaleY(0.08);
  }
}

.neck {
  position: absolute;
  z-index: 3;
  top: 27%;
  left: 50%;
  width: 10%;
  height: 9%;
  transform: translateX(-50%);
  background: linear-gradient(90deg, #191817, #383330, #151413);
}

.torso {
  position: absolute;
  z-index: 2;
  left: 50%;
  top: 31%;
  width: 43%;
  height: 48%;
  transform: translateX(-50%);
  clip-path: polygon(10% 0, 90% 0, 100% 100%, 0 100%);
  background:
    linear-gradient(
      105deg,
      #111111 0%,
      #292623 28%,
      #151515 50%,
      #24211f 73%,
      #0b0b0b 100%
    );
  box-shadow:
    inset 25px 0 40px rgba(255,255,255,0.015),
    inset -30px 0 35px rgba(0,0,0,0.38);
}

.blazer-left,
.blazer-right {
  position: absolute;
  z-index: 4;
  top: 31%;
  width: 23%;
  height: 47%;
  background: linear-gradient(105deg, #0a0a0a, #252321, #101010);
}

.blazer-left {
  left: 28%;
  clip-path: polygon(0 0, 100% 7%, 75% 100%, 0 90%);
  transform: rotate(2deg);
}

.blazer-right {
  right: 28%;
  clip-path: polygon(0 7%, 100% 0, 100% 90%, 25% 100%);
  transform: rotate(-2deg);
}

.blazer-neck {
  position: absolute;
  z-index: 6;
  top: 31%;
  left: 50%;
  width: 18%;
  height: 22%;
  transform: translateX(-50%);
  clip-path: polygon(0 0, 100% 0, 58% 100%, 42% 100%);
  background: linear-gradient(90deg, #111, #312d29, #101010);
}

.blazer-seam {
  position: absolute;
  z-index: 8;
  top: 39%;
  left: 50%;
  width: 1px;
  height: 34%;
  transform: translateX(-50%);
  background: linear-gradient(
    180deg,
    rgba(213,185,135,0.11),
    rgba(255,255,255,0.025),
    transparent
  );
}

.arm {
  position: absolute;
  z-index: 1;
  top: 34%;
  width: 13%;
  height: 44%;
  border-radius: 30px;
  background: linear-gradient(105deg, #0d0d0d, #292725 52%, #111);
}

.arm-left {
  left: 18%;
  transform: rotate(7deg);
}

.arm-right {
  right: 18%;
  transform: rotate(-7deg);
}

.hand {
  position: absolute;
  z-index: 7;
  top: 73%;
  width: 11%;
  height: 11%;
  border-radius: 48%;
  background: radial-gradient(circle at 35% 30%, #514a44, #201e1c 66%, #0c0c0c);
}

.hand-left {
  left: 17%;
  transform: rotate(9deg);
}

.hand-right {
  right: 17%;
  transform: rotate(-9deg);
}

.presence-copy {
  position: absolute;
  z-index: 20;
  left: 42px;
  bottom: 38px;
  pointer-events: none;
}

.presence-name {
  font-size: 11px;
  letter-spacing: 0.42em;
  color: rgba(235,226,210,0.82);
}

.presence-status {
  margin-top: 9px;
  color: rgba(235,226,210,0.3);
  font-size: 8px;
  letter-spacing: 0.26em;
  text-transform: uppercase;
}

.voice-control {
  position: absolute;
  z-index: 30;
  left: 50%;
  bottom: 34px;
  width: 68px;
  height: 68px;
  transform: translateX(-50%);
  border: 1px solid rgba(218,198,165,0.25);
  border-radius: 50%;
  background:
    radial-gradient(circle at 38% 32%, rgba(255,255,255,0.08), transparent 50%),
    rgba(10,10,9,0.72);
  color: rgba(238,231,218,0.8);
  cursor: pointer;
  box-shadow:
    0 18px 50px rgba(0,0,0,0.42),
    0 0 30px rgba(198,166,105,0.035);
  transition:
    transform 220ms ease,
    border-color 220ms ease,
    background 220ms ease;
}

.voice-control:hover {
  transform: translateX(-50%) scale(1.035);
  border-color: rgba(218,198,165,0.48);
}

.voice-control.active {
  border-color: rgba(198,166,105,0.7);
  box-shadow:
    0 0 0 7px rgba(198,166,105,0.045),
    0 18px 50px rgba(0,0,0,0.42);
}

.mic {
  position: relative;
  display: block;
  width: 13px;
  height: 24px;
  margin: 0 auto;
  border: 1px solid currentColor;
  border-radius: 8px;
}

.mic::before {
  content: "";
  position: absolute;
  left: 50%;
  bottom: -9px;
  width: 20px;
  height: 13px;
  transform: translateX(-50%);
  border: 1px solid currentColor;
  border-top: 0;
  border-radius: 0 0 12px 12px;
}

.mic::after {
  content: "";
  position: absolute;
  left: 50%;
  bottom: -14px;
  width: 1px;
  height: 6px;
  transform: translateX(-50%);
  background: currentColor;
}

.secondary-trigger {
  position: absolute;
  z-index: 30;
  left: calc(50% + 48px);
  bottom: 45px;
  width: 44px;
  height: 44px;
  border: 1px solid rgba(255,255,255,0.07);
  border-radius: 50%;
  background: rgba(12,12,11,0.7);
  color: rgba(238,231,218,0.38);
  cursor: pointer;
  transition: 180ms ease;
}

.secondary-trigger:hover {
  color: rgba(238,231,218,0.75);
  border-color: rgba(255,255,255,0.16);
}

.command-drawer {
  position: absolute;
  z-index: 40;
  left: 50%;
  bottom: 96px;
  width: min(520px, calc(100% - 44px));
  transform: translate(-50%, 16px);
  opacity: 0;
  pointer-events: none;
  padding: 14px;
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px;
  background: rgba(9,10,10,0.94);
  backdrop-filter: blur(22px);
  box-shadow: 0 24px 80px rgba(0,0,0,0.48);
  transition: 220ms ease;
}

.command-drawer.open {
  transform: translate(-50%, 0);
  opacity: 1;
  pointer-events: auto;
}

.command-row {
  display: flex;
  gap: 9px;
}

.command-input {
  flex: 1;
  min-width: 0;
  height: 48px;
  padding: 0 16px;
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 10px;
  outline: none;
  background: rgba(255,255,255,0.025);
  color: #eee9df;
}

.command-input:focus {
  border-color: rgba(203,174,124,0.34);
}

.command-send {
  width: 48px;
  border-radius: 10px;
  background: rgba(205,174,119,0.13);
  color: #e8ddca;
  cursor: pointer;
}

.command-hints {
  display: flex;
  gap: 8px;
  margin-top: 10px;
  overflow-x: auto;
  scrollbar-width: none;
}

.command-hint {
  flex: 0 0 auto;
  padding: 7px 10px;
  border: 1px solid rgba(255,255,255,0.055);
  border-radius: 999px;
  background: transparent;
  color: rgba(238,231,218,0.42);
  font-size: 9px;
  cursor: pointer;
}

.workspace {
  position: relative;
  min-width: 0;
  min-height: 100%;
  padding: 42px 42px 42px 12px;
  display: flex;
  align-items: center;
  opacity: 0;
  transform: translateX(35px);
  pointer-events: none;
  transition:
    opacity 450ms ease,
    transform 700ms cubic-bezier(.22,.75,.18,1);
}

.stage.has-workspace .workspace {
  opacity: 1;
  transform: translateX(0);
  pointer-events: auto;
}

.workspace-panel {
  width: 100%;
  max-height: calc(100vh - 176px);
  overflow: auto;
  padding: 28px;
  border-left: 1px solid rgba(255,255,255,0.07);
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.1) transparent;
}

.workspace-kicker {
  color: rgba(208,184,143,0.68);
  font-size: 8px;
  letter-spacing: 0.28em;
  text-transform: uppercase;
}

.workspace-title {
  margin: 12px 0 8px;
  font-family: Georgia, "Times New Roman", serif;
  font-size: clamp(30px, 3.2vw, 48px);
  font-weight: 400;
  letter-spacing: -0.035em;
  color: #eae4da;
}

.workspace-description {
  max-width: 560px;
  margin: 0;
  color: rgba(235,229,219,0.43);
  font-size: 12px;
  line-height: 1.8;
}

.workspace-line {
  width: 100%;
  height: 1px;
  margin: 28px 0;
  background: rgba(255,255,255,0.065);
}

.data-block {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.data-cell {
  padding: 17px;
  border: 1px solid rgba(255,255,255,0.065);
  background: rgba(255,255,255,0.018);
}

.data-label {
  color: rgba(235,229,219,0.32);
  font-size: 8px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.data-value {
  margin-top: 9px;
  color: rgba(240,234,224,0.82);
  font-family: Georgia, "Times New Roman", serif;
  font-size: 24px;
}

.message-list {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.message {
  max-width: 85%;
  padding: 12px 15px;
  border-radius: 12px;
  font-size: 11px;
  line-height: 1.65;
}

.message.jurix {
  align-self: flex-start;
  border: 1px solid rgba(255,255,255,0.055);
  background: rgba(255,255,255,0.018);
  color: rgba(235,229,219,0.62);
}

.message.user {
  align-self: flex-end;
  background: rgba(198,166,105,0.1);
  color: rgba(239,231,216,0.72);
}

.workspace-close {
  position: absolute;
  top: 18px;
  right: 24px;
  color: rgba(235,229,219,0.35);
  background: transparent;
  cursor: pointer;
  font-size: 18px;
}

.footer-nav {
  position: absolute;
  z-index: 20;
  right: 42px;
  bottom: 40px;
  display: flex;
  gap: 28px;
}

.footer-nav button {
  padding: 0;
  background: transparent;
  color: rgba(235,229,219,0.26);
  font-size: 8px;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  cursor: pointer;
  transition: color 180ms ease;
}

.footer-nav button:hover {
  color: rgba(235,229,219,0.7);
}

.security-event {
  position: absolute;
  z-index: 50;
  top: 110px;
  left: 50%;
  transform: translateX(-50%);
  padding: 9px 14px;
  border: 1px solid rgba(190,161,112,0.17);
  background: rgba(30,25,18,0.68);
  backdrop-filter: blur(15px);
  color: rgba(228,211,184,0.66);
  font-size: 8px;
  letter-spacing: 0.17em;
  text-transform: uppercase;
}

@media (max-width: 900px) {
  body {
    overflow: auto;
  }

  .topbar {
    padding: 0 22px;
  }

  .brand-subtitle {
    display: none;
  }

  .stage,
  .stage.has-workspace {
    position: relative;
    inset: 92px 0 auto;
    min-height: calc(100vh - 92px);
    display: block;
  }

  .presence-zone {
    min-height: calc(100vh - 92px);
  }

  .stage.has-workspace .presence-zone {
    transform: translateY(-4%);
  }

  .workspace {
    position: absolute;
    inset: 0;
    padding: 30px 20px;
    background: rgba(5,6,6,0.94);
    backdrop-filter: blur(18px);
  }

  .workspace-panel {
    max-height: calc(100vh - 145px);
    border-left: 0;
    padding: 24px 10px;
  }

  .footer-nav {
    display: none;
  }

  .presence-copy {
    left: 22px;
    bottom: 28px;
  }

  .jurix {
    width: min(390px, 72vw);
  }
}

@media (max-width: 560px) {
  .topbar {
    height: 76px;
  }

  .stage,
  .stage.has-workspace {
    inset: 76px 0 0;
    min-height: calc(100vh - 76px);
  }

  .system-state {
    font-size: 7px;
  }

  .jurix {
    width: 86vw;
    height: 68vh;
  }

  .voice-control {
    bottom: 24px;
  }

  .secondary-trigger {
    bottom: 35px;
  }

  .data-block {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
    transition-duration: 0.001ms !important;
  }
}
`;

function App() {
  const [presence, setPresence] = useState<PresenceMode>("idle");
  const [workspace, setWorkspace] = useState<WorkspaceMode>("none");
  const [commandOpen, setCommandOpen] = useState(false);
  const [command, setCommand] = useState("");
  const [messages, setMessages] = useState<Message[]>(INITIAL_MESSAGES);
  const [securityEvent, setSecurityEvent] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);

  const workspaceCopy = useMemo(() => {
    switch (workspace) {
      case "financial":
        return {
          kicker: "Financial intelligence",
          title: "Your financial picture",
          description:
            "A contextual workspace appears only when financial information needs to be examined.",
          values: [
            ["Net position", "₹ —"],
            ["Income", "₹ —"],
            ["Committed", "₹ —"],
            ["Available", "₹ —"],
          ],
        };
      case "legal":
        return {
          kicker: "Legal intelligence",
          title: "Evidence workspace",
          description:
            "Relevant evidence, sources and legal reasoning will appear here without turning the main experience into a dashboard.",
          values: [
            ["Jurisdiction", "—"],
            ["Evidence", "—"],
            ["Sources", "—"],
            ["Confidence", "—"],
          ],
        };
      case "security":
        return {
          kicker: "Security intelligence",
          title: "System security",
          description:
            "Security information is presented contextually when the system needs your attention.",
          values: [
            ["Identity", "Verified"],
            ["Session", "Active"],
            ["Authority", "Protected"],
            ["Risk", "Normal"],
          ],
        };
      default:
        return null;
    }
  }, [workspace]);

  useEffect(() => {
    if (commandOpen) {
      window.setTimeout(() => inputRef.current?.focus(), 80);
    }
  }, [commandOpen]);

  useEffect(() => {
    if (presence === "idle") return;

    const timer = window.setTimeout(() => {
      setPresence("idle");
    }, presence === "listening" ? 1200 : 1700);

    return () => window.clearTimeout(timer);
  }, [presence]);

  const startListening = () => {
    setPresence("listening");
    setCommandOpen(false);
  };

  const submitCommand = () => {
    const text = command.trim();

    if (!text) return;

    const nextId = messages.length + 1;

    setMessages((current) => [
      ...current,
      {
        id: nextId,
        role: "user",
        text,
      },
    ]);

    setCommand("");
    setPresence("thinking");

    window.setTimeout(() => {
      setMessages((current) => [
        ...current,
        {
          id: nextId + 1,
          role: "jurix",
          text:
            "I’ve received that request. The intelligence layer is ready; live financial, legal, or external data will be introduced only when the request requires it.",
        },
      ]);
      setPresence("speaking");
    }, 700);
  };

  const openWorkspace = (mode: WorkspaceMode) => {
    setWorkspace((current) => (current === mode ? "none" : mode));
    setSecurityEvent(mode === "security");

    if (mode === "security") {
      window.setTimeout(() => setSecurityEvent(false), 2600);
    }
  };

  return (
    <>
      <style>{styles}</style>

      <main className="app">
        <div className="shell">
          <header className="topbar">
            <div className="brand">
              <span className="brand-mark" aria-hidden="true" />
              <span className="brand-name">OVELA</span>
              <span className="brand-subtitle">Private intelligence</span>
            </div>

            <div className="system-state">
              <span className="state-dot" />
              {presence === "listening"
                ? "Listening"
                : presence === "thinking"
                  ? "Thinking"
                  : presence === "speaking"
                    ? "Speaking"
                    : "Ready"}
            </div>
          </header>

          {securityEvent && (
            <div className="security-event">
              Security context active · authority remains protected
            </div>
          )}

          <section className={`stage ${workspace !== "none" ? "has-workspace" : ""}`}>
            <section className="presence-zone">
              <div className="atmosphere" />
              <div className="atmosphere-ring" />

              <div className="jurix" aria-label="JURIX presence">
                <div className="jurix-shadow" />
                <div className="jurix-halo" />

                <div className="hair" />
                <div className="jurix-head" />
                <div className="face-light" />

                <div className="eyes">
                  <span className="eye" />
                  <span className="eye" />
                </div>

                <div className="neck" />
                <div className="torso" />
                <div className="blazer-left" />
                <div className="blazer-right" />
                <div className="blazer-neck" />
                <div className="blazer-seam" />

                <div className="arm arm-left" />
                <div className="arm arm-right" />

                <div className="hand hand-left" />
                <div className="hand hand-right" />
              </div>

              <div className="presence-copy">
                <div className="presence-name">JURIX</div>
                <div className="presence-status">
                  {presence === "listening"
                    ? "Listening"
                    : presence === "thinking"
                      ? "Considering"
                      : presence === "speaking"
                        ? "Speaking"
                        : "Present"}
                </div>
              </div>

              <button
                className={`voice-control ${presence === "listening" ? "active" : ""}`}
                type="button"
                aria-label="Talk to JURIX"
                onClick={startListening}
              >
                <span className="mic" />
              </button>

              <button
                className="secondary-trigger"
                type="button"
                aria-label="Open text interaction"
                aria-expanded={commandOpen}
                onClick={() => setCommandOpen((open) => !open)}
              >
                ···
              </button>

              <div className={`command-drawer ${commandOpen ? "open" : ""}`}>
                <div className="command-row">
                  <input
                    ref={inputRef}
                    className="command-input"
                    value={command}
                    onChange={(event) => setCommand(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        submitCommand();
                      }

                      if (event.key === "Escape") {
                        setCommandOpen(false);
                      }
                    }}
                    placeholder="Ask JURIX privately..."
                    aria-label="Message JURIX"
                  />

                  <button
                    className="command-send"
                    type="button"
                    onClick={submitCommand}
                    aria-label="Send message"
                  >
                    →
                  </button>
                </div>

                <div className="command-hints">
                  <button
                    className="command-hint"
                    type="button"
                    onClick={() => {
                      setCommand("Show my financial position");
                      inputRef.current?.focus();
                    }}
                  >
                    Financial position
                  </button>

                  <button
                    className="command-hint"
                    type="button"
                    onClick={() => {
                      setCommand("Review this legal matter");
                      inputRef.current?.focus();
                    }}
                  >
                    Legal review
                  </button>

                  <button
                    className="command-hint"
                    type="button"
                    onClick={() => {
                      setCommand("Check system security");
                      inputRef.current?.focus();
                    }}
                  >
                    Security
                  </button>
                </div>
              </div>
            </section>

            <aside className="workspace">
              {workspaceCopy && (
                <div className="workspace-panel">
                  <button
                    className="workspace-close"
                    type="button"
                    aria-label="Close workspace"
                    onClick={() => setWorkspace("none")}
                  >
                    ×
                  </button>

                  <div className="workspace-kicker">
                    {workspaceCopy.kicker}
                  </div>

                  <h1 className="workspace-title">{workspaceCopy.title}</h1>

                  <p className="workspace-description">
                    {workspaceCopy.description}
                  </p>

                  <div className="workspace-line" />

                  <div className="data-block">
                    {workspaceCopy.values.map(([label, value]) => (
                      <div className="data-cell" key={label}>
                        <div className="data-label">{label}</div>
                        <div className="data-value">{value}</div>
                      </div>
                    ))}
                  </div>

                  <div className="workspace-line" />

                  <div className="message-list">
                    {messages.slice(-4).map((message) => (
                      <div
                        className={`message ${message.role}`}
                        key={message.id}
                      >
                        {message.text}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </aside>
          </section>

          <nav className="footer-nav" aria-label="Contextual workspaces">
            <button
              type="button"
              onClick={() => openWorkspace("financial")}
            >
              Finance
            </button>

            <button
              type="button"
              onClick={() => openWorkspace("legal")}
            >
              Legal
            </button>

            <button
              type="button"
              onClick={() => openWorkspace("security")}
            >
              Security
            </button>
          </nav>
        </div>
      </main>
    </>
  );
}

export default App;