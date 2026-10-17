import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { FBXLoader } from "three/examples/jsm/loaders/FBXLoader.js";

export type JurixAvatarMode = "idle" | "greeting" | "listening" | "speaking";

export interface HoloPresentationData {
  primaryMetric?: string;
  metricLabel?: string;
  targetDelta?: string;
  monthlySavings?: string;
  monthlyBurn?: string;
  chartPoints?: { label: string; value: number; display: string }[];
  allocations?: { category: string; pct: number; amount: string; color: string }[];
}

interface JurixWebRTCStageProps {
  mode: JurixAvatarMode;
  presentationTrigger?: number;
  presentationActive?: boolean;
  presentationData?: HoloPresentationData;
}

const DEFAULT_PRESENTATION_DATA: HoloPresentationData = {
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
};

export const JurixWebRTCStage: React.FC<JurixWebRTCStageProps> = ({
  mode,
  presentationTrigger = 0,
  presentationActive = false,
  presentationData = DEFAULT_PRESENTATION_DATA,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const modeRef = useRef<JurixAvatarMode>(mode);
  const playModeRef = useRef<(name: JurixAvatarMode) => void>(() => {});
  const playPresentationRef = useRef<() => void>(() => {});
  const presentationActiveRef = useRef(false);
  const presentationHandRef = useRef<THREE.Object3D | null>(null);
  const holoProjectorRef = useRef<THREE.Group | null>(null);
  const currentDataRef = useRef<HoloPresentationData>(presentationData);
  const updateCanvasesRef = useRef<() => void>(() => {});

  useEffect(() => {
    currentDataRef.current = presentationData || DEFAULT_PRESENTATION_DATA;
    updateCanvasesRef.current();
  }, [presentationData]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let disposed = false;
    let animId = 0;
    let mixer: THREE.AnimationMixer | null = null;
    let activeAction: THREE.AnimationAction | null = null;

    const actions: Record<string, THREE.AnimationAction> = {};
    const clock = new THREE.Clock();

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, width / height, 0.1, 1000);
    camera.position.set(0, 1.0, 3.6);
    camera.lookAt(0, 0.8, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2.0));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.08;
    renderer.outputColorSpace = THREE.SRGBColorSpace;

    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    scene.add(new THREE.HemisphereLight(0xfff1df, 0x383744, 1.15));

    const keyLight = new THREE.DirectionalLight(0xffe2c4, 2.4);
    keyLight.position.set(1.5, 3.5, 3);
    scene.add(keyLight);

    const faceFillLight = new THREE.DirectionalLight(0xc4dcff, 0.55);
    faceFillLight.position.set(-2.5, 2.2, 3.5);
    scene.add(faceFillLight);

    const rimLight = new THREE.DirectionalLight(0x9ac8ff, 1.05);
    rimLight.position.set(-2.5, 2, -2);
    scene.add(rimLight);

    scene.background = null;

    const maxAniso = renderer.capabilities.getMaxAnisotropy();

    // High Density Canvas Textures (2048 x 1280 for sharp text rendering)
    const createCanvasTexture = (w: number, h: number) => {
      const cvs = document.createElement("canvas");
      cvs.width = w;
      cvs.height = h;
      const ctx = cvs.getContext("2d")!;
      const tex = new THREE.CanvasTexture(cvs);
      tex.colorSpace = THREE.SRGBColorSpace;
      tex.generateMipmaps = true;
      tex.minFilter = THREE.LinearMipmapLinearFilter;
      tex.magFilter = THREE.LinearFilter;
      tex.anisotropy = maxAniso;
      return { cvs, ctx, tex };
    };

    const display1Canvas = createCanvasTexture(2048, 1280);
    const display2Canvas = createCanvasTexture(2048, 1280);

    // ========================================================
    // SCREEN 1: CRISP, SHARP VECTOR TRAJECTORY
    // ========================================================
    const drawDisplay1 = () => {
      const { ctx, cvs } = display1Canvas;
      const d = currentDataRef.current || DEFAULT_PRESENTATION_DATA;
      const w = cvs.width;
      const h = cvs.height;
      ctx.clearRect(0, 0, w, h);

      // Gradient background
      const bg = ctx.createLinearGradient(0, 0, 0, h);
      bg.addColorStop(0, "rgba(4, 16, 36, 0.94)");
      bg.addColorStop(1, "rgba(1, 7, 18, 0.98)");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      // Fine precision outer border with inner margin
      ctx.strokeStyle = "rgba(56, 189, 248, 0.45)";
      ctx.lineWidth = 3;
      ctx.strokeRect(40, 40, w - 80, h - 80);

      // Sharp tech corners
      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 8;
      ctx.beginPath();
      ctx.moveTo(40, 130); ctx.lineTo(40, 40); ctx.lineTo(130, 40);
      ctx.moveTo(w - 130, 40); ctx.lineTo(w - 40, 40); ctx.lineTo(w - 40, 130);
      ctx.moveTo(40, h - 130); ctx.lineTo(40, h - 40); ctx.lineTo(130, h - 40);
      ctx.moveTo(w - 130, h - 40); ctx.lineTo(w - 40, h - 40); ctx.lineTo(w - 40, h - 130);
      ctx.stroke();

      // Top Tag (Crisp medium weight with letter spacing)
      ctx.fillStyle = "#38bdf8";
      ctx.font = "600 42px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText(d.metricLabel || "TOTAL PORTFOLIO NET WORTH", 100, 125);

      // Primary Metric (Prominent header number)
      ctx.fillStyle = "#ffffff";
      ctx.font = "800 135px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText(d.primaryMetric || "₹ 1.48 Cr", 100, 260);

      // YoY Delta Pill (Inside the inner frame boundary with safe padding)
      const badgeW = 340;
      const badgeH = 88;
      const badgeX = w - badgeW - 120; // 120px safe margin from right border
      const badgeY = 160;

      ctx.fillStyle = "rgba(34, 197, 94, 0.18)";
      ctx.fillRect(badgeX, badgeY, badgeW, badgeH);
      ctx.strokeStyle = "#22c55e";
      ctx.lineWidth = 2.5;
      ctx.strokeRect(badgeX, badgeY, badgeW, badgeH);

      ctx.fillStyle = "#4ade80";
      ctx.font = "700 42px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(`▲ ${d.targetDelta || "+16.8% YoY"}`, badgeX + badgeW / 2, badgeY + 58);
      ctx.textAlign = "left";

      // Sub-label (Crisp regular weight)
      ctx.fillStyle = "#94a3b8";
      ctx.font = "500 36px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText("GROWTH TRAJECTORY (FY 2025-26)", 100, 345);

      // Graph Coordinates
      const plotLeft = 140;
      const plotRight = w - 140;
      const plotTop = 460;
      const plotBottom = 1040;
      const plotHeight = plotBottom - plotTop;
      const plotWidth = plotRight - plotLeft;

      // Fine gridlines
      ctx.strokeStyle = "rgba(56, 189, 248, 0.12)";
      ctx.lineWidth = 1.5;
      for (let i = 0; i <= 3; i++) {
        const y = plotTop + (plotHeight / 3) * i;
        ctx.beginPath();
        ctx.moveTo(plotLeft, y);
        ctx.lineTo(plotRight, y);
        ctx.stroke();
      }

      const points = d.chartPoints && d.chartPoints.length > 0 ? d.chartPoints : DEFAULT_PRESENTATION_DATA.chartPoints!;
      const coords: { x: number; y: number; label: string; display: string }[] = [];

      points.forEach((pt, idx) => {
        const x = plotLeft + (plotWidth / (points.length - 1)) * idx;
        const y = plotBottom - pt.value * (plotHeight * 0.85);
        coords.push({ x, y, label: pt.label, display: pt.display });
      });

      // Area gradient fill
      const areaGrad = ctx.createLinearGradient(0, plotTop, 0, plotBottom);
      areaGrad.addColorStop(0, "rgba(56, 189, 248, 0.40)");
      areaGrad.addColorStop(1, "rgba(56, 189, 248, 0.02)");
      ctx.fillStyle = areaGrad;

      ctx.beginPath();
      ctx.moveTo(coords[0].x, plotBottom);
      ctx.lineTo(coords[0].x, coords[0].y);
      for (let i = 0; i < coords.length - 1; i++) {
        const xc = (coords[i].x + coords[i + 1].x) / 2;
        const yc = (coords[i].y + coords[i + 1].y) / 2;
        ctx.quadraticCurveTo(coords[i].x, coords[i].y, xc, yc);
      }
      ctx.lineTo(coords[coords.length - 1].x, coords[coords.length - 1].y);
      ctx.lineTo(coords[coords.length - 1].x, plotBottom);
      ctx.closePath();
      ctx.fill();

      // Sharp line curve
      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 5;
      ctx.beginPath();
      ctx.moveTo(coords[0].x, coords[0].y);
      for (let i = 0; i < coords.length - 1; i++) {
        const xc = (coords[i].x + coords[i + 1].x) / 2;
        const yc = (coords[i].y + coords[i + 1].y) / 2;
        ctx.quadraticCurveTo(coords[i].x, coords[i].y, xc, yc);
      }
      ctx.lineTo(coords[coords.length - 1].x, coords[coords.length - 1].y);
      ctx.stroke();

      // Precision data nodes
      coords.forEach((c) => {
        ctx.fillStyle = "#020b18";
        ctx.beginPath();
        ctx.arc(c.x, c.y, 18, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = "#38bdf8";
        ctx.lineWidth = 4;
        ctx.stroke();

        ctx.fillStyle = "#ffffff";
        ctx.beginPath();
        ctx.arc(c.x, c.y, 7, 0, Math.PI * 2);
        ctx.fill();

        // Node amount label
        ctx.fillStyle = "#ffffff";
        ctx.font = "600 46px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(c.display, c.x, c.y - 34);

        // Month Axis Label
        ctx.fillStyle = "#94a3b8";
        ctx.font = "500 40px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
        ctx.fillText(c.label, c.x, plotBottom + 64);
      });
      ctx.textAlign = "left";

      ctx.strokeStyle = "rgba(56, 189, 248, 0.4)";
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo(plotLeft, plotBottom);
      ctx.lineTo(plotRight, plotBottom);
      ctx.stroke();

      display1Canvas.tex.needsUpdate = true;
    };

    // ========================================================
    // SCREEN 2: CRISP ASSET ALLOCATION & CASHFLOW METRICS
    // ========================================================
    const drawDisplay2 = () => {
      const { ctx, cvs } = display2Canvas;
      const d = currentDataRef.current || DEFAULT_PRESENTATION_DATA;
      const w = cvs.width;
      const h = cvs.height;
      ctx.clearRect(0, 0, w, h);

      const bg = ctx.createLinearGradient(0, 0, 0, h);
      bg.addColorStop(0, "rgba(6, 14, 32, 0.94)");
      bg.addColorStop(1, "rgba(2, 6, 16, 0.98)");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      ctx.strokeStyle = "rgba(56, 189, 248, 0.45)";
      ctx.lineWidth = 3;
      ctx.strokeRect(40, 40, w - 80, h - 80);

      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 8;
      ctx.beginPath();
      ctx.moveTo(40, 130); ctx.lineTo(40, 40); ctx.lineTo(130, 40);
      ctx.moveTo(w - 130, 40); ctx.lineTo(w - 40, 40); ctx.lineTo(w - 40, 130);
      ctx.moveTo(40, h - 130); ctx.lineTo(40, h - 40); ctx.lineTo(130, h - 40);
      ctx.moveTo(w - 130, h - 40); ctx.lineTo(w - 40, h - 40); ctx.lineTo(w - 40, h - 130);
      ctx.stroke();

      // Top Tag
      ctx.fillStyle = "#38bdf8";
      ctx.font = "600 42px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText("ASSET ALLOCATION & CASHFLOW", 100, 125);

      // Top 2 KPI Telemetry Cards (Sharp numbers, clean labels)
      ctx.fillStyle = "rgba(15, 23, 42, 0.85)";
      ctx.fillRect(100, 175, 870, 185);
      ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
      ctx.lineWidth = 2.5;
      ctx.strokeRect(100, 175, 870, 185);

      ctx.fillStyle = "#94a3b8";
      ctx.font = "500 34px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText("ESTIMATED MONTHLY SAVINGS", 135, 230);

      ctx.fillStyle = "#38bdf8";
      ctx.font = "800 90px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText(d.monthlySavings || "₹ 1.85 L", 135, 325);

      ctx.fillStyle = "rgba(15, 23, 42, 0.85)";
      ctx.fillRect(1020, 175, 928, 185);
      ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
      ctx.lineWidth = 2.5;
      ctx.strokeRect(1020, 175, 928, 185);

      ctx.fillStyle = "#94a3b8";
      ctx.font = "500 34px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText("AVG. MONTHLY EXPENSE", 1055, 230);

      ctx.fillStyle = "#f43f5e";
      ctx.font = "800 90px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText(d.monthlyBurn || "₹ 65,000", 1055, 325);

      // Donut Graph
      const donutX = 420;
      const donutY = 740;
      const outerR = 250;
      const innerR = 160;

      const allocs = d.allocations && d.allocations.length > 0 ? d.allocations : DEFAULT_PRESENTATION_DATA.allocations!;
      let startAngle = -Math.PI / 2;

      allocs.forEach((item) => {
        const sliceAngle = item.pct * Math.PI * 2;
        const endAngle = startAngle + sliceAngle;

        ctx.beginPath();
        ctx.arc(donutX, donutY, outerR, startAngle, endAngle, false);
        ctx.arc(donutX, donutY, innerR, endAngle, startAngle, true);
        ctx.closePath();

        ctx.fillStyle = item.color;
        ctx.fill();

        ctx.strokeStyle = "#050c1c";
        ctx.lineWidth = 5;
        ctx.stroke();

        startAngle = endAngle;
      });

      // Donut Center Hub
      ctx.fillStyle = "#ffffff";
      ctx.font = "800 68px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("100%", donutX, donutY + 16);
      ctx.fillStyle = "#94a3b8";
      ctx.font = "500 28px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
      ctx.fillText("PORTFOLIO", donutX, donutY + 58);
      ctx.textAlign = "left";

      // Sharp Legend (500 weight text, 700 numbers)
      const legendLeft = 780;
      const legendTop = 450;
      const rowGap = 150;

      allocs.forEach((item, idx) => {
        const y = legendTop + idx * rowGap;

        // Color indicator pill
        ctx.fillStyle = item.color;
        ctx.fillRect(legendLeft, y, 20, 56);

        // Crisp readable category label
        ctx.fillStyle = "#e2e8f0";
        ctx.font = "500 44px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
        ctx.fillText(item.category, legendLeft + 36, y + 42);

        // Clear prominent numbers
        ctx.fillStyle = item.color;
        ctx.font = "700 48px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
        ctx.textAlign = "right";
        ctx.fillText(`${item.amount} (${Math.round(item.pct * 100)}%)`, w - 100, y + 42);
        ctx.textAlign = "left";

        // Thin progress track
        ctx.fillStyle = "rgba(30, 41, 59, 0.85)";
        ctx.fillRect(legendLeft + 36, y + 62, w - legendLeft - 136, 8);
        ctx.fillStyle = item.color;
        ctx.fillRect(legendLeft + 36, y + 62, (w - legendLeft - 136) * item.pct, 8);
      });

      display2Canvas.tex.needsUpdate = true;
    };

    updateCanvasesRef.current = () => {
      drawDisplay1();
      drawDisplay2();
    };
    updateCanvasesRef.current();

    // 3D Emitter Base
    const projectorGroup = new THREE.Group();
    projectorGroup.name = "JurixFloorHoloProjector";
    projectorGroup.position.set(-0.95, -0.34, -0.55);
    projectorGroup.visible = false;
    scene.add(projectorGroup);
    holoProjectorRef.current = projectorGroup;

    const groundDisc = new THREE.Mesh(
      new THREE.CircleGeometry(0.72, 36),
      new THREE.MeshBasicMaterial({
        color: 0x0284c7,
        transparent: true,
        opacity: 0.28,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      })
    );
    groundDisc.rotation.x = -Math.PI / 2;
    groundDisc.position.y = 0.001;
    projectorGroup.add(groundDisc);

    const baseMetal = new THREE.MeshStandardMaterial({ color: 0x070c16, metalness: 0.96, roughness: 0.16 });
    const chamferMat = new THREE.MeshStandardMaterial({ color: 0x1a2638, metalness: 0.88, roughness: 0.28 });

    const mainChassis = new THREE.Mesh(new THREE.CylinderGeometry(0.38, 0.44, 0.030, 8), baseMetal);
    mainChassis.position.y = 0.015;
    projectorGroup.add(mainChassis);

    const upperDeck = new THREE.Mesh(new THREE.CylinderGeometry(0.30, 0.34, 0.025, 16), chamferMat);
    upperDeck.position.y = 0.035;
    projectorGroup.add(upperDeck);

    for (let i = 0; i < 8; i++) {
      const angle = (i / 8) * Math.PI * 2;
      const fin = new THREE.Mesh(
        new THREE.BoxGeometry(0.045, 0.020, 0.012),
        new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.9, roughness: 0.2 })
      );
      fin.position.set(Math.cos(angle) * 0.32, 0.035, Math.sin(angle) * 0.32);
      fin.rotation.y = -angle;
      projectorGroup.add(fin);
    }

    const shutterRing = new THREE.Mesh(
      new THREE.RingGeometry(0.20, 0.24, 36),
      new THREE.MeshBasicMaterial({ color: 0x38bdf8, side: THREE.DoubleSide })
    );
    shutterRing.rotation.x = -Math.PI / 2;
    shutterRing.position.y = 0.048;
    projectorGroup.add(shutterRing);

    const opticalLens = new THREE.Mesh(
      new THREE.CylinderGeometry(0.15, 0.18, 0.015, 32),
      new THREE.MeshBasicMaterial({ color: 0xe0f7ff, transparent: true, opacity: 0.95 })
    );
    opticalLens.position.y = 0.054;
    projectorGroup.add(opticalLens);

    const plinthLight = new THREE.PointLight(0x38bdf8, 2.2, 3.8);
    plinthLight.position.y = 0.22;
    projectorGroup.add(plinthLight);

    const beamVertexShader = `
      varying vec2 vUv;
      void main() {
        vUv = uv;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `;
    const beamFragmentShader = `
      varying vec2 vUv;
      uniform vec3 color;
      void main() {
        float verticalFade = pow(1.0 - vUv.y, 2.2);
        float alpha = verticalFade * 0.20;
        gl_FragColor = vec4(color, alpha);
      }
    `;

    const gradientBeam = new THREE.Mesh(
      new THREE.CylinderGeometry(1.35, 0.18, 1.30, 36, 1, true),
      new THREE.ShaderMaterial({
        vertexShader: beamVertexShader,
        fragmentShader: beamFragmentShader,
        uniforms: { color: { value: new THREE.Color(0x38bdf8) } },
        transparent: true,
        blending: THREE.AdditiveBlending,
        side: THREE.DoubleSide,
        depthWrite: false,
      })
    );
    gradientBeam.position.y = 0.68;
    projectorGroup.add(gradientBeam);

    // Floating Panes
    const holoArray = new THREE.Group();
    holoArray.name = "FloatingHoloPanels";
    holoArray.position.set(0, 1.34, 0.02);
    projectorGroup.add(holoArray);

    const makePane = (map: THREE.CanvasTexture, w: number, h: number) => {
      const mat = new THREE.MeshBasicMaterial({
        map,
        transparent: true,
        opacity: 0.99,
        side: THREE.DoubleSide,
        depthWrite: false,
      });
      return new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat);
    };

    const screen1Mesh = makePane(display1Canvas.tex, 1.48, 0.95);
    screen1Mesh.position.set(-0.76, 0, 0.05);
    screen1Mesh.rotation.y = 0.10;
    holoArray.add(screen1Mesh);

    const screen2Mesh = makePane(display2Canvas.tex, 1.48, 0.95);
    screen2Mesh.position.set(0.76, 0, 0.05);
    screen2Mesh.rotation.y = -0.10;
    holoArray.add(screen2Mesh);

    const railPoints = [
      new THREE.Vector3(-1.52, 0.49, 0.08),
      new THREE.Vector3(0, 0.49, 0.01),
      new THREE.Vector3(0, 0.49, 0.01),
      new THREE.Vector3(1.52, 0.49, 0.08),
      new THREE.Vector3(-1.52, -0.49, 0.08),
      new THREE.Vector3(0, -0.49, 0.01),
      new THREE.Vector3(0, -0.49, 0.01),
      new THREE.Vector3(1.52, -0.49, 0.08),
    ];
    const railLine = new THREE.LineSegments(
      new THREE.BufferGeometry().setFromPoints(railPoints),
      new THREE.LineBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
      })
    );
    holoArray.add(railLine);

    const fbxLoader = new FBXLoader();

    const playMode = (requestedMode: JurixAvatarMode, duration = 0.35) => {
      const actionName = requestedMode === "speaking" ? "talking" : requestedMode;
      const next = actions[actionName];
      if (!next || activeAction === next) return;

      if (activeAction) activeAction.crossFadeTo(next, duration, true);
      next.reset().fadeIn(duration).play();
      activeAction = next;
    };
    playModeRef.current = (requestedMode) => playMode(requestedMode);

    playPresentationRef.current = () => {
      const next = actions.present;
      if (!next || !mixer || disposed) return;

      const hand = presentationHandRef.current;
      const palmHud = hand?.getObjectByName("JurixPalmHologram");
      if (palmHud) palmHud.visible = true;
      if (holoProjectorRef.current) holoProjectorRef.current.visible = true;

      mixer.stopAllAction();
      next.enabled = true;
      next.setLoop(THREE.LoopOnce, 1);
      next.clampWhenFinished = true;
      next.reset().fadeIn(0.25).play();
      activeAction = next;
      presentationActiveRef.current = true;
    };

    fbxLoader.load(
      "/models/jurix_original_rigged_v1.fbx",
      (model) => {
        if (disposed) return;

        model.name = "JurixOriginalRigged";
        model.traverse((obj) => {
          const mesh = obj as THREE.Mesh;
          if (!mesh.isMesh) return;
          mesh.castShadow = true;
          mesh.receiveShadow = true;
          const materials = Array.isArray(mesh.material) ? mesh.material : [mesh.material];
          materials.forEach((material) => {
            if (material instanceof THREE.MeshStandardMaterial) {
              material.roughness = Math.max(material.roughness, 0.82);
              material.metalness = Math.min(material.metalness, 0.06);
              material.needsUpdate = true;
            }
          });
        });

        model.updateMatrixWorld(true);
        const box = new THREE.Box3().setFromObject(model);
        const size = box.getSize(new THREE.Vector3());
        const center = box.getCenter(new THREE.Vector3());
        const scale = 1.62 / (size.y || 1);
        model.scale.setScalar(scale);
        model.position.set(-center.x * scale + 0.82, -box.min.y * scale - 0.2, -center.z * scale - 0.22);
        scene.add(model);

        presentationHandRef.current =
          model.getObjectByName("mixamorigLeftHand") ||
          model.getObjectByName("mixamorigRightHand") ||
          null;

        if (presentationHandRef.current) {
          const palmHud = new THREE.Group();
          palmHud.name = "JurixPalmHologram";
          palmHud.visible = presentationActiveRef.current;
          palmHud.position.set(0, 0.08, 0.045);
          palmHud.rotation.set(-0.72, 0, 0);
          presentationHandRef.current.add(palmHud);

          const orbParticles = 2800;
          const pGeo = new THREE.BufferGeometry();
          const pPos = new Float32Array(orbParticles * 3);
          const pCol = new Float32Array(orbParticles * 3);
          const cyanC = new THREE.Color(0x38bdf8);
          const indigoC = new THREE.Color(0x818cf8);
          const magentaC = new THREE.Color(0xf43f5e);
          const tmpC = new THREE.Color();

          for (let i = 0; i < orbParticles; i++) {
            const u = Math.random();
            const v = Math.random();
            const theta = u * 2.0 * Math.PI;
            const phi = Math.acos(2.0 * v - 1.0);
            const r = 0.12 + (Math.random() - 0.5) * 0.025;

            pPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
            pPos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
            pPos[i * 3 + 2] = r * Math.cos(phi) + 0.018;

            const distRatio = THREE.MathUtils.clamp((pPos[i * 3 + 1] + 0.12) / 0.24, 0, 1);
            tmpC.copy(cyanC).lerp(indigoC, distRatio);
            if (pPos[i * 3] < -0.02) tmpC.lerp(magentaC, 0.45);

            pCol[i * 3] = tmpC.r;
            pCol[i * 3 + 1] = tmpC.g;
            pCol[i * 3 + 2] = tmpC.b;
          }

          pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
          pGeo.setAttribute("color", new THREE.BufferAttribute(pCol, 3));

          const orbMesh = new THREE.Points(
            pGeo,
            new THREE.PointsMaterial({
              size: 0.006,
              vertexColors: true,
              transparent: true,
              opacity: 0.85,
              blending: THREE.AdditiveBlending,
              depthWrite: false,
              sizeAttenuation: true,
            })
          );
          orbMesh.name = "PalmGlobe";
          palmHud.add(orbMesh);

          const coreM = new THREE.Mesh(
            new THREE.SphereGeometry(0.042, 32, 32),
            new THREE.MeshBasicMaterial({
              color: 0xffffff,
              transparent: true,
              opacity: 0.85,
              blending: THREE.AdditiveBlending,
            })
          );
          coreM.position.z = 0.018;
          palmHud.add(coreM);

          const haloM = new THREE.Mesh(
            new THREE.SphereGeometry(0.075, 32, 32),
            new THREE.MeshBasicMaterial({
              color: 0x38bdf8,
              transparent: true,
              opacity: 0.45,
              blending: THREE.AdditiveBlending,
              depthWrite: false,
            })
          );
          haloM.position.z = 0.018;
          palmHud.add(haloM);

          const orbLight = new THREE.PointLight(0x38bdf8, 1.8, 1.2);
          orbLight.position.set(0, 0, 0.08);
          palmHud.add(orbLight);

          const ringConfigs = [
            { radius: 0.155, color: 0x38bdf8, tiltX: 0.22, tiltY: 0.15 },
            { radius: 0.190, color: 0xa855f7, tiltX: -0.48, tiltY: 0.32 },
            { radius: 0.225, color: 0xec4899, tiltX: 0.75, tiltY: -0.28 },
          ];

          ringConfigs.forEach(({ radius, color, tiltX, tiltY }, idx) => {
            const pts: THREE.Vector3[] = [];
            for (let i = 0; i <= 128; i++) {
              const a = (i / 128) * Math.PI * 2;
              pts.push(new THREE.Vector3(Math.cos(a) * radius, Math.sin(a) * radius * 0.88, 0.02 + idx * 0.003));
            }
            const rLine = new THREE.Line(
              new THREE.BufferGeometry().setFromPoints(pts),
              new THREE.LineBasicMaterial({
                color,
                transparent: true,
                opacity: 0.75,
                blending: THREE.AdditiveBlending,
              })
            );
            rLine.name = "PalmEnergyRing";
            rLine.rotation.x = tiltX;
            rLine.rotation.y = tiltY;
            palmHud.add(rLine);
          });
        }

        mixer = new THREE.AnimationMixer(model);

        const animationFiles = [
          { name: "idle", file: "/models/jurix_idle_v1.fbx", loop: THREE.LoopRepeat },
          { name: "greeting", file: "/models/jurix_greeting_v1.fbx", loop: THREE.LoopOnce },
          { name: "listening", file: "/models/jurix_listening_v1.fbx", loop: THREE.LoopRepeat },
          { name: "talking", file: "/models/jurix_talking_v1.fbx", loop: THREE.LoopRepeat },
          { name: "present", file: "/models/jurix_present_tablet.fbx", loop: THREE.LoopOnce },
        ] as const;

        mixer.addEventListener("finished", (event) => {
          if (disposed) return;
          if (event.action === actions.greeting) playMode("idle");
          if (event.action === actions.present) {
            presentationActiveRef.current = false;
            const palmHud = presentationHandRef.current?.getObjectByName("JurixPalmHologram");
            if (palmHud) palmHud.visible = false;
            if (holoProjectorRef.current) holoProjectorRef.current.visible = false;
            playMode("idle");
          }
        });

        animationFiles.forEach(({ name, file, loop }) => {
          fbxLoader.load(
            file,
            (animationFbx) => {
              if (disposed || !mixer) return;
              if (animationFbx.animations.length === 0) return;

              const clip = animationFbx.animations[0].clone();
              const action = mixer.clipAction(clip);
              action.setLoop(loop, loop === THREE.LoopOnce ? 1 : Infinity);
              if (loop === THREE.LoopOnce) action.clampWhenFinished = name === "present";
              actions[name] = action;
              if (name === "present" && presentationActiveRef.current) {
                playPresentationRef.current();
              }
              if (
                name === "idle" ||
                modeRef.current === name ||
                (modeRef.current === "speaking" && name === "talking")
              ) {
                playMode(modeRef.current);
              }
            },
            undefined,
            (error) => console.error("Failed to load Jurix animation:", file, error)
          );
        });
      },
      undefined,
      (error) => console.error("Failed to load rigged Jurix FBX:", error)
    );

    let lastFrameTime = 0;
    const frameInterval = 1000 / 30;

    const animate = (timestamp: number) => {
      if (disposed) return;
      animId = requestAnimationFrame(animate);

      if (timestamp - lastFrameTime < frameInterval) return;

      const delta = Math.min(clock.getDelta(), 0.05);
      lastFrameTime = timestamp;
      mixer?.update(delta);

      const palmHud = presentationHandRef.current?.getObjectByName("JurixPalmHologram");
      if (palmHud && palmHud.visible) {
        const globe = palmHud.getObjectByName("PalmGlobe");
        if (globe) {
          globe.rotation.y += delta * 0.45;
          globe.rotation.x += delta * 0.18;
        }
        let rIdx = 0;
        palmHud.children.forEach((child) => {
          if (child.name === "PalmEnergyRing") {
            child.rotation.z += delta * (rIdx % 2 === 0 ? 0.42 : -0.35);
            rIdx++;
          }
        });
      }

      const projector = holoProjectorRef.current;
      if (projector && projector.visible) {
        const panels = projector.getObjectByName("FloatingHoloPanels");
        if (panels) {
          panels.position.y = 1.34 + Math.sin(timestamp * 0.002) * 0.008;
        }
      }

      renderer.render(scene, camera);
    };
    animId = requestAnimationFrame(animate);

    const handleResize = () => {
      const w = container.clientWidth || window.innerWidth;
      const h = container.clientHeight || window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener("resize", handleResize);

    return () => {
      disposed = true;
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animId);
      mixer?.stopAllAction();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  useEffect(() => {
    if (!presentationActiveRef.current) playModeRef.current(mode);
  }, [mode]);

  useEffect(() => {
    presentationActiveRef.current = presentationActive;
    const hand = presentationHandRef.current;
    const palmHud = hand?.getObjectByName("JurixPalmHologram");
    if (palmHud) palmHud.visible = presentationActive;
    if (holoProjectorRef.current) holoProjectorRef.current.visible = presentationActive;
    if (!presentationActive) {
      playModeRef.current("idle");
    }
  }, [presentationActive]);

  useEffect(() => {
    if (presentationTrigger > 0) {
      playPresentationRef.current();
    }
  }, [presentationTrigger]);

  return (
    <div className="relative w-full h-full flex items-center justify-center pointer-events-none">
      <div ref={mountRef} className="w-full h-full pointer-events-auto" />
    </div>
  );
};