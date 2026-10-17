import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { FBXLoader } from "three/examples/jsm/loaders/FBXLoader.js";

export type JurixAvatarMode = "idle" | "greeting" | "listening" | "speaking";

export interface HoloPresentationData {
  reportTitle?: string;
  primaryValue?: string;
  primaryDelta?: string;
  leftTitle?: string;
  leftBars?: { label: string; value: number; display: string }[];
  centerTitle?: string;
  centerMetric?: string;
  centerSubtitle?: string;
  rightTitle?: string;
  rightMetric?: string;
  rightDelta?: string;
  statusBadge?: string;
}

interface JurixWebRTCStageProps {
  mode: JurixAvatarMode;
  presentationTrigger?: number;
  presentationActive?: boolean;
  presentationData?: HoloPresentationData;
}

const DEFAULT_PRESENTATION_DATA: HoloPresentationData = {
  reportTitle: "FINANCIAL POSITION & CASHFLOW",
  primaryValue: "₹ 52,100M",
  primaryDelta: "+342.8% Delta",
  leftTitle: "CAPITAL ALLOCATION",
  leftBars: [
    { label: "Q1", value: 0.45, display: "₹18M" },
    { label: "Q2", value: 0.62, display: "₹29M" },
    { label: "Q3", value: 0.85, display: "₹42M" },
    { label: "Q4", value: 0.96, display: "₹52M" },
  ],
  centerTitle: "PORTFOLIO HEALTH MATRIX",
  centerMetric: "99.4%",
  centerSubtitle: "ZERO INVARIANT DRIFT",
  rightTitle: "VARIANCE & EXPENSE TREND",
  rightMetric: "0.042 σ",
  rightDelta: "WITHIN SAFE LIMITS",
  statusBadge: "SETTLEMENT COMMITTED",
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
    currentDataRef.current = presentationData;
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
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
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

    // ========================================================
    // ZERO-LAG CACHED CANVASES (Baked only when data updates)
    // ========================================================
    const createCanvasTexture = (w: number, h: number) => {
      const cvs = document.createElement("canvas");
      cvs.width = w;
      cvs.height = h;
      const ctx = cvs.getContext("2d")!;
      const tex = new THREE.CanvasTexture(cvs);
      tex.colorSpace = THREE.SRGBColorSpace;
      tex.generateMipmaps = false;
      tex.minFilter = THREE.LinearFilter;
      return { cvs, ctx, tex };
    };

    const leftCanvas = createCanvasTexture(1024, 1024);
    const centerCanvas = createCanvasTexture(1024, 1024);
    const rightCanvas = createCanvasTexture(1024, 1024);

    const drawLeftStatic = () => {
      const { ctx } = leftCanvas;
      const d = currentDataRef.current;
      ctx.clearRect(0, 0, 1024, 1024);

      const bg = ctx.createLinearGradient(0, 0, 0, 1024);
      bg.addColorStop(0, "rgba(5, 17, 36, 0.90)");
      bg.addColorStop(1, "rgba(2, 7, 18, 0.96)");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, 1024, 1024);

      ctx.strokeStyle = "rgba(56, 189, 248, 0.12)";
      ctx.lineWidth = 1.5;
      for (let y = 60; y < 1024; y += 40) {
        ctx.beginPath();
        ctx.moveTo(40, y);
        ctx.lineTo(984, y);
        ctx.stroke();
      }

      ctx.strokeStyle = "#0284c7";
      ctx.lineWidth = 4;
      ctx.strokeRect(20, 20, 984, 984);
      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 6;
      ctx.beginPath();
      ctx.moveTo(20, 120); ctx.lineTo(20, 20); ctx.lineTo(120, 20);
      ctx.moveTo(904, 20); ctx.lineTo(1004, 20); ctx.lineTo(1004, 120);
      ctx.moveTo(20, 924); ctx.lineTo(20, 1004); ctx.lineTo(120, 1004);
      ctx.moveTo(904, 1004); ctx.lineTo(1004, 1004); ctx.lineTo(1004, 924);
      ctx.stroke();

      ctx.fillStyle = "#38bdf8";
      ctx.font = "bold 26px monospace";
      ctx.fillText(`// ${d.leftTitle || "CAPITAL ALLOCATION"}`, 50, 80);

      ctx.fillStyle = "#ffffff";
      ctx.font = "bold 58px sans-serif";
      ctx.fillText(d.primaryValue || "₹ 52,100M", 50, 160);

      ctx.fillStyle = "rgba(34, 197, 94, 0.22)";
      ctx.fillRect(50, 185, 240, 44);
      ctx.strokeStyle = "#22c55e";
      ctx.lineWidth = 2;
      ctx.strokeRect(50, 185, 240, 44);
      ctx.fillStyle = "#4ade80";
      ctx.font = "bold 24px monospace";
      ctx.fillText(`▲ ${d.primaryDelta || "+342.8%"}`, 68, 216);

      const bars = d.leftBars && d.leftBars.length > 0 ? d.leftBars : DEFAULT_PRESENTATION_DATA.leftBars!;
      const startX = 80;
      const totalWidth = 864;
      const barWidth = totalWidth / bars.length - 40;
      const baseY = 860;
      const maxHeight = 460;

      bars.forEach((b, idx) => {
        const x = startX + idx * (barWidth + 40);
        const barH = b.value * maxHeight;
        const barY = baseY - barH;

        const grad = ctx.createLinearGradient(0, barY, 0, baseY);
        grad.addColorStop(0, idx === bars.length - 1 ? "#38bdf8" : "#0284c7");
        grad.addColorStop(1, "rgba(2, 44, 90, 0.7)");
        ctx.fillStyle = grad;
        ctx.fillRect(x, barY, barWidth, barH);

        ctx.fillStyle = "#e0f2fe";
        ctx.fillRect(x, barY, barWidth, 6);

        ctx.fillStyle = "#ffffff";
        ctx.font = "bold 30px monospace";
        ctx.textAlign = "center";
        ctx.fillText(b.display, x + barWidth / 2, barY - 18);

        ctx.fillStyle = "#38bdf8";
        ctx.font = "bold 28px monospace";
        ctx.fillText(b.label, x + barWidth / 2, baseY + 45);
      });
      ctx.textAlign = "left";

      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo(50, baseY);
      ctx.lineTo(974, baseY);
      ctx.stroke();

      ctx.fillStyle = "rgba(148, 163, 184, 0.85)";
      ctx.font = "bold 20px monospace";
      ctx.fillText("VERIFIED LEDGER ENTRY // AUDIT SIGNED", 50, 960);

      leftCanvas.tex.needsUpdate = true;
    };

    const drawCenterStatic = () => {
      const { ctx } = centerCanvas;
      const d = currentDataRef.current;
      ctx.clearRect(0, 0, 1024, 1024);

      const bg = ctx.createLinearGradient(0, 0, 0, 1024);
      bg.addColorStop(0, "rgba(6, 20, 44, 0.92)");
      bg.addColorStop(1, "rgba(2, 8, 22, 0.97)");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, 1024, 1024);

      ctx.strokeStyle = "#0284c7";
      ctx.lineWidth = 4;
      ctx.strokeRect(20, 20, 984, 984);
      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 6;
      ctx.beginPath();
      ctx.moveTo(20, 120); ctx.lineTo(20, 20); ctx.lineTo(120, 20);
      ctx.moveTo(904, 20); ctx.lineTo(1004, 20); ctx.lineTo(1004, 120);
      ctx.moveTo(20, 924); ctx.lineTo(20, 1004); ctx.lineTo(120, 1004);
      ctx.moveTo(904, 1004); ctx.lineTo(1004, 1004); ctx.lineTo(1004, 924);
      ctx.stroke();

      ctx.fillStyle = "#38bdf8";
      ctx.font = "bold 26px monospace";
      ctx.fillText(`// ${d.centerTitle || "PORTFOLIO HEALTH MATRIX"}`, 50, 80);

      const cx = 512;
      const cy = 490;

      [280, 210, 140].forEach((r, idx) => {
        ctx.strokeStyle = idx === 0 ? "rgba(56, 189, 248, 0.85)" : "rgba(56, 189, 248, 0.35)";
        ctx.lineWidth = idx === 0 ? 4 : 2;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      });

      ctx.strokeStyle = "rgba(125, 211, 252, 0.4)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(cx - 310, cy); ctx.lineTo(cx + 310, cy);
      ctx.moveTo(cx, cy - 310); ctx.lineTo(cx, cy + 310);
      ctx.stroke();

      ctx.textAlign = "center";
      ctx.fillStyle = "#ffffff";
      ctx.font = "bold 82px sans-serif";
      ctx.fillText(d.centerMetric || "99.4%", cx, cy + 28);

      ctx.fillStyle = "#38bdf8";
      ctx.font = "bold 24px monospace";
      ctx.fillText(d.centerSubtitle || "ZERO INVARIANT DRIFT", cx, 830);

      ctx.fillStyle = "rgba(34, 197, 94, 0.2)";
      ctx.fillRect(cx - 210, 870, 420, 60);
      ctx.strokeStyle = "#22c55e";
      ctx.lineWidth = 3;
      ctx.strokeRect(cx - 210, 870, 420, 60);
      ctx.fillStyle = "#4ade80";
      ctx.font = "bold 26px monospace";
      ctx.fillText(`● ${d.statusBadge || "SETTLEMENT COMMITTED"}`, cx, 910);
      ctx.textAlign = "left";

      centerCanvas.tex.needsUpdate = true;
    };

    const drawRightStatic = () => {
      const { ctx } = rightCanvas;
      const d = currentDataRef.current;
      ctx.clearRect(0, 0, 1024, 1024);

      const bg = ctx.createLinearGradient(0, 0, 0, 1024);
      bg.addColorStop(0, "rgba(28, 8, 38, 0.92)");
      bg.addColorStop(1, "rgba(12, 3, 20, 0.97)");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, 1024, 1024);

      ctx.strokeStyle = "#a21caf";
      ctx.lineWidth = 4;
      ctx.strokeRect(20, 20, 984, 984);
      ctx.strokeStyle = "#e879f9";
      ctx.lineWidth = 6;
      ctx.beginPath();
      ctx.moveTo(20, 120); ctx.lineTo(20, 20); ctx.lineTo(120, 20);
      ctx.moveTo(904, 20); ctx.lineTo(1004, 20); ctx.lineTo(1004, 120);
      ctx.moveTo(20, 924); ctx.lineTo(20, 1004); ctx.lineTo(120, 1004);
      ctx.moveTo(904, 1004); ctx.lineTo(1004, 1004); ctx.lineTo(1004, 924);
      ctx.stroke();

      ctx.fillStyle = "#e879f9";
      ctx.font = "bold 26px monospace";
      ctx.fillText(`// ${d.rightTitle || "VARIANCE & EXPENSE TREND"}`, 50, 80);

      ctx.fillStyle = "#ffffff";
      ctx.font = "bold 66px sans-serif";
      ctx.fillText(d.rightMetric || "0.042 σ", 50, 160);

      ctx.fillStyle = "#f472b6";
      ctx.font = "bold 24px monospace";
      ctx.fillText(`STATUS: ${d.rightDelta || "WITHIN SAFE LIMITS"}`, 50, 206);

      const threshY = 440;
      ctx.strokeStyle = "#ef4444";
      ctx.lineWidth = 3;
      ctx.setLineDash([12, 8]);
      ctx.beginPath();
      ctx.moveTo(50, threshY);
      ctx.lineTo(974, threshY);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = "#f87171";
      ctx.font = "bold 22px monospace";
      ctx.fillText("MAX SPREAD TOLERANCE CEILING", 520, threshY - 14);

      // Baseline wave
      const points: { x: number; y: number }[] = [];
      const waveBase = 680;
      for (let x = 50; x <= 974; x += 12) {
        const rad = (x - 50) * 0.02;
        const y = waveBase + Math.sin(rad) * 90 + Math.cos(rad * 0.4) * 45;
        points.push({ x, y });
      }

      const areaGrad = ctx.createLinearGradient(0, threshY, 0, 860);
      areaGrad.addColorStop(0, "rgba(232, 121, 249, 0.35)");
      areaGrad.addColorStop(1, "rgba(217, 70, 239, 0.02)");
      ctx.fillStyle = areaGrad;
      ctx.beginPath();
      ctx.moveTo(points[0].x, points[0].y);
      points.forEach((p) => ctx.lineTo(p.x, p.y));
      ctx.lineTo(974, 860);
      ctx.lineTo(50, 860);
      ctx.closePath();
      ctx.fill();

      ctx.strokeStyle = "#f472b6";
      ctx.lineWidth = 5;
      ctx.beginPath();
      ctx.moveTo(points[0].x, points[0].y);
      points.forEach((p) => ctx.lineTo(p.x, p.y));
      ctx.stroke();

      ctx.strokeStyle = "#e879f9";
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo(50, 860);
      ctx.lineTo(974, 860);
      ctx.stroke();

      ctx.fillStyle = "rgba(226, 232, 240, 0.85)";
      ctx.font = "bold 20px monospace";
      ctx.fillText("DRIFT INTERVAL: REAL-TIME SECURE ORACLE", 50, 960);

      rightCanvas.tex.needsUpdate = true;
    };

    updateCanvasesRef.current = () => {
      drawLeftStatic();
      drawCenterStatic();
      drawRightStatic();
    };
    updateCanvasesRef.current();

    // ========================================================
    // 3D PROJECTOR & VOLUMETRIC HUD SCENE ASSEMBLY
    // Locked at exact coordinates: (-1.05, -0.34, -0.95)
    // ========================================================
    const projectorGroup = new THREE.Group();
    projectorGroup.name = "JurixFloorHoloProjector";
    projectorGroup.position.set(-1.05, -0.34, -0.95);
    projectorGroup.visible = false;
    scene.add(projectorGroup);
    holoProjectorRef.current = projectorGroup;

    // Floor Radial Ground Disc
    const groundDisc = new THREE.Mesh(
      new THREE.CircleGeometry(0.55, 36),
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

    // Industrial Pedestal Base
    const plinthMat = new THREE.MeshStandardMaterial({ color: 0x070d18, metalness: 0.94, roughness: 0.18 });
    const chamferMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, metalness: 0.88, roughness: 0.32 });

    const mainChassis = new THREE.Mesh(new THREE.CylinderGeometry(0.32, 0.36, 0.035, 8), plinthMat);
    mainChassis.position.y = 0.0175;
    projectorGroup.add(mainChassis);

    const upperDeck = new THREE.Mesh(new THREE.CylinderGeometry(0.24, 0.28, 0.025, 16), chamferMat);
    upperDeck.position.y = 0.040;
    projectorGroup.add(upperDeck);

    for (let i = 0; i < 8; i++) {
      const angle = (i / 8) * Math.PI * 2;
      const fin = new THREE.Mesh(
        new THREE.BoxGeometry(0.045, 0.022, 0.012),
        new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.9, roughness: 0.2 })
      );
      fin.position.set(Math.cos(angle) * 0.27, 0.038, Math.sin(angle) * 0.27);
      fin.rotation.y = -angle;
      projectorGroup.add(fin);
    }

    const shutterRing = new THREE.Mesh(
      new THREE.RingGeometry(0.16, 0.19, 36),
      new THREE.MeshBasicMaterial({ color: 0x38bdf8, side: THREE.DoubleSide })
    );
    shutterRing.rotation.x = -Math.PI / 2;
    shutterRing.position.y = 0.054;
    projectorGroup.add(shutterRing);

    const opticalLens = new THREE.Mesh(
      new THREE.CylinderGeometry(0.12, 0.14, 0.014, 32),
      new THREE.MeshBasicMaterial({ color: 0xe0f7ff, transparent: true, opacity: 0.95 })
    );
    opticalLens.position.y = 0.058;
    projectorGroup.add(opticalLens);

    const plinthLight = new THREE.PointLight(0x38bdf8, 2.0, 3.2);
    plinthLight.position.y = 0.22;
    projectorGroup.add(plinthLight);

    // Volumetric Light Funnel
    const volumetricCone = new THREE.Mesh(
      new THREE.CylinderGeometry(0.72, 0.13, 1.10, 36, 1, true),
      new THREE.MeshBasicMaterial({
        color: 0x0284c7,
        transparent: true,
        opacity: 0.12,
        blending: THREE.AdditiveBlending,
        side: THREE.DoubleSide,
        depthWrite: false,
      })
    );
    volumetricCone.position.y = 0.58;
    projectorGroup.add(volumetricCone);

    // Laser Core Needle
    const laserNeedle = new THREE.Mesh(
      new THREE.CylinderGeometry(0.18, 0.06, 1.10, 24, 1, true),
      new THREE.MeshBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0.35,
        blending: THREE.AdditiveBlending,
        side: THREE.DoubleSide,
        depthWrite: false,
      })
    );
    laserNeedle.position.y = 0.58;
    projectorGroup.add(laserNeedle);

    // Floating Holographic Array
    const holoArray = new THREE.Group();
    holoArray.name = "FloatingHoloPanels";
    holoArray.position.set(0, 1.15, 0.02);
    projectorGroup.add(holoArray);

    const makePane = (map: THREE.CanvasTexture, w: number, h: number) => {
      const mat = new THREE.MeshBasicMaterial({
        map,
        transparent: true,
        opacity: 0.98,
        side: THREE.DoubleSide,
        depthWrite: false,
      });
      return new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat);
    };

    const centerMesh = makePane(centerCanvas.tex, 0.58, 0.52);
    centerMesh.position.set(0, 0, 0);
    holoArray.add(centerMesh);

    // 3D Native Radar Sweep Hand (Zero Canvas Lag)
    const sweepArm = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, 0, 0.005), new THREE.Vector3(0, 0.16, 0.005)]),
      new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending })
    );
    sweepArm.name = "NativeRadarSweep";
    sweepArm.position.set(0, -0.015, 0);
    centerMesh.add(sweepArm);

    const leftMesh = makePane(leftCanvas.tex, 0.52, 0.48);
    leftMesh.position.set(-0.54, 0, 0.08);
    leftMesh.rotation.y = 0.32;
    holoArray.add(leftMesh);

    const rightMesh = makePane(rightCanvas.tex, 0.52, 0.48);
    rightMesh.position.set(0.54, 0, 0.08);
    rightMesh.rotation.y = -0.32;
    holoArray.add(rightMesh);

    const railPoints = [
      new THREE.Vector3(-0.78, 0.28, 0.12),
      new THREE.Vector3(-0.29, 0.28, 0.01),
      new THREE.Vector3(0.29, 0.28, 0.01),
      new THREE.Vector3(0.78, 0.28, 0.12),
      new THREE.Vector3(-0.78, -0.28, 0.12),
      new THREE.Vector3(-0.29, -0.28, 0.01),
      new THREE.Vector3(0.29, -0.28, 0.01),
      new THREE.Vector3(0.78, -0.28, 0.12),
    ];
    const railLine = new THREE.LineSegments(
      new THREE.BufferGeometry().setFromPoints(railPoints),
      new THREE.LineBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0.92,
        blending: THREE.AdditiveBlending,
      })
    );
    holoArray.add(railLine);

    // ==========================================
    // FBX AVATAR AND ANIMATION CONTROLLER
    // ==========================================
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

        // HIGH-LUMINANCE QUANTUM ORB IN PALM
        if (presentationHandRef.current) {
          const palmHud = new THREE.Group();
          palmHud.name = "JurixPalmHologram";
          palmHud.visible = presentationActiveRef.current;
          palmHud.position.set(0, 0.08, 0.045);
          palmHud.rotation.set(-0.72, 0, 0);
          presentationHandRef.current.add(palmHud);

          // 1. High-Density Photorealistic Particle Cloud (2,800 Particles)
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

          // 2. Pure White Radiant Micro-Core
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

          // 3. Volumetric Cyan Core Halo
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

          // 4. Point Light Core Cast
          const orbLight = new THREE.PointLight(0x38bdf8, 1.8, 1.2);
          orbLight.position.set(0, 0, 0.08);
          palmHud.add(orbLight);

          // 5. High-Luminance Gyroscopic Orbital Rings
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
      const elapsed = clock.getElapsedTime();
      lastFrameTime = timestamp;
      mixer?.update(delta);

      // Animate Palm Hologram
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

      // Smooth Native Animation without Canvas Redraw Stalls
      const projector = holoProjectorRef.current;
      if (projector && projector.visible) {
        const sweep = projector.getObjectByName("NativeRadarSweep");
        if (sweep) {
          sweep.rotation.z = -elapsed * 2.0;
        }
        const panels = projector.getObjectByName("FloatingHoloPanels");
        if (panels) {
          panels.position.y = 1.15 + Math.sin(timestamp * 0.002) * 0.008;
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