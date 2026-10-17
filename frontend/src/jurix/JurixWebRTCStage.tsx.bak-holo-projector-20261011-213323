import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { FBXLoader } from "three/examples/jsm/loaders/FBXLoader.js";

export type JurixAvatarMode = "idle" | "greeting" | "listening" | "speaking";

interface JurixWebRTCStageProps {
  mode: JurixAvatarMode;
  presentationTrigger?: number;
  presentationActive?: boolean;
}

export const JurixWebRTCStage: React.FC<JurixWebRTCStageProps> = ({
  mode,
  presentationTrigger = 0,
  presentationActive = false,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const modeRef = useRef<JurixAvatarMode>(mode);
  const playModeRef = useRef<(name: JurixAvatarMode) => void>(() => {});
  const playPresentationRef = useRef<() => void>(() => {});
  const presentationActiveRef = useRef(false);
  const presentationHandRef = useRef<THREE.Object3D | null>(null);

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

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
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
          palmHud.position.set(0, 0.075, 0.045);
          palmHud.rotation.set(-0.72, 0, 0);
          palmHud.scale.setScalar(0.9);
          presentationHandRef.current.add(palmHud);

          // 1. High-Density Photorealistic Particle Cloud
          const particleCount = 2600;
          const particleGeometry = new THREE.BufferGeometry();
          const positions = new Float32Array(particleCount * 3);
          const colors = new Float32Array(particleCount * 3);

          const cyanCore = new THREE.Color(0x38bdf8);
          const indigoMid = new THREE.Color(0x818cf8);
          const magentaEdge = new THREE.Color(0xf43f5e);
          const tempColor = new THREE.Color();

          for (let i = 0; i < particleCount; i++) {
            const u = Math.random();
            const v = Math.random();
            const theta = u * 2.0 * Math.PI;
            const phi = Math.acos(2.0 * v - 1.0);
            const r = 0.115 + (Math.random() - 0.5) * 0.025;

            const x = r * Math.sin(phi) * Math.cos(theta);
            const y = r * Math.sin(phi) * Math.sin(theta);
            const z = r * Math.cos(phi);

            positions[i * 3] = x;
            positions[i * 3 + 1] = y;
            positions[i * 3 + 2] = z + 0.018;

            const distRatio = THREE.MathUtils.clamp((y + 0.12) / 0.24, 0, 1);
            tempColor.copy(cyanCore).lerp(indigoMid, distRatio);
            if (x < -0.02) {
              tempColor.lerp(magentaEdge, 0.45);
            }

            colors[i * 3] = tempColor.r;
            colors[i * 3 + 1] = tempColor.g;
            colors[i * 3 + 2] = tempColor.b;
          }

          particleGeometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
          particleGeometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));

          const particleGlobe = new THREE.Points(
            particleGeometry,
            new THREE.PointsMaterial({
              size: 0.0055,
              vertexColors: true,
              transparent: true,
              opacity: 0.75,
              blending: THREE.AdditiveBlending,
              depthWrite: false,
              sizeAttenuation: true,
              toneMapped: false,
            })
          );
          particleGlobe.name = "PalmParticleGlobe";
          palmHud.add(particleGlobe);

          // 2. High-Luminance Micro Core
          const energyCore = new THREE.Mesh(
            new THREE.SphereGeometry(0.038, 32, 32),
            new THREE.MeshBasicMaterial({
              color: 0xe0f7ff,
              transparent: true,
              opacity: 0.45,
              blending: THREE.AdditiveBlending,
              toneMapped: false,
            })
          );
          energyCore.position.z = 0.018;
          palmHud.add(energyCore);

          // 3. Volumetric Core Halo
          const coreHalo = new THREE.Mesh(
            new THREE.SphereGeometry(0.065, 32, 32),
            new THREE.MeshBasicMaterial({
              color: 0x38bdf8,
              transparent: true,
              opacity: 0.35,
              blending: THREE.AdditiveBlending,
              depthWrite: false,
              toneMapped: false,
            })
          );
          coreHalo.position.z = 0.018;
          palmHud.add(coreHalo);

          // 4. Subtle Wireframe Geometry Cage
          const latticeCage = new THREE.Mesh(
            new THREE.IcosahedronGeometry(0.122, 2),
            new THREE.MeshBasicMaterial({
              color: 0x6366f1,
              wireframe: true,
              transparent: true,
              opacity: 0.16,
              blending: THREE.AdditiveBlending,
              depthWrite: false,
              toneMapped: false,
            })
          );
          latticeCage.name = "PalmLatticeCage";
          latticeCage.position.z = 0.018;
          palmHud.add(latticeCage);

          // 5. Point Light Emission
          const glow = new THREE.PointLight(0x38bdf8, 1.2, 0.9);
          glow.position.set(0, 0, 0.08);
          palmHud.add(glow);

          // 6. Gyroscopic Quantum Orbital Rings
          const ringConfigs = [
            { radius: 0.145, color: 0x38bdf8, tiltX: 0.22, tiltY: 0.15 },
            { radius: 0.178, color: 0xa855f7, tiltX: -0.48, tiltY: 0.32 },
            { radius: 0.210, color: 0xec4899, tiltX: 0.75, tiltY: -0.28 },
          ];

          ringConfigs.forEach(({ radius, color, tiltX, tiltY }, index) => {
            const points: THREE.Vector3[] = [];
            for (let i = 0; i <= 128; i++) {
              const a = (i / 128) * Math.PI * 2;
              points.push(
                new THREE.Vector3(
                  Math.cos(a) * radius,
                  Math.sin(a) * radius * 0.88,
                  0.02 + index * 0.003
                )
              );
            }

            const ring = new THREE.Line(
              new THREE.BufferGeometry().setFromPoints(points),
              new THREE.LineBasicMaterial({
                color,
                transparent: true,
                opacity: 0.55,
                blending: THREE.AdditiveBlending,
                depthWrite: false,
                toneMapped: false,
              })
            );
            ring.name = "PalmEnergyRing";
            ring.rotation.x = tiltX;
            ring.rotation.y = tiltY;
            palmHud.add(ring);
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

          if (event.action === actions.greeting) {
            playMode("idle");
          }

          if (event.action === actions.present) {
            presentationActiveRef.current = false;
            const palmHud = presentationHandRef.current?.getObjectByName("JurixPalmHologram");
            if (palmHud) palmHud.visible = false;
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
        const particles = palmHud.getObjectByName("PalmParticleGlobe");
        if (particles) {
          particles.rotation.y += delta * 0.45;
          particles.rotation.x += delta * 0.18;
        }

        const cage = palmHud.getObjectByName("PalmLatticeCage");
        if (cage) {
          cage.rotation.y -= delta * 0.25;
          cage.rotation.z += delta * 0.15;
        }

        let ringIndex = 0;
        palmHud.children.forEach((child) => {
          if (child.name === "PalmEnergyRing") {
            child.rotation.z += delta * (ringIndex % 2 === 0 ? 0.42 : -0.35);
            ringIndex++;
          }
        });
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