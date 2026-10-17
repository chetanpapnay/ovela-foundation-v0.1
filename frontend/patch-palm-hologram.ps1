$ErrorActionPreference = "Stop"
$f = ".\src\jurix\JurixWebRTCStage.tsx"
$src = [IO.File]::ReadAllText((Resolve-Path $f))
$backup = "$f.bak-palm-tracking"
Copy-Item $f $backup -Force

$replacements = @(
  @{
    Old = 'const presentationTabletRef = useRef<THREE.Group | null>(null);'
    New = 'const presentationTabletRef = useRef<THREE.Group | null>(null);' + "`r`n" +
          '  const presentationHandRef = useRef<THREE.Object3D | null>(null);'
  },
  @{
    Old = 'palmHologram.visible = false;' + "`r`n" + '    presentationTabletRef.current = palmHologram;'
    New = 'palmHologram.visible = false;' + "`r`n" +
          '    palmHologram.scale.setScalar(0.72);' + "`r`n" +
          '    presentationTabletRef.current = palmHologram;' + "`r`n" +
          '    scene.add(palmHologram);'
  },
  @{
    Old = '        scene.add(model);'
    New = '        scene.add(model);' + "`r`n" +
          '        presentationHandRef.current = model.getObjectByName("mixamorigRightHand")' + "`r`n" +
          '          || model.getObjectByName("mixamorigLeftHand")' + "`r`n" +
          '          || null;'
  },
  @{
    Old = '      mixer?.update(delta);' + "`r`n" + '      renderer.render(scene, camera);'
    New = '      mixer?.update(delta);' + "`r`n" +
          '      const hand = presentationHandRef.current;' + "`r`n" +
          '      const hud = presentationTabletRef.current;' + "`r`n" +
          '      if (hand && hud && hud.visible) {' + "`r`n" +
          '        hand.updateWorldMatrix(true, false);' + "`r`n" +
          '        hand.getWorldPosition(hud.position);' + "`r`n" +
          '        hud.position.y += 0.075;' + "`r`n" +
          '        hud.position.z += 0.045;' + "`r`n" +
          '        hud.quaternion.copy(camera.quaternion);' + "`r`n" +
          '      }' + "`r`n" +
          '      renderer.render(scene, camera);'
  }
)

foreach ($r in $replacements) {
  if (-not $src.Contains($r.Old)) {
    Copy-Item $backup $f -Force
    throw "Patch stopped: expected code was not found. Original restored from backup."
  }
  $src = $src.Replace($r.Old, $r.New)
}
[IO.File]::WriteAllText((Resolve-Path $f), $src, [Text.UTF8Encoding]::new($false))
npm run build
if ($LASTEXITCODE -ne 0) {
  Copy-Item $backup $f -Force
  throw "Build failed; original file restored."
}
