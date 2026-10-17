const fs = require("fs");
for (const f of ["public/models/jurix_avatar.glb", "public/models/jurix_v2_test.glb"]) {
  const b = fs.readFileSync(f);
  const n = b.readUInt32LE(12);
  const j = JSON.parse(b.toString("utf8", 20, 20 + n));
  console.log(f + " | skins: " + (j.skins?.length || 0) + " | nodes: " + (j.nodes?.length || 0) + " | meshes: " + (j.meshes?.length || 0));
}
