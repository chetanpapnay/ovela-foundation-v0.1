const fs = require("fs");
const { GLTFLoader } = require("three/examples/jsm/loaders/GLTFLoader.js");
const { LoadingManager } = require("three");

const file = "public/models/jurix_v2_test.glb";
const data = fs.readFileSync(file);
const jsonLength = data.readUInt32LE(12);
const json = JSON.parse(data.toString("utf8", 20, 20 + jsonLength));

console.log("GLB nodes:");
(json.nodes || []).forEach((node, i) => {
  if (node.name) console.log(i + ": " + node.name);
});

console.log("\nSkin joint node names:");
(json.skins || []).forEach((skin, i) => {
  console.log("Skin " + i + ":");
  (skin.joints || []).forEach(j => console.log("  " + j + ": " + (json.nodes[j]?.name || "(unnamed)")));
});
