const fs = require("fs");
const file = "src/App.tsx";
let code = fs.readFileSync(file, "utf8");

// Remove the unused icon imports flagged by tsc
const unusedIcons = [
  "Activity,",
  "Sliders,",
  "Compass,",
  "Maximize2,",
  "Layers,",
  "ChevronRight,",
  "Eye,",
  "FileText,",
  "Search,"
];

unusedIcons.forEach(icon => {
  const reg = new RegExp(`^\\s*${icon}\\r?\\n`, "gm");
  code = code.replace(reg, "");
});

fs.writeFileSync(file, code, "utf8");
console.log("✓ Removed unused icon imports from src/App.tsx");
