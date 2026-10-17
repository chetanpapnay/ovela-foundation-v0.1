const fs = require("fs");
const file = "src/jurix/OvelaConsole.tsx";
let code = fs.readFileSync(file, "utf8");

// 1. Give header elements high-contrast backdrops
code = code.replace(
  'padding: "24px 32px",',
  'padding: "20px 32px", background: "linear-gradient(180deg, rgba(2,6,14,0.85) 0%, rgba(2,6,14,0.4) 70%, transparent 100%)", backdropFilter: "blur(8px)",'
);

// 2. Put subtitle in a clear, frosted-glass capsule for bulletproof readability
code = code.replace(
  '<p style={{ maxWidth: "700px", textAlign: "center", fontSize: "16px", color: "#f8fafc", fontWeight: 300, lineHeight: 1.6, textShadow: "0 2px 14px rgba(0, 0, 0, 0.95)" }}>',
  '<p style={{ maxWidth: "700px", textAlign: "center", fontSize: "15px", color: "#f8fafc", fontWeight: 400, letterSpacing: "0.02em", background: "rgba(4, 10, 22, 0.65)", backdropFilter: "blur(16px)", border: "1px solid rgba(56, 189, 248, 0.2)", padding: "10px 24px", borderRadius: "9999px", boxShadow: "0 10px 25px rgba(0,0,0,0.5)" }}>'
);

fs.writeFileSync(file, code, "utf8");
console.log("✓ Applied contrast fix to header and subtitles.");
