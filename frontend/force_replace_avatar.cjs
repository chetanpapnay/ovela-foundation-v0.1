const fs = require("fs");
const file = "src/App.tsx";
let code = fs.readFileSync(file, "utf8");

// Locate the vector SVG silhouette block
const svgStart = code.indexOf("<svg viewBox=\"0 0 400 600\"");
if (svgStart !== -1) {
  const svgEnd = code.indexOf("</svg>", svgStart) + 6;
  
  const replacement = `<div className="relative w-full h-[540px] flex items-center justify-center overflow-hidden rounded-2xl">
              <img
                src="/images/executive_hero.png"
                alt="Sovereign Executive"
                className="w-full h-full object-cover object-center filter contrast-105 brightness-95 opacity-90 pointer-events-auto"
                style={{
                  maskImage: "radial-gradient(ellipse 95% 95% at 50% 45%, black 65%, transparent 100%)",
                  WebkitMaskImage: "radial-gradient(ellipse 95% 95% at 50% 45%, black 65%, transparent 100%)"
                }}
              />
              <div className="absolute inset-0 bg-[radial-gradient(rgba(56,189,248,0.12)_1px,transparent_1px)] [background-size:24px_24px] pointer-events-none" />
              <motion.div
                animate={{ scale: [1, 1.25, 1], opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
                className="absolute top-[38%] left-[26%] w-6 h-6 rounded-full border border-cyan-400 bg-cyan-400/20 shadow-[0_0_20px_#38bdf8] flex items-center justify-center pointer-events-none"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-200" />
              </motion.div>
            </div>`;

  code = code.slice(0, svgStart) + replacement + code.slice(svgEnd);
  fs.writeFileSync(file, code, "utf8");
  console.log("✓ SUCCESS: Completely erased SVG mannequin and injected real executive visual!");
} else {
  console.error("Could not find SVG block. Checking file structure...");
}
