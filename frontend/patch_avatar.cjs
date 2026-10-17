const fs = require("fs");
const file = "src/App.tsx";
let code = fs.readFileSync(file, "utf8");

const oldCenterChamberRegex = /{\/\* Volumetric Central Holo-Avatar Presence \*\/}[\s\S]*?{\/\* HUD Telemetry Footer Overlay \*\/}/;

const newCenterChamber = `{/* Volumetric Real Human Executive Anchor */}
          <div className="relative w-full h-full flex items-center justify-center select-none overflow-hidden">
            {/* Ambient Cyan Volumetric Lighting */}
            <div className="absolute inset-0 bg-radial from-cyan-500/20 via-transparent to-transparent blur-3xl pointer-events-none" />

            <div className="relative w-full h-full flex items-center justify-center">
              <img
                src="/images/executive_hero.png"
                alt="Sovereign Executive"
                className="w-full h-full object-cover object-center filter contrast-105 brightness-95 opacity-90 transition-all duration-700"
                style={{
                  maskImage: "radial-gradient(ellipse 95% 95% at 50% 45%, black 65%, transparent 100%)",
                  WebkitMaskImage: "radial-gradient(ellipse 95% 95% at 50% 45%, black 65%, transparent 100%)"
                }}
              />
              
              {/* Dynamic Scanning Grid */}
              <div className="absolute inset-0 bg-[radial-gradient(rgba(56,189,248,0.12)_1px,transparent_1px)] [background-size:24px_24px] pointer-events-none" />
              
              {/* Holographic Fingertip Spatial Anchor */}
              <motion.div
                animate={{
                  scale: [1, 1.25, 1],
                  opacity: [0.6, 1, 0.6]
                }}
                transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
                className="absolute top-[42%] left-[24%] w-6 h-6 rounded-full border border-cyan-400 bg-cyan-400/20 shadow-[0_0_20px_#38bdf8] flex items-center justify-center pointer-events-none"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-200" />
              </motion.div>
            </div>
          </div>

          {/* HUD Telemetry Footer Overlay */}`;

if (oldCenterChamberRegex.test(code)) {
  code = code.replace(oldCenterChamberRegex, newCenterChamber);
  fs.writeFileSync(file, code, "utf8");
  console.log("✓ Successfully replaced vector mannequin with real executive anchor!");
} else {
  console.log("Regex pattern not matched. Checking file contents.");
}
