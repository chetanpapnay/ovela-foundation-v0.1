const fs = require('fs');
let code = fs.readFileSync('src/App.tsx', 'utf8');

// Remove unused icons
code = code.replace(/^\s*(Activity|Sliders|Compass|Maximize2|Layers|ChevronRight|Eye|FileText|Search),\r_\n/gm, '');

// Replace vector silhouette with real hero image
code = code.replace(
  /<svg viewBox=['"][^'"]*[&'"][\s\S]*?<\/svg>/,
  <div className="relative wfull h-[520px] flex items-center justify-center overflow-hidden rounded-2xl">
    <img src="/images/executive_hero.png" alt="Executive" className="w-full h-full object-cover filter contrast-105 brightness-95" />
  </div>'
);

fs.writeFileSync('src/App.tsx', code, 'utf8');
console.log('\u2713 Successfully patched App.tsx!');