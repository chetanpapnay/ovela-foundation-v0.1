const fs = require('fs');

// 1. Fix src/App.tsx
fs.writeFileSync('src/App.tsx', "import { OvelaConsole } from './jurix/OvelaConsole';\n\nexport function App() {\n  return <OvelaConsole />;\n}\n\nexport default App;\n", 'utf8');

// 2. Fix src/jurix/OvelaConsole.tsx
let code = fs.readFileSync('src/jurix/OvelaConsole.tsx', 'utf8');
code = code.replace(
  'import { JurixPresentationPlan } from "./types/presentation";',
  'import type { JurixPresentationPlan } from "./types/presentation";'
);
fs.writeFileSync('src/jurix/OvelaConsole.tsx', code, 'utf8');

console.log('✓ Successfully patched App.tsx and OvelaConsole.tsx');
