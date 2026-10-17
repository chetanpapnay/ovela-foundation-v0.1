/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        stage: {
          dark: "#030508",
          card: "#080d16",
        }
      }
    },
  },
  plugins: [],
};
