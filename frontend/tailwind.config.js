/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        critical:   { DEFAULT: "#ef4444", fg: "#ffffff" },
        malicious:  { DEFAULT: "#f97316", fg: "#ffffff" },
        suspicious: { DEFAULT: "#eab308", fg: "#000000" },
        clean:      { DEFAULT: "#22c55e", fg: "#ffffff" },
      },
      keyframes: {
        fadeSlideIn: {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        radarSweep: {
          "0%":   { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        radarPing: {
          "0%":   { transform: "scale(1)",   opacity: "0.6" },
          "100%": { transform: "scale(2.2)", opacity: "0" },
        },
        scanLine: {
          "0%":   { transform: "translateY(0%)",   opacity: "0" },
          "10%":  { opacity: "1" },
          "90%":  { opacity: "1" },
          "100%": { transform: "translateY(600%)", opacity: "0" },
        },
        terminalDot: {
          "0%, 80%, 100%": { opacity: "0" },
          "40%":           { opacity: "1" },
        },
        borderPulse: {
          "0%, 100%": { opacity: "1" },
          "50%":      { opacity: "0.4" },
        },
      },
      animation: {
        fadeSlideIn:  "fadeSlideIn 0.4s ease forwards",
        radarSweep:   "radarSweep 3s linear infinite",
        radarPing:    "radarPing 2s ease-out infinite",
        scanLine:     "scanLine 2s ease-in-out infinite",
        terminalDot:  "terminalDot 1.4s ease-in-out infinite",
        borderPulse:  "borderPulse 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
