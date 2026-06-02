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
      },
      animation: {
        fadeSlideIn: "fadeSlideIn 0.4s ease forwards",
      },
    },
  },
  plugins: [],
};
