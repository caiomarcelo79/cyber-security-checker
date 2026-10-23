import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#090D16",
          panel: "#111827",
          border: "#1F2937",
          accent: "#0EA5E9",
          emerald: "#10B981",
        },
        severity: {
          critical: "#EF4444",
          high: "#F97316",
          medium: "#EAB308",
          low: "#3B82F6",
          info: "#64748B",
        },
      },
    },
  },
  plugins: [],
};

export default config;
