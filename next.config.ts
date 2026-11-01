import type { NextConfig } from "next";
const config: NextConfig = {
  env: {
    NEXT_PUBLIC_GUARDIAN_CLOUD_MODE: process.env.GUARDIAN_CLOUD_MODE || "false",
  },
  async redirects() {
    return process.env.GUARDIAN_CLOUD_MODE === "true"
      ? [{ source: "/", destination: "/account", permanent: false }]
      : [];
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.GUARDIAN_API_URL || "http://127.0.0.1:8000"}/api/:path*`,
      },
    ];
  },
};
export default config;
