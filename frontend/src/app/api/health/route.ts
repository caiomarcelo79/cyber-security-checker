import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    status: "UP",
    service: "cyber-security-checker-frontend",
    timestamp: new Date().toISOString(),
  });
}
