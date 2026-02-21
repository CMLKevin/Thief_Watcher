import { NextResponse } from "next/server";

import { setRunning } from "@/lib/watcher";

export const runtime = "nodejs";

export async function POST() {
  const status = await setRunning(true);
  return NextResponse.json({ ok: true, message: "watcher started", status });
}

export async function GET() {
  return POST();
}
