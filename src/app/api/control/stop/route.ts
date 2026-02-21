import { NextResponse } from "next/server";

import { setRunning } from "@/lib/watcher";

export const runtime = "nodejs";

export async function POST() {
  const status = await setRunning(false);
  return NextResponse.json({ ok: true, message: "watcher stopped", status });
}

export async function GET() {
  return POST();
}
