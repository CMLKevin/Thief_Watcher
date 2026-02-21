import { NextResponse } from "next/server";

import { ensureState } from "@/lib/watcher";

export const runtime = "nodejs";

export async function GET() {
  const state = await ensureState();
  return NextResponse.json({
    ok: true,
    service: "thief_watcher_next",
    running: state.running,
  });
}
