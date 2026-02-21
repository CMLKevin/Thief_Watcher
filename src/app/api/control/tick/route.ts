import { NextResponse } from "next/server";

import { manualTick } from "@/lib/watcher";

export const runtime = "nodejs";

export async function POST() {
  try {
    const status = await manualTick();
    return NextResponse.json({ ok: true, message: "manual tick completed", status });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 400 },
    );
  }
}

export async function GET() {
  return POST();
}
