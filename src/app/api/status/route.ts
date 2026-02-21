import { NextResponse } from "next/server";

import { statusWithIntel } from "@/lib/watcher";

export const runtime = "nodejs";

export async function GET() {
  try {
    const data = await statusWithIntel();
    return NextResponse.json({ ok: true, ...data });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
