import { NextResponse } from "next/server";

import { listTags, refreshState } from "@/lib/watcher";

export const runtime = "nodejs";

export async function GET() {
  try {
    const state = await refreshState();
    const tags = await listTags();
    return NextResponse.json({ ok: true, state, tags });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
