import { NextRequest, NextResponse } from "next/server";

import { filterEvents } from "@/lib/watcher";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  try {
    const p = req.nextUrl.searchParams;
    const result = await filterEvents({
      limit: Number(p.get("limit") || 150),
      severity: p.get("severity") || "",
      direction: p.get("direction") || "",
      token: p.get("token") || "",
      q: p.get("q") || "",
    });

    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
