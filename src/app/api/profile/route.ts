import { NextRequest, NextResponse } from "next/server";

import { profileAddress } from "@/lib/watcher";

export const runtime = "nodejs";
export const maxDuration = 60;

async function run(addressRaw: string, windowRaw: unknown) {
  const address = String(addressRaw || "").trim();
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return NextResponse.json(
      { ok: false, error: "Address must be a valid 0x-prefixed 40-byte address" },
      { status: 400 },
    );
  }

  const window = Math.max(500, Math.min(250000, Number(windowRaw || 50000)));
  const profile = await profileAddress(address, window);
  return NextResponse.json({ ok: true, profile });
}

export async function GET(req: NextRequest) {
  try {
    const p = req.nextUrl.searchParams;
    return await run(p.get("address") || "", p.get("window") || "50000");
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Record<string, unknown>;
    return await run(String(body.address || ""), body.window);
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 400 },
    );
  }
}
