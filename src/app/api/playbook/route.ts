import { NextResponse } from "next/server";

import { recoveryPlaybook } from "@/lib/watcher";

export const runtime = "nodejs";

export async function GET() {
  try {
    const playbook = await recoveryPlaybook();
    return NextResponse.json({ ok: true, playbook });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
