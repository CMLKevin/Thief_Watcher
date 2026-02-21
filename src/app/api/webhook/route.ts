import { NextRequest, NextResponse } from "next/server";

import { setWebhook } from "@/lib/watcher";

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Record<string, unknown>;
    const url = String(body.url || "").trim();
    if (url && !/^https?:\/\//i.test(url)) {
      return NextResponse.json(
        { ok: false, error: "Webhook URL must start with http:// or https://" },
        { status: 400 },
      );
    }

    const state = await setWebhook(url || null);
    return NextResponse.json({ ok: true, webhookUrl: state.webhookUrl });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
