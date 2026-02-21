import { NextRequest, NextResponse } from "next/server";

import { generateEscalationPacket, normalizeSeeds } from "@/lib/watcher";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Record<string, unknown>;
    const packet = await generateEscalationPacket({
      caseId: String(body.caseId || body.case_id || "").trim() || undefined,
      analyst: String(body.analyst || "").trim() || undefined,
      cexName: String(body.cexName || body.cex_name || "").trim() || undefined,
      notes: String(body.notes || "").trim() || undefined,
      victimWallet:
        String(body.victimWallet || body.victim_wallet || "").trim() || undefined,
      suspectWallet:
        String(body.suspectWallet || body.suspect_wallet || "").trim() || undefined,
      seeds: normalizeSeeds(body.seeds),
      window: Number(body.window || 20000),
      hops: Number(body.hops || 2),
      maxEdges: Number(body.maxEdges || body.max_edges || 1200),
      fromBlock:
        body.fromBlock !== undefined
          ? Number(body.fromBlock)
          : body.from_block !== undefined
            ? Number(body.from_block)
            : undefined,
      toBlock:
        body.toBlock !== undefined
          ? Number(body.toBlock)
          : body.to_block !== undefined
            ? Number(body.to_block)
            : undefined,
    });

    return NextResponse.json({ ok: true, ...packet });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
