import { NextRequest, NextResponse } from "next/server";

import { buildTraceGraph, normalizeSeeds } from "@/lib/watcher";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Record<string, unknown>;
    const seeds = normalizeSeeds(body.seeds);
    if (!seeds.length) {
      return NextResponse.json(
        { ok: false, error: "Provide at least one valid seed address" },
        { status: 400 },
      );
    }

    const graph = await buildTraceGraph({
      seeds,
      hops: Number(body.hops || 2),
      maxEdges: Number(body.maxEdges || body.max_edges || 900),
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

    return NextResponse.json({ ok: true, graph });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 500 },
    );
  }
}
