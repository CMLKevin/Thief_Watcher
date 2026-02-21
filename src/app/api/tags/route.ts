import { NextRequest, NextResponse } from "next/server";

import { addCustomTag, listTags } from "@/lib/watcher";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const q = (p.get("q") || "").toLowerCase();
  const type = (p.get("type") || "").toLowerCase();

  const tags = await listTags();
  const rows = Object.entries(tags)
    .map(([address, label]) => ({
      address,
      ...label,
    }))
    .filter((row) => {
      if (type && String(row.type || "").toLowerCase() !== type) return false;
      if (!q) return true;
      const blob = `${row.address} ${row.label || ""} ${row.notes || ""}`.toLowerCase();
      return blob.includes(q);
    })
    .sort((a, b) =>
      `${a.type || ""}:${a.label || ""}:${a.address}`.localeCompare(
        `${b.type || ""}:${b.label || ""}:${b.address}`,
      ),
    );

  return NextResponse.json({
    ok: true,
    count: rows.length,
    tags: rows,
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Record<string, unknown>;
    const address = String(body.address || "").trim();
    const label = String(body.label || "").trim();
    const type = String(body.type || "custom").trim().toLowerCase();
    const notes = String(body.notes || "").trim();
    const source = String(body.source || "manual").trim();

    if (!address || !label) {
      return NextResponse.json(
        { ok: false, error: "Fields `address` and `label` are required" },
        { status: 400 },
      );
    }

    await addCustomTag({ address, label, type, notes, source });
    return NextResponse.json({ ok: true, message: "tag added" });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: String(error) },
      { status: 400 },
    );
  }
}
