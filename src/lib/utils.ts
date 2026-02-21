import fs from "node:fs/promises";
import path from "node:path";

export const nowIso = (): string =>
  new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

export const normalizeAddress = (value: string): string =>
  `0x${value.toLowerCase().replace(/^0x/, "")}`;

export const isHexAddress = (value: string): boolean =>
  /^0x[a-fA-F0-9]{40}$/.test(value || "");

export const addrTopic = (address: string): string =>
  `0x${"0".repeat(24)}${normalizeAddress(address).slice(2)}`;

export const fromTopicAddress = (topic: string): string =>
  normalizeAddress(`0x${topic.slice(-40)}`);

export const toBigInt = (hex: string): bigint => BigInt(hex || "0x0");

export const toInt = (hex: string): number => Number(toBigInt(hex));

export const toFloatSafe = (v: unknown, fallback = 0): number => {
  const parsed = Number(v);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const clamp = (
  value: unknown,
  minimum: number,
  maximum: number,
  fallback: number,
): number => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
};

export const dedupe = <T>(items: T[]): T[] => [...new Set(items)];

export const safeSlug = (raw: string, fallback = "case"): string => {
  const cleaned = (raw || "").trim().replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^[-._]+|[-._]+$/g, "");
  return cleaned ? cleaned.slice(0, 120) : fallback;
};

export async function ensureDir(filePathOrDir: string, treatAsDir = false): Promise<void> {
  const dir = treatAsDir ? filePathOrDir : path.dirname(filePathOrDir);
  await fs.mkdir(dir, { recursive: true });
}
