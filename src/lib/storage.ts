import fs from "node:fs/promises";

import { DATA_DIR, STATE_FILE, TAGS_FILE } from "@/lib/constants";
import type { AddressLabel, WatchState } from "@/lib/types";
import { ensureDir } from "@/lib/utils";

const lockMap = new Map<string, Promise<void>>();

async function withFileLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = lockMap.get(key) || Promise.resolve();
  let release!: () => void;
  const next = new Promise<void>((resolve) => {
    release = resolve;
  });
  lockMap.set(key, previous.then(() => next));
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (lockMap.get(key) === next) {
      lockMap.delete(key);
    }
  }
}

async function readJsonFile<T>(path: string, fallback: T): Promise<T> {
  try {
    const buf = await fs.readFile(path, "utf8");
    return JSON.parse(buf) as T;
  } catch {
    return fallback;
  }
}

async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await ensureDir(path);
  await fs.writeFile(path, JSON.stringify(value, null, 2), "utf8");
}

export async function readState(fallback: WatchState): Promise<WatchState> {
  await ensureDir(DATA_DIR, true);
  return readJsonFile(STATE_FILE, fallback);
}

export async function writeState(value: WatchState): Promise<void> {
  await withFileLock(STATE_FILE, async () => {
    await writeJsonFile(STATE_FILE, value);
  });
}

export async function readCustomTags(): Promise<Record<string, Partial<AddressLabel>>> {
  await ensureDir(DATA_DIR, true);
  return readJsonFile(TAGS_FILE, {});
}

export async function writeCustomTags(tags: Record<string, Partial<AddressLabel>>): Promise<void> {
  await withFileLock(TAGS_FILE, async () => {
    await writeJsonFile(TAGS_FILE, tags);
  });
}
