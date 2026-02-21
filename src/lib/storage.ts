import fs from "node:fs/promises";
import { Redis } from "@upstash/redis";

import { DATA_DIR, STATE_FILE, TAGS_FILE } from "@/lib/constants";
import type { AddressLabel, WatchState } from "@/lib/types";
import { ensureDir } from "@/lib/utils";

const lockMap = new Map<string, Promise<void>>();
const REDIS_PREFIX = process.env.THIEF_WATCHER_REDIS_PREFIX || "thief_watcher";
const REDIS_STATE_KEY = `${REDIS_PREFIX}:state`;
const REDIS_TAGS_KEY = `${REDIS_PREFIX}:custom_tags`;

let redisClient: Redis | null | undefined;

function getRedisClient(): Redis | null {
  if (redisClient !== undefined) {
    return redisClient;
  }

  const url = process.env.UPSTASH_REDIS_REST_URL?.trim();
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  if (!url || !token) {
    redisClient = null;
    return redisClient;
  }

  redisClient = new Redis({ url, token });
  return redisClient;
}

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

async function readJsonRedis<T>(key: string): Promise<T | null> {
  const client = getRedisClient();
  if (!client) return null;

  try {
    const data = await client.get<T>(key);
    if (data === null || data === undefined) return null;
    return data;
  } catch {
    return null;
  }
}

async function writeJsonRedis(key: string, value: unknown): Promise<boolean> {
  const client = getRedisClient();
  if (!client) return false;

  try {
    await client.set(key, value);
    return true;
  } catch {
    return false;
  }
}

export async function readState(fallback: WatchState): Promise<WatchState> {
  await ensureDir(DATA_DIR, true);
  const fromRedis = await readJsonRedis<WatchState>(REDIS_STATE_KEY);
  if (fromRedis && typeof fromRedis === "object") {
    return fromRedis;
  }

  const fromFile = await readJsonFile(STATE_FILE, fallback);
  void writeJsonRedis(REDIS_STATE_KEY, fromFile);
  return fromFile;
}

export async function writeState(value: WatchState): Promise<void> {
  const persistedRedis = await writeJsonRedis(REDIS_STATE_KEY, value);
  await withFileLock(STATE_FILE, async () => {
    // Always persist local copy for local development and fallback recovery.
    await writeJsonFile(STATE_FILE, value);
  });
  if (!persistedRedis && getRedisClient()) {
    // Redis configured but unreachable: rely on file fallback only.
  }
}

export async function readCustomTags(): Promise<Record<string, Partial<AddressLabel>>> {
  await ensureDir(DATA_DIR, true);
  const fromRedis =
    await readJsonRedis<Record<string, Partial<AddressLabel>>>(REDIS_TAGS_KEY);
  if (fromRedis && typeof fromRedis === "object") {
    return fromRedis;
  }

  const fromFile = await readJsonFile<Record<string, Partial<AddressLabel>>>(
    TAGS_FILE,
    {},
  );
  void writeJsonRedis(REDIS_TAGS_KEY, fromFile);
  return fromFile;
}

export async function writeCustomTags(tags: Record<string, Partial<AddressLabel>>): Promise<void> {
  await writeJsonRedis(REDIS_TAGS_KEY, tags);
  await withFileLock(TAGS_FILE, async () => {
    await writeJsonFile(TAGS_FILE, tags);
  });
}
