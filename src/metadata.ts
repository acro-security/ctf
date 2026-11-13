import path from "node:path";
import { Glob } from "bun";
import { parse as parseYaml } from "yaml";
import type { Challenge, Facets, IndexPayload } from "./types";

const IGNORED_DIRS = new Set([".git", "node_modules", "dist", "src"]);
const METADATA_GLOB = "**/challenges.{yaml,yml}";

interface LoadedIndex extends IndexPayload {
  allowedFiles: Map<string, string>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function toPosix(value: string): string {
  return value.replaceAll("\\", "/");
}

const DIFFICULTY_ORDER = ["trivial", "easy", "moderate", "hard", "brutal"];

function sortDifficulties(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => {
    const ai = DIFFICULTY_ORDER.indexOf(a);
    const bi = DIFFICULTY_ORDER.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
}

function isInside(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function metadataFiles(repoRoot: string): Promise<string[]> {
  const glob = new Glob(METADATA_GLOB);
  const found: string[] = [];

  for await (const relative of glob.scan({ cwd: repoRoot, onlyFiles: true, dot: false })) {
    const normalized = toPosix(relative);
    if (normalized.split("/").some((part) => IGNORED_DIRS.has(part))) continue;
    found.push(normalized);
  }

  return found.sort();
}

export async function loadChallenges(repoRoot: string): Promise<LoadedIndex> {
  const challenges: Challenge[] = [];
  const allowedFiles = new Map<string, string>();

  for (const metadataRelative of await metadataFiles(repoRoot)) {
    const metadataPath = path.join(repoRoot, metadataRelative);
    const sourceDir = path.dirname(metadataPath);
    const sourceDirRelative = toPosix(path.relative(repoRoot, sourceDir));

    let raw: unknown;
    try {
      raw = parseYaml(await Bun.file(metadataPath).text()) as unknown;
    } catch (error) {
      console.warn(`warning: cannot parse ${metadataRelative}: ${String(error)}`);
      continue;
    }

    if (!isRecord(raw) || !Array.isArray(raw.challenges)) {
      console.warn(`warning: ${metadataRelative} has no challenges array`);
      continue;
    }

    const folderEvent = asString(raw.event);
    const folderDate = asString(raw.date);
    const entries = raw.challenges;

    for (const entry of entries) {
      if (!isRecord(entry) || typeof entry.title !== "string") {
        console.warn(`warning: ${metadataRelative} has an entry without a title`);
        continue;
      }

      const challenge: Challenge = {
        id: asString(entry.id) ?? slugify(entry.title) ?? "challenge",
        title: entry.title,
        event: asString(entry.event) ?? folderEvent ?? sourceDirRelative,
        category: asString(entry.category) ?? "misc",
        tags: [...new Set(asStringArray(entry.tags))],
        sourceDir: sourceDirRelative,
      };

      const date = asString(entry.date) ?? folderDate;
      if (date) challenge.date = date;

      const summary = asString(entry.summary);
      if (summary) challenge.summary = summary;

      const difficulty = asString(entry.difficulty);
      if (difficulty) challenge.difficulty = difficulty;

      for (const key of ["path", "writeup"] as const) {
        const value = asString(entry[key]);
        if (!value) continue;

        const hash = value.indexOf("#");
        const filePart = hash === -1 ? value : value.slice(0, hash);
        const anchor = hash === -1 ? "" : value.slice(hash + 1);
        const absolute = path.resolve(sourceDir, filePart);

        if (!isInside(repoRoot, absolute)) {
          console.warn(
            `warning: ${metadataRelative}: ${key} escapes the repository: ${value}`,
          );
          continue;
        }

        const relative = toPosix(path.relative(repoRoot, absolute));
        if (!(await Bun.file(absolute).exists())) {
          console.warn(`warning: ${metadataRelative}: missing ${key}: ${value}`);
        }

        allowedFiles.set(relative, absolute);

        if (key === "path") {
          challenge.path = relative;
          challenge.pathUrl = `/poc?path=${encodeURIComponent(relative)}`;
        } else {
          challenge.writeup = anchor ? `${relative}#${anchor}` : relative;
          challenge.writeupUrl = `/writeup?path=${encodeURIComponent(relative)}`;
        }
      }

      challenges.push(challenge);
    }
  }

  const facets: Facets = {
    categories: [...new Set(challenges.map((challenge) => challenge.category))].sort(),
    tags: [...new Set(challenges.flatMap((challenge) => challenge.tags))].sort(),
    difficulties: sortDifficulties(
      challenges
        .map((challenge) => challenge.difficulty)
        .filter((value): value is string => Boolean(value)),
    ),
  };

  return { challenges, facets, allowedFiles };
}
