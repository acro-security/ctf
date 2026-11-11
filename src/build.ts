import path from "node:path";
import { fileURLToPath } from "node:url";
import { copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import { loadChallenges } from "./metadata";
import { createRenderer, renderPage } from "./render";
import type { Challenge, IndexPayload } from "./types";

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SRC_DIR, "..");
const DIST_DIR = path.join(REPO_ROOT, "dist");
const INDEX_PATH = path.join(SRC_DIR, "index.html");
const CLIENT_PATH = path.join(SRC_DIR, "client.ts");

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function pageSlug(relative: string): string {
  const parsed = path.parse(relative);
  return `${slug(parsed.name)}-${Bun.hash(relative).toString(36)}`;
}

function writeupPath(challenge: Challenge): string | undefined {
  return challenge.writeup?.split("#")[0];
}

async function build(): Promise<void> {
  await rm(DIST_DIR, { recursive: true, force: true });
  await mkdir(DIST_DIR, { recursive: true });

  const index = await loadChallenges(REPO_ROOT);
  const renderer = await createRenderer();

  const pocPages = new Map<string, string>();
  const writeupPages = new Map<string, string>();

  for (const challenge of index.challenges) {
    if (challenge.path) {
      pocPages.set(challenge.path, pageSlug(challenge.path));
    }

    const writeup = writeupPath(challenge);
    if (writeup) {
      writeupPages.set(writeup, pageSlug(writeup));
    }
  }

  const staticChallenges = index.challenges.map((challenge) => {
    const writeup = writeupPath(challenge);
    return {
      ...challenge,
      pathUrl: challenge.path
        ? `./poc/${pocPages.get(challenge.path)}.html`
        : undefined,
      writeupUrl: writeup
        ? `./writeup/${writeupPages.get(writeup)}.html`
        : undefined,
    };
  });

  const payload: IndexPayload = {
    challenges: staticChallenges,
    facets: index.facets,
  };
  await writeFile(
    path.join(DIST_DIR, "challenges.json"),
    JSON.stringify(payload),
    "utf8",
  );

  await copyFile(INDEX_PATH, path.join(DIST_DIR, "index.html"));

  const transpiler = new Bun.Transpiler({ loader: "ts" });
  const clientJs = transpiler.transformSync(await Bun.file(CLIENT_PATH).text());
  await writeFile(path.join(DIST_DIR, "app.js"), clientJs, "utf8");
  await writeFile(path.join(DIST_DIR, ".nojekyll"), "", "utf8");

  await mkdir(path.join(DIST_DIR, "poc"), { recursive: true });
  for (const [relative, slugValue] of pocPages) {
    const absolute = index.allowedFiles.get(relative) ?? path.join(REPO_ROOT, relative);
    const source = await Bun.file(absolute).text();
    const challenge = index.challenges.find((item) => item.path === relative);
    const title = challenge?.title ?? path.basename(relative);
    const language = renderer.languageForPath(absolute);
    const body = `<section class="code">${renderer.code(source, language)}</section>`;
    const html = renderPage(title, relative, body, {
      homeHref: "../index.html",
      rawHref: `../raw/${encodeURI(relative)}`,
    });
    await writeFile(path.join(DIST_DIR, "poc", `${slugValue}.html`), html, "utf8");
  }

  await mkdir(path.join(DIST_DIR, "writeup"), { recursive: true });
  for (const [relative, slugValue] of writeupPages) {
    const absolute = index.allowedFiles.get(relative) ?? path.join(REPO_ROOT, relative);
    const source = await Bun.file(absolute).text();
    const challenge = index.challenges.find((item) => writeupPath(item) === relative);
    const title = challenge ? `${challenge.event} — Writeup` : path.basename(relative);
    const body = `<article class="markdown">${await renderer.markdown(source)}</article>`;
    const html = renderPage(title, relative, body, {
      homeHref: "../index.html",
      rawHref: `../raw/${encodeURI(relative)}`,
    });
    await writeFile(path.join(DIST_DIR, "writeup", `${slugValue}.html`), html, "utf8");
  }

  for (const [relative, absolute] of index.allowedFiles) {
    const destination = path.join(DIST_DIR, "raw", relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(absolute, destination);
  }

  console.log(`Built ${staticChallenges.length} challenges into ${DIST_DIR}`);
  console.log(`  ${pocPages.size} PoC pages, ${writeupPages.size} writeup pages`);
}

await build();
