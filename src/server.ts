import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadChallenges } from "./metadata";
import { createRenderer, renderPage } from "./render";
import type { IndexPayload } from "./types";

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SRC_DIR, "..");
const INDEX_PATH = path.join(SRC_DIR, "index.html");
const CLIENT_PATH = path.join(SRC_DIR, "client.ts");

const index = await loadChallenges(REPO_ROOT);
const renderer = await createRenderer();
const payload: IndexPayload = {
  challenges: index.challenges,
  facets: index.facets,
};
const payloadJson = JSON.stringify(payload);
const indexHtml = await Bun.file(INDEX_PATH).text();

const transpiler = new Bun.Transpiler({ loader: "ts" });
const clientJs = transpiler.transformSync(await Bun.file(CLIENT_PATH).text());

const hostname = process.env.HOST ?? "127.0.0.1";
const port = Number(process.env.PORT ?? 8099);

function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

const server = Bun.serve({
  hostname,
  port,
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return htmlResponse(indexHtml);
    }

    if (url.pathname === "/app.js") {
      return new Response(clientJs, {
        headers: {
          "Content-Type": "text/javascript; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }

    if (url.pathname === "/api/challenges" || url.pathname === "/challenges.json") {
      return new Response(payloadJson, {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }

    if (url.pathname === "/poc" || url.pathname === "/writeup") {
      const relative = url.searchParams.get("path");
      if (!relative) return textResponse("missing path", 400);

      const absolute = index.allowedFiles.get(relative);
      if (!absolute) return textResponse("not found", 404);

      const file = Bun.file(absolute);
      if (!(await file.exists())) return textResponse("not found", 404);

      const source = await file.text();
      const challenge = index.challenges.find((item) => {
        return item.path === relative || item.writeup?.split("#")[0] === relative;
      });
      const title = challenge?.title ?? path.basename(relative);

      if (url.pathname === "/poc") {
        const language = renderer.languageForPath(absolute);
        const body = `<section class="code">${renderer.code(source, language)}</section>`;
        return htmlResponse(renderPage(title, relative, body));
      }

      const body = `<article class="markdown">${await renderer.markdown(source)}</article>`;
      return htmlResponse(renderPage(title, relative, body));
    }

    if (url.pathname === "/file") {
      const relative = url.searchParams.get("path");
      if (!relative) return textResponse("missing path", 400);

      const absolute = index.allowedFiles.get(relative);
      if (!absolute) return textResponse("not found", 404);

      const file = Bun.file(absolute);
      if (!(await file.exists())) return textResponse("not found", 404);

      return new Response(file, {
        headers: {
          "Content-Type": file.type || "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }

    return textResponse("not found", 404);
  },
});

console.log(`Serving challenge search on http://${hostname}:${server.port}`);
console.log(`Indexed ${index.challenges.length} challenges from challenges.yaml files`);
