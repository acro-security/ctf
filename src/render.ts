import path from "node:path";
import rehypeMathjax from "rehype-mathjax/svg";
import rehypeShiki from "@shikijs/rehype";
import rehypeStringify from "rehype-stringify";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import { createHighlighter } from "shiki";
import { unified } from "unified";

const THEME = "github-dark";

const LANGUAGES = [
  "bash",
  "lua",
  "python",
  "lisp",
  "typescript",
  "javascript",
  "json",
  "yaml",
  "markdown",
  "http",
  "c",
  "cpp",
  "rust",
  "go",
  "java",
  "sql",
  "diff",
  "nix",
  "ini",
  "html",
  "text",
];

const ALIASES: Record<string, string> = {
  console: "text",
  sh: "bash",
  shell: "bash",
  shellscript: "bash",
  zsh: "bash",
  py: "python",
  cl: "lisp",
  ts: "typescript",
  js: "javascript",
  md: "markdown",
  yml: "yaml",
  rs: "rust",
};

const EXTENSIONS: Record<string, string> = {
  bash: "bash",
  sh: "bash",
  zsh: "bash",
  lua: "lua",
  py: "python",
  lisp: "lisp",
  cl: "lisp",
  ts: "typescript",
  js: "javascript",
  json: "json",
  yaml: "yaml",
  yml: "yaml",
  md: "markdown",
  http: "http",
  c: "c",
  h: "c",
  cpp: "cpp",
  cc: "cpp",
  hpp: "cpp",
  rs: "rust",
  go: "go",
  java: "java",
  sql: "sql",
  diff: "diff",
  patch: "diff",
  nix: "nix",
  ini: "ini",
  html: "html",
};

export interface Renderer {
  code(source: string, language: string): string;
  markdown(source: string): Promise<string>;
  languageForPath(file: string): string;
}

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    return HTML_ESCAPES[character] ?? character;
  });
}

function normalizeLanguage(language: string, loaded: Set<string>): string {
  const normalized = language.trim().toLowerCase().replace(/^language-/, "");
  const mapped = ALIASES[normalized] ?? normalized;
  return loaded.has(mapped) ? mapped : "text";
}

export async function createRenderer(): Promise<Renderer> {
  const highlighter = await createHighlighter({
    themes: [THEME],
    langs: LANGUAGES,
  });

  const loaded = new Set(highlighter.getLoadedLanguages());
  const languageForPath = (file: string): string => {
    const extension = path.extname(file).slice(1).toLowerCase();
    return normalizeLanguage(EXTENSIONS[extension] ?? extension, loaded);
  };

  const markdown = unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkMath)
    .use(remarkRehype)
    .use(rehypeMathjax, {
      svg: {
        fontCache: "local",
      },
    })
    .use(rehypeShiki, {
      theme: THEME,
      defaultLanguage: "text",
      fallbackLanguage: "text",
    })
    .use(rehypeStringify);

  return {
    code(source, language) {
      return highlighter.codeToHtml(source, {
        lang: normalizeLanguage(language, loaded),
        theme: THEME,
      });
    },
    async markdown(source) {
      return String(await markdown.process(source));
    },
    languageForPath,
  };
}

export interface PageLinks {
  homeHref?: string;
  rawHref?: string;
}

export function renderPage(
  title: string,
  relativePath: string,
  body: string,
  links: PageLinks = {},
): string {
  const homeHref = links.homeHref ?? "/";
  const rawHref = links.rawHref ?? `/file?path=${encodeURIComponent(relativePath)}`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1c2024;
      --muted: #667085;
      --border: #d8dde3;
      --accent: #2f6feb;
      --chip: #eef1f5;
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0f1115;
        --panel: #171a21;
        --text: #e6e8ec;
        --muted: #9aa4b2;
        --border: #2a2f3a;
        --accent: #7aa2ff;
        --chip: #222733;
      }
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 16px/1.65 system-ui, -apple-system, "Segoe UI", sans-serif;
    }

    header, main {
      max-width: 960px;
      margin: 0 auto;
      padding: 24px 24px 0;
    }

    main { padding-top: 16px; padding-bottom: 64px; }

    a { color: var(--accent); }

    .top {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
    }

    .top h1 {
      margin: 0;
      font-size: 1.35rem;
      letter-spacing: -.02em;
    }

    .nav {
      display: flex;
      gap: 14px;
      font-size: .9rem;
    }

    .path {
      margin: 6px 0 0;
      color: var(--muted);
      font: .85rem ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }

    .markdown h1,
    .markdown h2,
    .markdown h3 {
      margin-top: 1.6em;
      margin-bottom: .5em;
      line-height: 1.25;
    }

    .markdown h1:first-child,
    .markdown h2:first-child,
    .markdown h3:first-child {
      margin-top: 0;
    }

    .markdown code:not(pre code) {
      padding: 2px 5px;
      border-radius: 5px;
      background: var(--chip);
      font-size: .9em;
    }

    .markdown table {
      display: block;
      width: 100%;
      overflow: auto;
      border-collapse: collapse;
    }

    .markdown th,
    .markdown td {
      padding: 6px 10px;
      border: 1px solid var(--border);
    }

    .markdown blockquote {
      margin: 1em 0;
      padding-left: 14px;
      border-left: 3px solid var(--border);
      color: var(--muted);
    }

    .markdown mjx-container[jax="SVG"] {
      max-width: 100%;
    }

    .markdown mjx-container[display="true"] {
      display: block;
      margin: .8em 0;
      overflow-x: auto;
      text-align: center;
    }

    .markdown mjx-container[jax="SVG"] svg {
      max-width: 100%;
    }

    .code .shiki,
    .markdown .shiki {
      margin: 1em 0;
      padding: 16px;
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: auto;
      font: .88rem/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .code .shiki code,
    .markdown .shiki code {
      font: inherit;
    }
  </style>
</head>
<body>
  <header>
    <div class="top">
      <h1>${escapeHtml(title)}</h1>
      <nav class="nav">
        <a href="${escapeHtml(homeHref)}">← search</a>
        <a href="${escapeHtml(rawHref)}" target="_blank" rel="noreferrer">raw</a>
      </nav>
    </div>
    <p class="path">${escapeHtml(relativePath)}</p>
  </header>
  <main>${body}</main>
</body>
</html>`;
}
