import type { Challenge, Facets, IndexPayload } from "./types";

type TagMode = "all" | "any";

interface State {
  q: string;
  category: string;
  tags: Set<string>;
  mode: TagMode;
}

const state: State = {
  q: "",
  category: "",
  tags: new Set<string>(),
  mode: "all",
};

let all: Challenge[] = [];
let facets: Facets = { categories: [], tags: [] };

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing #${id}`);
  return element as T;
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

function tagCounts(): Map<string, number> {
  const counts = new Map<string, number>();
  for (const challenge of all) {
    for (const tag of challenge.tags) {
      counts.set(tag, (counts.get(tag) ?? 0) + 1);
    }
  }
  return counts;
}

function renderControls(): void {
  const categorySelect = byId<HTMLSelectElement>("category");
  for (const value of facets.categories) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    categorySelect.appendChild(option);
  }

  const counts = tagCounts();
  const tags = [...counts.entries()].sort((a, b) => {
    return b[1] - a[1] || a[0].localeCompare(b[0]);
  });

  byId<HTMLElement>("tags").innerHTML = tags.map(([tag, count]) => `
    <button class="tag" type="button" data-tag="${escapeHtml(tag)}" aria-pressed="${state.tags.has(tag)}">
      ${escapeHtml(tag)}<span class="count">${count}</span>
    </button>
  `).join("");
}

function matches(challenge: Challenge): boolean {
  const haystack = [
    challenge.id,
    challenge.title,
    challenge.event,
    challenge.date,
    challenge.category,
    challenge.summary,
    ...challenge.tags,
    challenge.path,
    challenge.writeup,
  ].join(" ").toLowerCase();

  if (state.q && !haystack.includes(state.q)) return false;
  if (state.category && challenge.category !== state.category) return false;

  if (state.tags.size) {
    const tags = new Set(challenge.tags);
    const selected = [...state.tags];
    const hit = state.mode === "all"
      ? selected.every((tag) => tags.has(tag))
      : selected.some((tag) => tags.has(tag));
    if (!hit) return false;
  }

  return true;
}

function renderResults(): void {
  const found = all.filter(matches);
  const suffix = all.length === 1 ? "" : "s";
  byId<HTMLElement>("status").textContent = `${found.length} of ${all.length} challenge${suffix}`;

  if (!found.length) {
    byId<HTMLElement>("results").innerHTML = '<p class="empty">No matching challenges.</p>';
    return;
  }

  byId<HTMLElement>("results").innerHTML = found.map((challenge) => {
    const links: string[] = [];
    if (challenge.pathUrl) {
      links.push(`<a href="${escapeHtml(challenge.pathUrl)}" target="_blank" rel="noreferrer">solver / poc</a>`);
    }
    if (challenge.writeupUrl) {
      links.push(`<a href="${escapeHtml(challenge.writeupUrl)}" target="_blank" rel="noreferrer">writeup</a>`);
    }

    const meta = [challenge.event, challenge.date].filter(Boolean).join(" · ");
    const tags = challenge.tags
      .map((tag) => `<span>${escapeHtml(tag)}</span>`)
      .join("");

    return `
      <article class="card">
        <div class="card-head">
          <h2>${escapeHtml(challenge.title)}</h2>
          <span class="badge">${escapeHtml(challenge.category)}</span>
        </div>
        ${meta ? `<p class="meta">${escapeHtml(meta)}</p>` : ""}
        ${challenge.summary ? `<p class="summary">${escapeHtml(challenge.summary)}</p>` : ""}
        <div class="card-tags">${tags}</div>
        <p class="links">${links.join("")}<code>${escapeHtml(challenge.path ?? "")}</code></p>
      </article>
    `;
  }).join("");
}

function bind(): void {
  byId<HTMLInputElement>("q").addEventListener("input", (event) => {
    state.q = (event.target as HTMLInputElement).value.trim().toLowerCase();
    renderResults();
  });

  byId<HTMLSelectElement>("category").addEventListener("change", (event) => {
    state.category = (event.target as HTMLSelectElement).value;
    renderResults();
  });

  byId<HTMLSelectElement>("mode").addEventListener("change", (event) => {
    state.mode = (event.target as HTMLSelectElement).value === "any" ? "any" : "all";
    renderResults();
  });

  byId<HTMLElement>("tags").addEventListener("click", (event) => {
    const button = (event.target as HTMLElement).closest("button[data-tag]") as HTMLButtonElement | null;
    if (!button) return;

    const tag = button.dataset.tag;
    if (!tag) return;

    if (state.tags.has(tag)) {
      state.tags.delete(tag);
    } else {
      state.tags.add(tag);
    }

    button.setAttribute("aria-pressed", String(state.tags.has(tag)));
    renderResults();
  });
}

async function init(): Promise<void> {
  bind();

  try {
    const response = await fetch("./challenges.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = (await response.json()) as IndexPayload;
    all = data.challenges;
    facets = data.facets;

    renderControls();
    renderResults();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    byId<HTMLElement>("status").textContent = `Failed to load index: ${message}`;
  }
}

void init();
