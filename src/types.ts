export interface ChallengeMeta {
  id?: string;
  title: string;
  category?: string;
  tags?: string[];
  summary?: string;
  event?: string;
  date?: string;
  path?: string;
  writeup?: string;
  difficulty?: string;
}

export interface FolderMeta {
  event?: string;
  date?: string;
  challenges: ChallengeMeta[];
}

export interface Challenge {
  id: string;
  title: string;
  event: string;
  date?: string;
  category: string;
  tags: string[];
  summary?: string;
  sourceDir: string;
  path?: string;
  writeup?: string;
  pathUrl?: string;
  writeupUrl?: string;
  difficulty?: string;
}

export interface Facets {
  categories: string[];
  tags: string[];
  difficulties: string[];
}

export interface IndexPayload {
  challenges: Challenge[];
  facets: Facets;
}
