import type { Finding, ServiceContext, Triage } from "./types";

export type Bucket = Triage["final_bucket"];
export type Counts = Record<Bucket, number>;

export interface Summary {
  findings: number;
  cvss_ge_7: number;
  rule: Counts;
  final: Counts;
  needs_review: number;
  verified: number;
}

export interface RunListItem {
  id: string;
  name: string;
  summary: Summary;
  stages: string[];
}

export interface Item {
  finding: Finding;
  triage: Triage;
}

export interface RunDetail {
  id: string;
  meta: {
    name: string;
    sbom_source: string;
    context: ServiceContext;
    coverage: { components: number; epss_pct: number; kev_feed: boolean; kev_hits: number; unsupported?: Record<string, number> };
    summary: Summary;
    stages: string[];
    llm?: {
      provider: string;
      model: string | null;
      mode?: "single" | "two_stage";
      code_reader?: { provider: string; model: string | null } | null;
    } | null;
  };
  items: Item[];
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const listRuns = () => get<RunListItem[]>("/api/runs");
export const getRun = (id: string) => get<RunDetail>(`/api/runs/${encodeURIComponent(id)}`);
