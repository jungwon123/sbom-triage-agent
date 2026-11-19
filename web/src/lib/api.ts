import type { CombinedCheck, Decision, Finding, Job, Proposal, ServiceContext, Triage } from "./types";

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

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().then((d) => d?.detail).catch(() => null);
    throw new Error(typeof detail === "string" ? detail : `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export interface ExportResult {
  approved: string[];
  files: string[];
  dir: string;
  pr_draft: string | null;
  combined: CombinedCheck | null;
  combined_skipped: string | null;
}

const base = (id: string) => `/api/runs/${encodeURIComponent(id)}`;
export const getProposals = (id: string) => get<Proposal[]>(`${base(id)}/proposals`);
export const patchUrl = (id: string, target: string) => `${base(id)}/patch?target=${encodeURIComponent(target)}`;
export const decide = (id: string, body: { target: string; status: Decision["status"]; by: string; reason: string }) =>
  post<Decision>(`${base(id)}/decisions`, body);
export const exportApproved = (id: string) => post<ExportResult>(`${base(id)}/export`);
export type ExportJob = Omit<Job, "result"> & { result?: ExportResult | null };
export const startExportTogether = (id: string) => post<ExportJob>(`${base(id)}/export/together`);
export const getJob = (id: string, jobId: string) => get<ExportJob>(`${base(id)}/jobs/${encodeURIComponent(jobId)}`);
export const latestExportJob = (id: string) => get<ExportJob | null>(`${base(id)}/jobs/latest?kind=export_together`);
export const listRuns = () => get<RunListItem[]>("/api/runs");
export const getRun = (id: string) => get<RunDetail>(`/api/runs/${encodeURIComponent(id)}`);
