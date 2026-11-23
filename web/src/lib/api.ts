import type { Change, CombinedCheck, Decision, Finding, Job, Me, Proposal, Service, ServiceContext, Triage } from "./types";

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
    repo?: string | null;
    sbom_source: string;
    context: ServiceContext;
    coverage: { components: number; epss_pct: number; kev_feed: boolean; kev_hits: number; unsupported?: Record<string, number>; input_notes?: string[]; reported_by_input?: number; only_in_input?: number; osv?: boolean; kev_list?: { catalog_version: string | null; date_released: string | null; count: number } | null };
    summary: Summary;
    stages: string[];
    service?: string;
    previous_run?: string;
    changes?: Change[];
    llm?: {
      provider: string;
      model: string | null;
      mode?: "single" | "two_stage";
      code_reader?: { provider: string; model: string | null } | null;
    } | null;
  };
  items: Item[];
}

/** Fired when the server says the session is gone, so the app can go back to the sign-in screen. */
export const SIGNED_OUT = "triage:signed-out";

async function fail(res: Response): Promise<never> {
  if (res.status === 401) window.dispatchEvent(new Event(SIGNED_OUT));
  const detail = await res.json().then((d) => d?.detail).catch(() => null);
  throw new Error(typeof detail === "string" ? detail : `${res.status} ${res.statusText}`);
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) return fail(res);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) return fail(res);
  return res.json() as Promise<T>;
}

export const getMe = () => get<Me>("/api/me");
export const logout = () => post<{ ok: boolean }>("/auth/logout");
/** Sign-in starts with a full page navigation; the server sends the browser to the identity provider. */
export const loginUrl = () => `/auth/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
export const roleLabel: Record<NonNullable<Me["role"]>, string> = { viewer: "열람", approver: "승인", admin: "관리" };
/** Deciding, exporting and starting sandbox work need the approver role (auth.py). */
export const canDecide = (me: Me) => me.role === "approver" || me.role === "admin";

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
export const decide = (id: string, body: { target: string; status: Decision["status"]; by?: string; reason: string }) =>
  post<Decision>(`${base(id)}/decisions`, body);
export const exportApproved = (id: string) => post<ExportResult>(`${base(id)}/export`);
export type ExportJob = Omit<Job, "result"> & { result?: ExportResult | null };
export const startExportTogether = (id: string) => post<ExportJob>(`${base(id)}/export/together`);
export const getJob = (id: string, jobId: string) => get<ExportJob>(`${base(id)}/jobs/${encodeURIComponent(jobId)}`);
export const latestExportJob = (id: string) => get<ExportJob | null>(`${base(id)}/jobs/latest?kind=export_together`);
export type VerifyJob = Omit<Job, "result"> & { result?: { summary: Summary | null; skipped: string | null } | null };
export const startVerify = (id: string) => post<VerifyJob>(`${base(id)}/verify`);
export const latestVerifyJob = (id: string) => get<VerifyJob | null>(`${base(id)}/jobs/latest?kind=verify`);
export const getVerifyJob = (id: string, jobId: string) => get<VerifyJob>(`${base(id)}/jobs/${encodeURIComponent(jobId)}`);
export type AgentScope = "all" | "changed";
export type AgentJob = Omit<Job, "result"> & {
  result?: { summary: Summary | null; skipped: string | null; judged: number; fallbacks?: number } | null;
};
export const startAgent = (id: string, scope: AgentScope) => post<AgentJob>(`${base(id)}/agent`, { scope });
export const latestAgentJob = (id: string) => get<AgentJob | null>(`${base(id)}/jobs/latest?kind=agent`);
export const getAgentJob = (id: string, jobId: string) => get<AgentJob>(`${base(id)}/jobs/${encodeURIComponent(jobId)}`);
export const listRuns = () => get<RunListItem[]>("/api/runs");
export const getRun = (id: string) => get<RunDetail>(`/api/runs/${encodeURIComponent(id)}`);

/** A registered service with its current run's counts and the check in progress, if any. */
export type ServiceRow = Service & { summary: Summary | null; job: Omit<Job, "result" | "payload"> | null };
export interface ServiceInput {
  id: string;
  name: string;
  target: string;
  owner: string | null;
  check_hours: number | null;
  context: ServiceContext;
}
export const listServices = () => get<ServiceRow[]>("/api/services");
export const addService = (body: ServiceInput) => post<ServiceRow>("/api/services", body);
export const checkService = (id: string) => post<ServiceRow>(`/api/services/${encodeURIComponent(id)}/check`);
export async function removeService(id: string): Promise<void> {
  const res = await fetch(`/api/services/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res.ok) await fail(res);
}
/** Registering a service points the scanner at a path on the server, so it needs the admin role. */
export const canAdmin = (me: Me) => me.role === "admin";
