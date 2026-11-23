import { useEffect, useMemo, useState } from "react";
import Detail from "./components/Detail";
import ItemList from "./components/ItemList";
import Overview from "./components/Overview";
import Changes from "./components/Changes";
import Decisions from "./components/Decisions";
import Services from "./components/Services";
import {
  SIGNED_OUT, getMe, getProposals, getRun, listRuns, loginUrl, logout, roleLabel, type RunDetail, type RunListItem,
} from "./lib/api";
import type { Me, Proposal } from "./lib/types";
import { byCvss, byPriority } from "./lib/format";

export type SortMode = "priority" | "cvss";

type View = "run" | "services";

function viewFromUrl(): View {
  return new URLSearchParams(window.location.search).get("view") === "services" ? "services" : "run";
}

function runFromUrl(): string | null {
  return new URLSearchParams(window.location.search).get("run");
}

const LOGIN_ERRORS: Record<string, string> = {
  expired: "로그인 요청이 만료되었습니다. 다시 시도하세요.",
  denied: "로그인을 취소했거나 인증 서버가 거부했습니다.",
  no_role: "로그인은 확인됐지만 이 서비스의 권한이 없는 계정입니다. 관리자에게 열람 또는 승인 그룹에 추가해 달라고 요청하세요.",
  provider: "인증 서버에 연결하지 못했습니다. 잠시 뒤 다시 시도하세요.",
  failed: "로그인을 확인하지 못했습니다. 다시 시도하세요.",
};

/** The reason the last sign-in attempt ended without a session, read once and removed from the address. */
function takeLoginError(): string | null {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("login_error");
  if (!code) return null;
  url.searchParams.delete("login_error");
  window.history.replaceState(null, "", url);
  return LOGIN_ERRORS[code] ?? LOGIN_ERRORS.failed;
}

export default function App() {
  const [runs, setRuns] = useState<RunListItem[]>([]);
  const [runId, setRunId] = useState<string | null>(runFromUrl());
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<SortMode>("priority");
  const [selected, setSelected] = useState<string | null>(null);
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [view, setView] = useState<View>(viewFromUrl);
  const [loginError] = useState(takeLoginError);
  const locked = me?.mode === "oidc" && !me.signed_in;
  const ready = me !== null && !locked;

  useEffect(() => {
    getMe()
      .then(setMe)
      .catch((e: Error) => setError(e.message));
    // Any call answered with 401 means the session ended: back to the sign-in screen.
    const out = () => setMe((m) => (m && m.mode === "oidc" ? { mode: "oidc", signed_in: false } : m));
    window.addEventListener(SIGNED_OUT, out);
    return () => window.removeEventListener(SIGNED_OUT, out);
  }, []);

  useEffect(() => {
    if (!ready) return;
    listRuns()
      .then((list) => {
        setRuns(list);
        if (!runFromUrl() && list.length) setRunId(list[0].id);
      })
      .catch((e: Error) => setError(e.message));
  }, [ready]);

  useEffect(() => {
    if (!runId || !ready) return;
    setRun(null);
    setProposals([]);
    getProposals(runId).then(setProposals).catch(() => setProposals([]));
    getRun(runId)
      .then((r) => {
        setRun(r);
        setError(null);
        const first = [...r.items].sort(byPriority)[0];
        setSelected(first ? first.finding.id : null);
      })
      .catch((e: Error) => setError(e.message));
  }, [runId, ready]);

  const items = useMemo(() => (run ? [...run.items].sort(mode === "priority" ? byPriority : byCvss) : []), [run, mode]);
  const current = items.find((i) => i.finding.id === selected) ?? null;
  const proposal = current ? (proposals.find((p) => p.finding_ids.includes(current.finding.id)) ?? null) : null;
  const reloadProposals = () => (runId ? getProposals(runId).then(setProposals) : Promise.resolve());

  function pickRun(id: string) {
    const url = new URL(window.location.href);
    url.searchParams.set("run", id);
    url.searchParams.delete("view");
    window.history.replaceState(null, "", url);
    setRunId(id);
    setView("run");
    // a run made by a re-check is not in the list loaded at start
    if (!runs.some((r) => r.id === id)) listRuns().then(setRuns).catch(() => undefined);
  }

  function pickView(v: View) {
    const url = new URL(window.location.href);
    if (v === "services") url.searchParams.set("view", v);
    else url.searchParams.delete("view");
    window.history.replaceState(null, "", url);
    setView(v);
  }

  async function signOut() {
    await logout().catch(() => undefined);
    setRun(null);
    setRuns([]);
    setProposals([]);
    setMe({ mode: "oidc", signed_in: false });
  }

  if (locked) return <SignIn error={loginError} />;

  return (
    <div className="mx-auto max-w-[1440px] px-4 pb-16 sm:px-8">
      <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-rule py-4">
        <h1 className="text-[17px] font-semibold">SBOM Triage</h1>
        <nav aria-label="화면" className="flex gap-1 text-sm">
          {(["run", "services"] as const).map((v) => (
            <button
              key={v}
              type="button"
              aria-current={view === v ? "page" : undefined}
              className={`rounded px-2.5 py-1 ${view === v ? "bg-ink font-semibold text-white" : "text-ink underline"}`}
              onClick={() => pickView(v)}
            >
              {v === "run" ? "분석 결과" : "서비스"}
            </button>
          ))}
        </nav>
        <label className={`flex items-center gap-2 text-sm text-dim ${view === "run" ? "" : "hidden"}`}>
          분석 실행
          <select
            className="max-w-[60vw] rounded border border-rule bg-sheet px-2 py-1 text-ink"
            value={runId ?? ""}
            onChange={(e) => pickRun(e.target.value)}
          >
            {runId && !runs.some((r) => r.id === runId) && <option value={runId}>{runId}</option>}
            {runs.map((r) => (
              <option key={r.id} value={r.id}>
                {r.id} ({r.summary.findings}건)
              </option>
            ))}
          </select>
        </label>
        {run && view === "run" && <Context run={run} />}
        {me?.signed_in && (
          <p className={`flex items-center gap-2 text-sm ${run && view === "run" ? "" : "ml-auto"}`}>
            <span title={me.email ?? undefined}>{me.name}</span>
            {me.role && <span className="rounded bg-monitor-soft px-1.5 py-0.5 text-[13px]">{roleLabel[me.role]} 권한</span>}
            <button type="button" className="text-link underline" onClick={signOut}>
              로그아웃
            </button>
          </p>
        )}
      </header>

      {view === "services" && me && ready && <Services me={me} onOpenRun={pickRun} />}

      {view === "run" && error && (
        <p role="alert" className="mt-10 max-w-xl text-[15px] leading-relaxed">
          분석 결과를 불러오지 못했습니다 ({error}). API가 실행 중인지 확인하세요:{" "}
          <code className="rounded bg-sheet px-1.5 py-0.5 font-mono text-[13px]">uv run uvicorn triage.api:app</code>
        </p>
      )}
      {view === "run" && !error && !run && (runId || !ready) && <p className="mt-10 text-dim">불러오는 중입니다.</p>}
      {view === "run" && !error && ready && !runId && runs.length === 0 && (
        <p className="mt-10 max-w-xl text-[15px] leading-relaxed">
          아직 분석 결과가 없습니다. 먼저 스캔을 실행하세요:{" "}
          <code className="rounded bg-sheet px-1.5 py-0.5 font-mono text-[13px]">uv run python -m triage scan &lt;레포 경로&gt;</code>
        </p>
      )}

      {view === "run" && run && me && (
        <>
          <Overview run={run} items={items} mode={mode} onMode={setMode} selected={selected} onSelect={setSelected} />
          {run.meta.changes && run.meta.changes.length > 0 && (
            <section aria-label="지난 확인 이후 변경" className="mt-6 rounded-md bg-sheet px-5 py-4 ring-1 ring-rule">
              <h2 className="text-[15px] font-semibold">지난 확인 이후 달라진 것 {run.meta.changes.length}건</h2>
              <p className="mt-1 text-sm text-dim">
                비교한 이전 실행은 <span className="font-mono text-[12.5px]">{run.meta.previous_run}</span>입니다. 새로
                생기거나 움직인 항목은 AI 판단을 다시 받기 전까지 규칙 결과입니다.
              </p>
              <Changes changes={run.meta.changes} onSelect={setSelected} />
            </section>
          )}
          <Decisions runId={run.id} proposals={proposals} me={me} onSelect={setSelected} />
          <main className="mt-8 grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(420px,520px)]">
            <ItemList items={items} mode={mode} selected={selected} onSelect={setSelected} />
            <aside className="order-first lg:sticky lg:top-4 lg:order-none lg:max-h-[calc(100vh-2rem)] lg:overflow-y-auto">
              {current ? (
                <Detail item={current} runId={run.id} proposal={proposal} me={me} onDecided={reloadProposals} />
              ) : <p className="text-dim">목록에서 항목을 고르면 근거와 조치안이 표시됩니다.</p>}
            </aside>
          </main>
        </>
      )}
    </div>
  );
}

function SignIn({ error }: { error: string | null }) {
  return (
    <main className="mx-auto max-w-md px-4 pt-[18vh]">
      <h1 className="text-[22px] font-semibold">SBOM Triage</h1>
      <p className="mt-3 text-[15px] leading-relaxed">
        서비스의 취약점 목록과 수정안은 로그인한 사람만 볼 수 있습니다. 회사 계정으로 로그인하세요.
      </p>
      {error && (
        <p role="alert" className="mt-4 rounded border-l-4 border-now bg-sheet px-3 py-2 text-sm leading-relaxed">
          {error}
        </p>
      )}
      <a className="mt-6 inline-block rounded bg-ink px-4 py-2 text-[15px] font-semibold text-white" href={loginUrl()}>
        회사 계정으로 로그인
      </a>
      <p className="mt-6 text-sm leading-relaxed text-dim">
        열람 권한은 분석 결과를 볼 수 있고, 승인 권한은 수정안을 승인하거나 반려하고 내보낼 수 있습니다. 권한은 회사 계정의
        그룹으로 정해집니다.
      </p>
    </main>
  );
}

function Context({ run }: { run: RunDetail }) {
  const c = run.meta.context;
  const crit = { high: "높음", medium: "보통", low: "낮음" } as const;
  const llm = run.meta.llm;
  return (
    <dl className="ml-auto flex flex-wrap gap-x-5 gap-y-1 text-sm text-dim">
      <div className="flex gap-1.5">
        <dt>서비스 중요도</dt>
        <dd className="text-ink">{c.service_criticality ? crit[c.service_criticality] : "미입력"}</dd>
      </div>
      <div className="flex gap-1.5">
        <dt>외부 노출</dt>
        <dd className="text-ink">{c.internet_facing == null ? "미입력" : c.internet_facing ? "예" : "아니오"}</dd>
      </div>
      <div className="flex gap-1.5" title="서비스 중요도와 외부 노출은 참고용이며 점수에 넣지 않습니다">
        <dt>판단</dt>
        <dd className="text-ink">
          {llm?.code_reader
            ? `규칙 + AI (코드 판독은 사내 모델 ${llm.code_reader.model ?? "local"}${llm.provider !== "none" ? `, 작성은 ${llm.model ?? llm.provider}` : ""})`
            : llm && llm.provider !== "none"
              ? `규칙 + AI (${llm.model ?? llm.provider})`
              : "규칙만"}
        </dd>
      </div>
    </dl>
  );
}
