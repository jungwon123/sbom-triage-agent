import { useEffect, useMemo, useState } from "react";
import Detail from "./components/Detail";
import ItemList from "./components/ItemList";
import Overview from "./components/Overview";
import { getRun, listRuns, type RunDetail, type RunListItem } from "./lib/api";
import { byCvss, byPriority } from "./lib/format";

export type SortMode = "priority" | "cvss";

function runFromUrl(): string | null {
  return new URLSearchParams(window.location.search).get("run");
}

export default function App() {
  const [runs, setRuns] = useState<RunListItem[]>([]);
  const [runId, setRunId] = useState<string | null>(runFromUrl());
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<SortMode>("priority");
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    listRuns()
      .then((list) => {
        setRuns(list);
        if (!runFromUrl() && list.length) setRunId(list[0].id);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!runId) return;
    setRun(null);
    getRun(runId)
      .then((r) => {
        setRun(r);
        setError(null);
        const first = [...r.items].sort(byPriority)[0];
        setSelected(first ? first.finding.id : null);
      })
      .catch((e: Error) => setError(e.message));
  }, [runId]);

  const items = useMemo(() => (run ? [...run.items].sort(mode === "priority" ? byPriority : byCvss) : []), [run, mode]);
  const current = items.find((i) => i.finding.id === selected) ?? null;

  function pickRun(id: string) {
    const url = new URL(window.location.href);
    url.searchParams.set("run", id);
    window.history.replaceState(null, "", url);
    setRunId(id);
  }

  return (
    <div className="mx-auto max-w-[1440px] px-4 pb-16 sm:px-8">
      <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-rule py-4">
        <h1 className="text-[17px] font-semibold">SBOM Triage</h1>
        <label className="flex items-center gap-2 text-sm text-dim">
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
        {run && <Context run={run} />}
      </header>

      {error && (
        <p role="alert" className="mt-10 max-w-xl text-[15px] leading-relaxed">
          분석 결과를 불러오지 못했습니다 ({error}). API가 실행 중인지 확인하세요:{" "}
          <code className="rounded bg-sheet px-1.5 py-0.5 font-mono text-[13px]">uv run uvicorn triage.api:app</code>
        </p>
      )}
      {!error && !run && runId && <p className="mt-10 text-dim">불러오는 중입니다.</p>}
      {!error && !runId && runs.length === 0 && (
        <p className="mt-10 max-w-xl text-[15px] leading-relaxed">
          아직 분석 결과가 없습니다. 먼저 스캔을 실행하세요:{" "}
          <code className="rounded bg-sheet px-1.5 py-0.5 font-mono text-[13px]">uv run python -m triage scan &lt;레포 경로&gt;</code>
        </p>
      )}

      {run && (
        <>
          <Overview run={run} items={items} mode={mode} onMode={setMode} selected={selected} onSelect={setSelected} />
          <main className="mt-8 grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(420px,520px)]">
            <ItemList items={items} mode={mode} selected={selected} onSelect={setSelected} />
            <aside className="order-first lg:sticky lg:top-4 lg:order-none lg:max-h-[calc(100vh-2rem)] lg:overflow-y-auto">
              {current ? <Detail item={current} /> : <p className="text-dim">목록에서 항목을 고르면 근거와 조치안이 표시됩니다.</p>}
            </aside>
          </main>
        </>
      )}
    </div>
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
        <dd className="text-ink">{llm && llm.provider !== "none" ? `규칙 + AI (${llm.model ?? llm.provider})` : "규칙만"}</dd>
      </div>
    </dl>
  );
}
