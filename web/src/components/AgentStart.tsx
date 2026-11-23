import { useEffect, useState } from "react";
import { canDecide, getAgentJob, latestAgentJob, startAgent, type AgentJob, type AgentScope } from "../lib/api";
import type { Me } from "../lib/types";

interface Props {
  runId: string;
  me: Me;
  changed: number;
  onDone: () => void;
}

const POLL_MS = 3000;
const isActive = (j: AgentJob | null) => j?.status === "queued" || j?.status === "running";
const skipLabel: Record<string, string> = {
  "replay mode": "재생 모드에서는 모델을 호출하지 않습니다. 저장된 판단을 그대로 보여 줍니다.",
  "no model": "작업자에 모델이 설정되어 있지 않아 실행하지 않았습니다. 기존 판단은 그대로입니다.",
  "nothing to judge": "다시 판단할 항목이 없습니다.",
};

/** Starts the AI judgment of a run as a queued job and follows it. The worker calls the model. */
export default function AgentStart({ runId, me, changed, onDone }: Props) {
  const [job, setJob] = useState<AgentJob | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setJob(null);
    setError(null);
    latestAgentJob(runId)
      .then((j) => alive && setJob(j))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [runId]);

  useEffect(() => {
    if (!job || !isActive(job)) return;
    const t = window.setTimeout(() => {
      getAgentJob(runId, job.id)
        .then((j) => {
          setJob(j);
          if (j.status === "done") onDone();
        })
        .catch((e: Error) => setError(e.message));
    }, POLL_MS);
    return () => window.clearTimeout(t);
  }, [job, runId, onDone]);

  if (!canDecide(me)) return null;
  const result = job?.status === "done" ? job.result : null;

  async function start(scope: AgentScope) {
    setError(null);
    try {
      setJob(await startAgent(runId, scope));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const button = "rounded border border-ink px-3 py-1.5 text-sm font-semibold disabled:opacity-40";
  return (
    <section aria-label="AI 판단" className="mt-6 rounded-md bg-sheet px-5 py-4 ring-1 ring-rule">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <h2 className="text-[15px] font-semibold">AI 판단</h2>
        <p className="text-sm text-dim">모델을 호출하므로 사용량만큼 비용이 듭니다.</p>
        <div className="ml-auto flex flex-wrap gap-2">
          {changed > 0 && (
            <button type="button" className={button} disabled={isActive(job)} onClick={() => start("changed")}>
              달라진 {changed}건만 판단
            </button>
          )}
          <button type="button" className={button} disabled={isActive(job)} onClick={() => start("all")}>
            전체 판단 실행
          </button>
        </div>
      </div>
      {job && isActive(job) && (
        <p role="status" className="mt-3 rounded border-l-4 border-next bg-paper px-3 py-2 text-sm">
          {job.status === "queued"
            ? job.waiting_for_worker
              ? "판단이 대기 중입니다. 지금 떠 있는 작업자가 없어 시작하지 못하고 있습니다."
              : "판단이 대기 중입니다. 작업자가 순서대로 처리합니다."
            : "모델이 항목을 하나씩 판단하고 있습니다. 몇 분 걸립니다."}{" "}
          <span className="text-dim">이 화면을 닫아도 작업은 계속됩니다.</span>
        </p>
      )}
      {result?.skipped && <p className="mt-3 text-sm">{skipLabel[result.skipped] ?? result.skipped}</p>}
      {result && !result.skipped && (
        <p className="mt-3 text-sm">
          {result.judged}건을 판단했습니다.
          {result.fallbacks ? ` 모델 호출이 실패해 규칙 결과로 남은 항목이 ${result.fallbacks}건 있습니다.` : ""}
        </p>
      )}
      {job && (job.status === "failed" || job.status === "interrupted") && (
        <p role="alert" className="mt-3 rounded border-l-4 border-now bg-paper px-3 py-2 text-sm">
          판단을 끝내지 못했습니다. {job.error}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-2 text-sm text-now">
          판단을 시작하지 못했습니다. {error}
        </p>
      )}
    </section>
  );
}
