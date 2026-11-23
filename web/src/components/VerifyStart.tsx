import { useEffect, useState } from "react";
import { canDecide, getVerifyJob, latestVerifyJob, startVerify, type VerifyJob } from "../lib/api";
import type { Me } from "../lib/types";

interface Props {
  runId: string;
  me: Me;
  hasRepo: boolean;
  verified: number;
  onDone: () => void;
}

const POLL_MS = 3000;
const isActive = (j: VerifyJob | null) => j?.status === "queued" || j?.status === "running";
const skipLabel: Record<string, string> = {
  "replay mode": "재생 모드에서는 샌드박스를 실행하지 않습니다.",
  "no repo": "원본 저장소가 없는 실행이라 검증할 수 없습니다.",
  "docker unavailable": "작업자에 Docker가 없어 검증을 건너뛰었습니다.",
};

/** Starts the sandbox verification of the NOW items as a queued job and follows it. */
export default function VerifyStart({ runId, me, hasRepo, verified, onDone }: Props) {
  const [job, setJob] = useState<VerifyJob | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setJob(null);
    setError(null);
    latestVerifyJob(runId)
      .then((j) => alive && setJob(j))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [runId]);

  useEffect(() => {
    if (!job || !isActive(job)) return;
    const t = window.setTimeout(() => {
      getVerifyJob(runId, job.id)
        .then((j) => {
          setJob(j);
          if (j.status === "done") onDone();
        })
        .catch((e: Error) => setError(e.message));
    }, POLL_MS);
    return () => window.clearTimeout(t);
  }, [job, runId, onDone]);

  if (!hasRepo || !canDecide(me)) return null;
  const skipped = job?.status === "done" ? job.result?.skipped : null;

  async function start() {
    setError(null);
    try {
      setJob(await startVerify(runId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <section aria-label="샌드박스 검증" className="mt-6 rounded-md bg-sheet px-5 py-4 ring-1 ring-rule">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <h2 className="text-[15px] font-semibold">샌드박스 검증</h2>
        <p className="text-sm text-dim">
          {verified > 0 ? `검증을 통과한 조치안 ${verified}건이 있습니다.` : "아직 검증한 조치안이 없습니다."}
        </p>
        <button
          type="button"
          className="ml-auto rounded border border-ink px-3 py-1.5 text-sm font-semibold disabled:opacity-40"
          disabled={isActive(job)}
          onClick={start}
        >
          NOW 항목 검증 실행
        </button>
      </div>
      {job && isActive(job) && (
        <p role="status" className="mt-3 rounded border-l-4 border-next bg-paper px-3 py-2 text-sm">
          {job.status === "queued"
            ? job.waiting_for_worker
              ? "검증이 대기 중입니다. 지금 떠 있는 작업자가 없어 시작하지 못하고 있습니다."
              : "검증이 대기 중입니다. 작업자가 순서대로 처리합니다."
            : "샌드박스에서 조치 전 기준선과 조치안을 확인하고 있습니다. 몇 분 걸립니다."}{" "}
          <span className="text-dim">이 화면을 닫아도 작업은 계속됩니다.</span>
        </p>
      )}
      {skipped && <p className="mt-3 text-sm">{skipLabel[skipped] ?? skipped}</p>}
      {job && (job.status === "failed" || job.status === "interrupted") && (
        <p role="alert" className="mt-3 rounded border-l-4 border-now bg-paper px-3 py-2 text-sm">
          검증을 끝내지 못했습니다. {job.error}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-2 text-sm text-now">
          검증을 시작하지 못했습니다. {error}
        </p>
      )}
    </section>
  );
}
