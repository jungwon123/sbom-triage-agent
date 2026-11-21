import { useEffect, useRef, useState } from "react";
import {
  exportApproved, getJob, latestExportJob, startExportTogether, type ExportJob, type ExportResult,
} from "../lib/api";
import { reasonLabel, verdictLabel } from "../lib/format";
import type { Proposal } from "../lib/types";

interface Props {
  runId: string;
  proposals: Proposal[];
  onSelect: (findingId: string) => void;
}

const POLL_MS = 2000;
const isActive = (j: ExportJob | null) => j?.status === "queued" || j?.status === "running";

function clock(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" });
}

/** Where the owner stands: how many proposed changes are decided, and the export of the approved ones. */
export default function Decisions({ runId, proposals, onSelect }: Props) {
  const [result, setResult] = useState<ExportResult | null>(null);
  const [job, setJob] = useState<ExportJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<number | null>(null);

  // The combined check runs as a queued job on the server, so a reload picks it up where it is.
  useEffect(() => {
    let alive = true;
    setResult(null);
    setJob(null);
    setError(null);
    latestExportJob(runId)
      .then((j) => {
        if (!alive || !j) return;
        setJob(j);
        if (j.status === "done" && j.result) setResult(j.result);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [runId]);

  useEffect(() => {
    if (!job || !isActive(job)) return;
    timer.current = window.setTimeout(() => {
      getJob(runId, job.id)
        .then((j) => {
          setJob(j);
          if (j.status === "done" && j.result) setResult(j.result);
        })
        .catch((e: Error) => setError(e.message));
    }, POLL_MS);
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [job, runId]);

  const ready = proposals.filter((p) => p.verification?.patch_file);
  if (ready.length === 0) return null;
  const count = (s: string) => ready.filter((p) => p.decision?.status === s).length;
  const open = ready.filter((p) => !p.decision);
  const approved = count("approved");
  const working = busy || isActive(job);

  async function together() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setJob(await startExportTogether(runId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function single() {
    setBusy(true);
    setError(null);
    setJob(null);
    try {
      setResult(await exportApproved(runId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="수정안 결정 현황" className="mt-6 rounded-md bg-sheet px-5 py-4 ring-1 ring-rule">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <h2 className="text-[15px] font-semibold">검증된 수정안 {ready.length}건</h2>
        <p className="text-sm">
          승인 {approved}, 보류 {count("held")}, 반려 {count("rejected")},{" "}
          <span className={open.length ? "font-semibold" : "text-dim"}>결정 대기 {open.length}</span>
        </p>
        <div className="ml-auto flex flex-wrap gap-2">
          <button
            type="button"
            className="rounded bg-ink px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-40"
            disabled={working || approved === 0}
            onClick={together}
          >
            승인한 {approved}건 함께 검증하고 내보내기
          </button>
          <button
            type="button"
            className="rounded border border-ink px-3 py-1.5 text-sm font-semibold disabled:opacity-40"
            disabled={working || approved === 0}
            onClick={single}
          >
            건별 패치만 내보내기
          </button>
        </div>
      </div>
      {open.length > 0 && (
        <p className="mt-2 text-sm text-dim">
          결정 대기:{" "}
          {open.map((p, i) => (
            <span key={p.target}>
              {i > 0 && ", "}
              <button type="button" className="text-link underline" onClick={() => onSelect(p.finding_ids[0])}>
                {p.package} {p.from_version}
              </button>
            </span>
          ))}
        </p>
      )}

      {job && isActive(job) && (
        <p role="status" className="mt-3 rounded border-l-4 border-next bg-paper px-3 py-2 text-sm">
          {job.status === "queued"
            ? job.waiting_for_worker
              ? "함께 검증이 대기 중입니다. 지금 떠 있는 작업자가 없어 시작하지 못하고 있습니다. 작업자를 실행하면 이어서 진행합니다."
              : `함께 검증이 대기 중입니다${job.position ? ` (앞선 작업 ${job.position}건)` : ""}. 작업자가 순서대로 처리합니다.`
            : `샌드박스에서 승인한 변경을 함께 적용해 확인하고 있습니다 (${clock(job.started_at)} 시작, 보통 1~2분).`}{" "}
          <span className="text-dim">이 화면을 닫거나 새로 고쳐도 작업은 계속됩니다.</span>
        </p>
      )}
      {job && (job.status === "failed" || job.status === "interrupted") && (
        <p role="alert" className="mt-3 rounded border-l-4 border-now bg-paper px-3 py-2 text-sm">
          함께 검증을 끝내지 못했습니다. {job.error}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-2 text-sm text-now">
          내보내지 못했습니다. {error}
        </p>
      )}

      {result && (
        <div className="mt-3">
          {result.combined && (
            <div
              className={`mb-3 rounded border-l-4 bg-paper px-3 py-2 ${
                result.combined.verdict === "verified" ? "border-ink" : result.combined.verdict === "failed" ? "border-now" : "border-next"
              }`}
            >
              <p className="font-semibold">
                함께 적용한 결과: {verdictLabel[result.combined.verdict]}
                {job?.finished_at && <span className="ml-2 text-sm font-normal text-dim">{clock(job.finished_at)} 완료</span>}
              </p>
              <p className="text-sm">
                {reasonLabel[result.combined.reason] ?? result.combined.reason} 대상 취약점 {result.combined.finding_ids.length}건 중
                남은 것 {result.combined.remaining.length}건, 실행된 테스트 {result.combined.tests_run}개, lockfile{" "}
                {result.combined.lockfile_lines_changed}줄 변경.
              </p>
              {result.combined.verdict !== "verified" && (
                <p className="mt-1 text-sm">이 패치는 그대로 반영하지 말고 건별로 나눠 확인하세요.</p>
              )}
            </div>
          )}
          {result.combined_skipped && (
            <p className="mb-2 text-sm">함께 검증하지 못해 건별 패치를 내보냈습니다. {result.combined_skipped}</p>
          )}
          <p className="text-sm">
            <code className="rounded bg-paper px-1.5 py-0.5 font-mono text-[13px]">{result.dir}</code>에 파일{" "}
            {result.files.length}개를 썼습니다. 원본 저장소에는 아무것도 반영하지 않았습니다.
          </p>
          {result.pr_draft && (
            <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded bg-paper px-3 py-2 font-mono text-[12.5px] leading-relaxed">
              {result.pr_draft}
            </pre>
          )}
        </div>
      )}
    </section>
  );
}
