import { useState } from "react";
import { exportApproved, type ExportResult } from "../lib/api";
import type { Proposal } from "../lib/types";

interface Props {
  runId: string;
  proposals: Proposal[];
  onSelect: (findingId: string) => void;
}

/** Where the owner stands: how many proposed changes are decided, and the export of the approved ones. */
export default function Decisions({ runId, proposals, onSelect }: Props) {
  const [result, setResult] = useState<ExportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const ready = proposals.filter((p) => p.verification?.patch_file);
  if (ready.length === 0) return null;
  const count = (s: string) => ready.filter((p) => p.decision?.status === s).length;
  const open = ready.filter((p) => !p.decision);
  const approved = count("approved");

  async function run() {
    setBusy(true);
    setError(null);
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
        <button
          type="button"
          className="ml-auto rounded bg-ink px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-40"
          disabled={busy || approved === 0}
          onClick={run}
        >
          승인한 {approved}건 내보내기
        </button>
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
      {error && (
        <p role="alert" className="mt-2 text-sm text-now">
          내보내지 못했습니다. {error}
        </p>
      )}
      {result && (
        <div className="mt-3">
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
