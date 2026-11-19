import { useState } from "react";
import { decide, patchUrl } from "../lib/api";
import type { Decision, Proposal } from "../lib/types";

export const statusLabel: Record<Decision["status"], string> = { approved: "승인", rejected: "반려", held: "보류" };
const NAME_KEY = "triage.decider";

function savedName(): string {
  try {
    return localStorage.getItem(NAME_KEY) ?? "";
  } catch {
    return "";
  }
}

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("ko-KR", { dateStyle: "medium", timeStyle: "short" });
}

interface Props {
  runId: string;
  proposal: Proposal;
  onDecided: () => Promise<unknown>;
}

/** The change the sandbox produced, and the owner's call on it. The agent never decides here. */
export default function ProposalBox({ runId, proposal: p, onDecided }: Props) {
  const [by, setBy] = useState(savedName);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const v = p.verification;
  const d = p.decision;
  const hasPatch = Boolean(v?.patch_file);
  const others = p.finding_ids.length - 1;

  async function submit(status: Decision["status"]) {
    setBusy(true);
    setError(null);
    try {
      await decide(runId, { target: p.target, status, by, reason });
      try {
        localStorage.setItem(NAME_KEY, by.trim());
      } catch {
        /* the name is a convenience only */
      }
      setReason("");
      await onDecided();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="수정안과 결정">
      <h3 className="text-sm font-semibold">수정안</h3>
      {hasPatch ? (
        <>
          <p className="mt-2 text-sm leading-relaxed">
            샌드박스에서 조치를 적용한 뒤 실제로 바뀐 내용입니다.
            {others > 0 && ` 이 패키지의 취약점 ${p.finding_ids.length}건이 이 변경 하나로 함께 처리됩니다.`}
          </p>
          {v?.package_json_diff ? (
            <pre className="mt-2 max-h-64 overflow-auto rounded bg-paper px-3 py-2 font-mono text-[12.5px] leading-relaxed">
              {v.package_json_diff.split("\n").map((line, i) => (
                <span
                  key={i}
                  className={`block ${
                    line.startsWith("+") && !line.startsWith("+++")
                      ? "bg-monitor-soft font-semibold"
                      : line.startsWith("-") && !line.startsWith("---")
                        ? "text-dim line-through decoration-dim/50"
                        : line.startsWith("@@")
                          ? "text-dim"
                          : ""
                  }`}
                >
                  {line || " "}
                </span>
              ))}
            </pre>
          ) : (
            <p className="mt-2 text-sm text-dim">package.json은 바뀌지 않고 lockfile만 바뀝니다.</p>
          )}
          <p className="mt-2 text-sm text-dim">
            package-lock.json {v?.lockfile_lines_changed ?? 0}줄 변경.{" "}
            <a className="text-link underline" href={patchUrl(runId, p.target)} target="_blank" rel="noreferrer">
              전체 변경 내용 보기
            </a>
          </p>
        </>
      ) : (
        <p className="mt-2 text-sm leading-relaxed text-dim">
          아직 샌드박스에서 만든 변경 내용이 없습니다. 검증을 실행하면 적용할 diff가 생기고, 그 뒤에 승인할 수 있습니다.
        </p>
      )}

      <div className="mt-4 rounded border border-rule px-3 py-3">
        <h4 className="text-sm font-semibold">담당자 결정</h4>
        {d ? (
          <p className="mt-1 text-[15px]">
            <span className="font-semibold">{statusLabel[d.status]}</span>{" "}
            <span className="text-dim">
              {d.by}, {when(d.at)}
            </span>
            {d.reason && <span className="mt-0.5 block text-sm">사유: {d.reason}</span>}
          </p>
        ) : (
          <p className="mt-1 text-sm text-dim">아직 결정하지 않았습니다. 반영 여부는 사람이 정합니다.</p>
        )}

        <div className="mt-3 grid gap-2 sm:grid-cols-[9rem_1fr]">
          <label className="text-sm">
            <span className="text-dim">결정하는 사람</span>
            <input
              className="mt-0.5 w-full rounded border border-rule bg-sheet px-2 py-1"
              value={by}
              maxLength={60}
              onChange={(e) => setBy(e.target.value)}
            />
          </label>
          <label className="text-sm">
            <span className="text-dim">사유 (반려와 보류에는 필수)</span>
            <input
              className="mt-0.5 w-full rounded border border-rule bg-sheet px-2 py-1"
              value={reason}
              maxLength={600}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            className="rounded bg-ink px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-40"
            disabled={busy || !by.trim() || !hasPatch}
            onClick={() => submit("approved")}
          >
            승인
          </button>
          <button
            type="button"
            className="rounded border border-ink px-3 py-1.5 text-sm font-semibold disabled:opacity-40"
            disabled={busy || !by.trim() || !reason.trim()}
            onClick={() => submit("held")}
          >
            보류
          </button>
          <button
            type="button"
            className="rounded border border-ink px-3 py-1.5 text-sm font-semibold disabled:opacity-40"
            disabled={busy || !by.trim() || !reason.trim()}
            onClick={() => submit("rejected")}
          >
            반려
          </button>
        </div>
        {error && (
          <p role="alert" className="mt-2 text-sm text-now">
            결정을 기록하지 못했습니다. {error}
          </p>
        )}
        <p className="mt-2 text-sm text-dim">
          승인해도 원본 저장소는 바뀌지 않습니다. 승인한 변경은 패치 파일과 PR 초안으로 내보낼 수 있습니다.
        </p>
      </div>
    </section>
  );
}
