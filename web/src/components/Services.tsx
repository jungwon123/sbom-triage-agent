import { useCallback, useEffect, useState, type FormEvent } from "react";
import { addService, canAdmin, canDecide, checkService, listServices, removeService, type ServiceRow } from "../lib/api";
import { BUCKETS, bucketColor, changeLabel, when } from "../lib/format";
import type { Change, Me, ServiceCheck } from "../lib/types";
import Changes from "./Changes";

interface Props {
  me: Me;
  onOpenRun: (runId: string) => void;
}

const POLL_MS = 2000;
const active = (s: ServiceRow) => s.job?.status === "queued" || s.job?.status === "running";
const crit = { high: "높음", medium: "보통", low: "낮음" } as const;

function countsText(counts: ServiceCheck["counts"]): string {
  return (Object.keys(changeLabel) as Change["kind"][])
    .filter((k) => counts?.[k])
    .map((k) => `${changeLabel[k]} ${counts![k]}`)
    .join(", ");
}

/** Registered services: what each one's current run says, when it was last re-checked and what moved. */
export default function Services({ me, onOpenRun }: Props) {
  const [rows, setRows] = useState<ServiceRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(
    () =>
      listServices()
        .then((list) => {
          setRows(list);
          setError(null);
        })
        .catch((e: Error) => setError(e.message)),
    [],
  );

  useEffect(() => {
    void load();
  }, [load]);

  // A check is a queued job on the server; keep reading until none is waiting or running.
  useEffect(() => {
    if (!rows?.some(active)) return;
    const t = window.setTimeout(() => void load(), POLL_MS);
    return () => window.clearTimeout(t);
  }, [rows, load]);

  async function act(id: string, fn: () => Promise<unknown>) {
    setBusy(id);
    setError(null);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="pt-10">
      <h2 className="text-[clamp(1.5rem,3.2vw,2.25rem)] font-semibold leading-tight tracking-[-0.02em]">등록된 서비스</h2>
      <p className="mt-3 max-w-[70ch] text-[15px] leading-relaxed text-dim">
        등록한 서비스는 정해진 주기로 다시 스캔해 지난 결과와 비교합니다. 새 취약점, 등급 변화, KEV 등재, 수정 버전 공개가 있을
        때만 새 분석 실행이 생기고, 달라진 것이 없으면 확인한 시각만 남습니다. 다시 확인하는 데에는 AI 모델을 호출하지 않습니다.
      </p>
      {error && (
        <p role="alert" className="mt-4 rounded border-l-4 border-now bg-sheet px-3 py-2 text-sm">
          요청을 처리하지 못했습니다. {error}
        </p>
      )}
      {rows === null && !error && <p className="mt-8 text-dim">불러오는 중입니다.</p>}
      {rows?.length === 0 && (
        <p className="mt-8 max-w-xl text-[15px] leading-relaxed">
          아직 등록된 서비스가 없습니다. {canAdmin(me) ? "아래에서 등록하거나 " : "관리 권한이 있는 계정이 등록하거나 "}
          명령줄에서 등록하세요:{" "}
          <code className="rounded bg-sheet px-1.5 py-0.5 font-mono text-[13px]">
            uv run python -m triage services add &lt;식별자&gt; &lt;레포 경로&gt;
          </code>
        </p>
      )}

      <ul className="mt-8 space-y-4">
        {rows?.map((s) => {
          const c = s.last_check;
          const working = active(s) || busy === s.id;
          return (
            <li key={s.id} className="rounded-md bg-sheet px-5 py-4 ring-1 ring-rule">
              <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
                <h3 className="text-[17px] font-semibold">{s.name}</h3>
                <span className="font-mono text-[13px] text-dim">{s.id}</span>
                {s.owner && <span className="text-sm text-dim">담당 {s.owner}</span>}
                <span className="text-sm text-dim">
                  중요도 {s.context?.service_criticality ? crit[s.context.service_criticality] : "미입력"}, 외부 노출{" "}
                  {s.context?.internet_facing == null ? "미입력" : s.context.internet_facing ? "예" : "아니오"}
                </span>
                <span className="ml-auto text-sm text-dim">
                  {s.check_hours ? `${s.check_hours}시간마다 자동 확인` : "요청할 때만 확인"}
                </span>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2">
                {s.summary && s.current_run ? (
                  <>
                    <dl className="flex gap-x-5">
                      {BUCKETS.map((b) => (
                        <div key={b} className="flex items-baseline gap-1.5">
                          <dt className={`text-sm font-semibold ${bucketColor[b].text}`}>{b}</dt>
                          <dd className="text-[17px] font-semibold tabular-nums">{s.summary!.final[b]}</dd>
                        </div>
                      ))}
                    </dl>
                    <button type="button" className="text-sm text-link underline" onClick={() => onOpenRun(s.current_run!)}>
                      분석 결과 보기
                    </button>
                  </>
                ) : (
                  <p className="text-sm text-dim">아직 분석 결과가 없습니다. 처음 확인하면 첫 실행이 만들어집니다.</p>
                )}
                {canDecide(me) && (
                  <button
                    type="button"
                    className="ml-auto rounded border border-ink px-3 py-1.5 text-sm font-semibold disabled:opacity-40"
                    disabled={working}
                    onClick={() => act(s.id, () => checkService(s.id))}
                  >
                    지금 다시 확인
                  </button>
                )}
              </div>

              {active(s) && (
                <p role="status" className="mt-3 rounded border-l-4 border-next bg-paper px-3 py-2 text-sm">
                  {s.job?.status === "queued"
                    ? s.job.waiting_for_worker
                      ? "확인이 대기 중입니다. 지금 떠 있는 작업자가 없어 시작하지 못하고 있습니다."
                      : "확인이 대기 중입니다. 작업자가 순서대로 처리합니다."
                    : "다시 스캔해 지난 결과와 비교하고 있습니다."}
                </p>
              )}
              {!active(s) && s.job?.status === "interrupted" && (
                <p role="alert" className="mt-3 text-sm text-now">확인을 끝내지 못했습니다. {s.job.error}</p>
              )}

              {c && (
                <div className="mt-3 border-t border-rule pt-3 text-sm">
                  <p>
                    <span className="text-dim">마지막 확인 {when(c.at)}</span>{" "}
                    {c.result === "no_change" && "달라진 것이 없습니다."}
                    {c.result === "first" && "첫 분석을 마쳤습니다."}
                    {c.result === "failed" && <span className="text-now">확인하지 못했습니다. {c.error}</span>}
                    {c.result === "changed" && <span className="font-semibold">달라진 것이 있습니다: {countsText(c.counts)}.</span>}
                  </p>
                  {c.result === "changed" && (
                    <>
                      <p className="mt-1 text-dim">
                        움직이지 않은 항목의 AI 판단 {c.carried ?? 0}건은 그대로 가져왔습니다.
                        {(c.needs_judgment ?? 0) > 0 &&
                          ` 새로 생기거나 움직인 ${c.needs_judgment}건은 규칙 결과이며 AI 판단을 아직 하지 않았습니다.`}{" "}
                        샌드박스 검증과 승인 기록은 이전 실행에 남아 있고 새 실행에서는 다시 해야 합니다.
                      </p>
                      <details className="mt-1">
                        <summary className="cursor-pointer text-link underline">변경 {(c.changes ?? []).length}건 보기</summary>
                        <Changes changes={c.changes ?? []} />
                      </details>
                    </>
                  )}
                </div>
              )}

              {canAdmin(me) && (
                <p className="mt-3 text-right">
                  <button
                    type="button"
                    className="text-sm text-dim underline"
                    disabled={working}
                    onClick={() => {
                      if (window.confirm(`${s.name} 등록을 해제할까요? 분석 실행 기록은 지워지지 않습니다.`))
                        void act(s.id, () => removeService(s.id));
                    }}
                  >
                    등록 해제
                  </button>
                </p>
              )}
            </li>
          );
        })}
      </ul>

      {canAdmin(me) ? (
        <Register onDone={load} />
      ) : (
        rows !== null && <p className="mt-8 text-sm text-dim">서비스 등록과 해제는 관리 권한이 있는 계정만 할 수 있습니다.</p>
      )}
    </section>
  );
}

const field = "mt-1 w-full rounded border border-rule bg-paper px-2 py-1.5 text-ink";

function Register({ onDone }: { onDone: () => Promise<unknown> }) {
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const v = Object.fromEntries(new FormData(form)) as Record<string, string>;
    setSaving(true);
    setError(null);
    try {
      await addService({
        id: v.id.trim(),
        name: v.name.trim(),
        target: v.target.trim(),
        owner: v.owner.trim() || null,
        check_hours: v.check_hours ? Number(v.check_hours) : null,
        context: {
          service_criticality: (v.criticality || null) as "high" | "medium" | "low" | null,
          internet_facing: v.internet === "" ? null : v.internet === "yes",
        },
      });
      form.reset();
      await onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={submit} className="mt-10 max-w-3xl rounded-md bg-sheet px-5 py-4 ring-1 ring-rule">
      <h3 className="text-[15px] font-semibold">서비스 등록</h3>
      <p className="mt-1 text-sm text-dim">
        대상은 서버에서 보이는 저장소 디렉터리나 SBOM JSON 파일의 경로이며, 허용된 위치(TRIAGE_SERVICE_ROOTS) 아래여야 합니다.
      </p>
      <div className="mt-3 grid gap-x-4 gap-y-3 sm:grid-cols-2">
        <label className="text-sm">
          식별자 (영문 소문자, 숫자, 하이픈)
          <input name="id" required pattern="[a-z0-9][a-z0-9-]{0,39}" className={`${field} font-mono`} />
        </label>
        <label className="text-sm">
          이름
          <input name="name" required maxLength={80} className={field} />
        </label>
        <label className="text-sm sm:col-span-2">
          대상 경로
          <input name="target" required maxLength={500} className={`${field} font-mono`} placeholder="fixtures/demo-repo" />
        </label>
        <label className="text-sm">
          담당
          <input name="owner" maxLength={80} className={field} />
        </label>
        <label className="text-sm">
          자동 확인 주기 (시간, 비우면 요청할 때만)
          <input name="check_hours" type="number" min={1} max={720} defaultValue={24} className={field} />
        </label>
        <label className="text-sm">
          서비스 중요도
          <select name="criticality" className={field} defaultValue="">
            <option value="">미입력</option>
            <option value="high">높음</option>
            <option value="medium">보통</option>
            <option value="low">낮음</option>
          </select>
        </label>
        <label className="text-sm">
          외부 노출
          <select name="internet" className={field} defaultValue="">
            <option value="">미입력</option>
            <option value="yes">예</option>
            <option value="no">아니오</option>
          </select>
        </label>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-sm text-now">
          등록하지 못했습니다. {error}
        </p>
      )}
      <button type="submit" disabled={saving} className="mt-4 rounded bg-ink px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-40">
        등록
      </button>
    </form>
  );
}
