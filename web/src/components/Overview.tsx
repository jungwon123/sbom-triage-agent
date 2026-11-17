import type { SortMode } from "../App";
import type { Item, RunDetail } from "../lib/api";
import { BUCKETS, bucketColor, bucketMeaning } from "../lib/format";

interface Props {
  run: RunDetail;
  items: Item[];
  mode: SortMode;
  onMode: (m: SortMode) => void;
  selected: string | null;
  onSelect: (id: string) => void;
}

/** Every finding is one tick. Order follows the sort mode, color is always the final bucket,
 *  so switching to CVSS order shows how far the "fix now" items sit from the top of that list. */
export default function Overview({ run, items, mode, onMode, selected, onSelect }: Props) {
  const s = run.meta.summary;
  const total = s.findings;
  const nowRanks = items.map((it, i) => (it.triage.final_bucket === "NOW" ? i + 1 : 0)).filter(Boolean);
  const highNotNow = run.items.filter((i) => (i.finding.cvss ?? 0) >= 7 && i.triage.final_bucket !== "NOW").length;

  const caption =
    total === 0
      ? "알려진 취약점이 없습니다."
      : mode === "cvss"
        ? nowRanks.length
          ? `CVSS가 높은 순으로 세우면 이번 주에 고칠 항목은 ${nowRanks.slice(0, 6).join(", ")}${nowRanks.length > 6 ? " …" : ""}번째에 있습니다.`
          : "이번 주에 고칠 항목이 없습니다."
        : `CVSS 7.0 이상 ${s.cvss_ge_7}건 가운데 ${highNotNow}건은 이번 주에 고치지 않아도 됩니다.`;

  return (
    <section className="pt-10">
      <p className="max-w-[26ch] text-[clamp(1.75rem,4.2vw,3rem)] font-semibold leading-[1.18] tracking-[-0.02em]">
        취약점 {total}건 가운데 이번 주에 고칠 것은 {s.final.NOW}건입니다.
      </p>

      <div className="mt-8 flex flex-wrap items-end justify-between gap-4">
        <dl className="flex flex-wrap gap-x-8 gap-y-2">
          {BUCKETS.map((b) => (
            <div key={b} className="flex items-baseline gap-2">
              <span className={`inline-block h-3 w-3 translate-y-[1px] rounded-sm ${bucketColor[b].bar}`} aria-hidden />
              <dt className="text-sm text-dim">
                <span className="font-semibold text-ink">{b}</span> {bucketMeaning[b]}
              </dt>
              <dd className="text-xl font-semibold">{s.final[b]}</dd>
            </div>
          ))}
        </dl>
        <div role="group" aria-label="정렬 기준" className="inline-flex rounded-md border border-rule bg-sheet p-0.5 text-sm">
          {(["priority", "cvss"] as const).map((m) => (
            <button
              key={m}
              type="button"
              aria-pressed={mode === m}
              onClick={() => onMode(m)}
              className={`rounded px-3 py-1.5 ${mode === m ? "bg-ink font-medium text-white" : "text-dim hover:text-ink"}`}
            >
              {m === "priority" ? "우선순위 순" : "CVSS 순"}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-3 flex h-14 items-end gap-px overflow-hidden rounded bg-sheet px-1 pt-1 ring-1 ring-rule" aria-label="취약점 전체 분포">
        {items.map((it) => {
          const b = it.triage.final_bucket;
          const on = it.finding.id === selected;
          return (
            <button
              key={it.finding.id}
              type="button"
              title={`${it.finding.package}@${it.finding.version} ${it.finding.vuln_id} (${b})`}
              aria-label={`${it.finding.package} ${it.finding.vuln_id} ${b}`}
              onClick={() => onSelect(it.finding.id)}
              className={`min-w-[2px] flex-1 rounded-t-sm ${bucketColor[b].bar} ${
                on ? "h-full opacity-100 ring-2 ring-ink" : b === "NOW" ? "h-[85%]" : b === "NEXT" ? "h-[55%] opacity-70" : "h-[30%] opacity-50"
              }`}
            />
          );
        })}
      </div>
      <p className="mt-2 text-sm text-dim">{caption}</p>
    </section>
  );
}
