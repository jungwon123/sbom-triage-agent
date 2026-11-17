import type { SortMode } from "../App";
import type { Bucket, Item } from "../lib/api";
import { BUCKETS, bucketColor, bucketMeaning, fmtCvss, fmtEpss, reachLabel } from "../lib/format";

interface Props {
  items: Item[];
  mode: SortMode;
  selected: string | null;
  onSelect: (id: string) => void;
}

export default function ItemList({ items, mode, selected, onSelect }: Props) {
  if (mode === "cvss") {
    return (
      <section aria-label="CVSS 순 목록">
        <h2 className="mb-2 text-sm text-dim">CVSS가 높은 순. 왼쪽 색은 최종 분류입니다.</h2>
        <ol className="divide-y divide-rule rounded-md bg-sheet ring-1 ring-rule">
          {items.map((it, i) => (
            <Row key={it.finding.id} item={it} rank={i + 1} on={it.finding.id === selected} onSelect={onSelect} />
          ))}
        </ol>
      </section>
    );
  }
  return (
    <div className="space-y-8">
      {BUCKETS.map((b) => {
        const group = items.filter((i) => i.triage.final_bucket === b);
        return (
          <section key={b} aria-label={b}>
            <h2 className="mb-2 flex items-baseline gap-2">
              <span className={`text-[15px] font-semibold ${bucketColor[b].text}`}>{b}</span>
              <span className="text-sm text-dim">
                {bucketMeaning[b]}, {group.length}건
              </span>
            </h2>
            {group.length === 0 ? (
              <p className="rounded-md bg-sheet px-4 py-3 text-sm text-dim ring-1 ring-rule">{emptyText[b]}</p>
            ) : (
              <ul className="divide-y divide-rule rounded-md bg-sheet ring-1 ring-rule">
                {group.map((it) => (
                  <Row key={it.finding.id} item={it} on={it.finding.id === selected} onSelect={onSelect} />
                ))}
              </ul>
            )}
          </section>
        );
      })}
    </div>
  );
}

const emptyText: Record<Bucket, string> = {
  NOW: "이번 주에 고칠 항목이 없습니다.",
  NEXT: "다음 스프린트로 넘길 항목이 없습니다.",
  MONITOR: "지켜볼 항목이 없습니다.",
};

function Row({ item, rank, on, onSelect }: { item: Item; rank?: number; on: boolean; onSelect: (id: string) => void }) {
  const { finding: f, triage: t } = item;
  const c = bucketColor[t.final_bucket];
  const v = t.verification;
  return (
    <li>
      <button
        type="button"
        aria-current={on}
        onClick={() => onSelect(f.id)}
        className={`flex w-full items-stretch gap-3 text-left ${on ? c.soft : "hover:bg-paper"}`}
      >
        <span className={`w-1 shrink-0 ${c.bar}`} aria-hidden />
        {rank !== undefined && <span className="w-8 shrink-0 self-center text-right text-sm text-dim">{rank}</span>}
        <span className="min-w-0 flex-1 py-2.5">
          <span className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium">{f.package}</span>
            <span className="text-sm text-dim">{f.version}</span>
            <span className="text-sm text-dim">{f.vuln_id}</span>
          </span>
          <span className="mt-0.5 block truncate text-sm text-dim">{f.summary ?? "설명 없음"}</span>
          <span className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[13px] text-dim">
            <span>{f.scope === "prod" ? "운영 의존성" : "개발 의존성"}</span>
            <span>{f.direct ? "직접" : "간접"}</span>
            <span>{reachLabel[t.reachability]}</span>
            {f.kev && <span className="font-semibold text-now">KEV 등재</span>}
            {t.needs_review && <span className="font-semibold text-ink">담당자 확인 필요</span>}
            {t.final_bucket !== t.rule_bucket && <span className="text-ink">AI가 {t.rule_bucket}에서 조정</span>}
            {v && <span className={v.verdict === "verified" ? "text-ink" : "text-now"}>{verdictShort[v.verdict]}</span>}
          </span>
        </span>
        <span className="shrink-0 self-center pr-4 text-right text-sm">
          <span className="block">
            <span className="text-dim">CVSS</span> <span className="font-semibold">{fmtCvss(f.cvss)}</span>
          </span>
          <span className="block text-dim">EPSS {fmtEpss(f.epss_percentile)}</span>
        </span>
      </button>
    </li>
  );
}

const verdictShort = { verified: "조치안 검증 통과", failed: "조치안 검증 실패", inconclusive: "조치안 판단 불가" } as const;
