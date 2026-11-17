import type { Item } from "../lib/api";
import {
  bucketColor, bucketMeaning, decidedLabel, fmtCvss, fmtEpss, reachLabel, reasonLabel, stepLabel, verdictLabel,
} from "../lib/format";
import type { Verification } from "../lib/types";

const PARTS = [
  { key: "severity", label: "심각도", max: 25 },
  { key: "exploit", label: "악용 가능성", max: 25 },
  { key: "exposure", label: "노출도", max: 50 },
] as const;

export default function Detail({ item }: { item: Item }) {
  const { finding: f, triage: t } = item;
  const c = bucketColor[t.final_bucket];
  const r = t.remediation;
  return (
    <article className="rounded-md bg-sheet ring-1 ring-rule">
      <header className={`rounded-t-md px-5 py-4 ${c.soft}`}>
        <p className={`text-sm font-semibold ${c.text}`}>
          {t.final_bucket} <span className="font-normal text-ink">{bucketMeaning[t.final_bucket]}</span>
        </p>
        <h2 className="mt-1 text-xl font-semibold leading-snug">
          {f.package} <span className="font-normal text-dim">{f.version}</span>
        </h2>
        <p className="mt-1 text-sm text-dim">
          {f.vuln_id}
          {f.summary ? `, ${f.summary}` : ""}
        </p>
      </header>

      <div className="space-y-6 px-5 py-5">
        {t.needs_review && (
          <p className="rounded border border-ink px-3 py-2 text-sm">
            악용 가능성이 높고 운영 코드에서 쓰는 항목이라 등급을 자동으로 낮추지 않았습니다. 담당자가 확인해야 합니다.
          </p>
        )}

        <section>
          <h3 className="text-sm font-semibold">위험 점수 {t.risk}점</h3>
          <div className="mt-2 space-y-1.5">
            {PARTS.map((p) => {
              const v = t.risk_breakdown[p.key] ?? 0;
              return (
                <div key={p.key} className="grid grid-cols-[5.5rem_1fr_4.5rem] items-center gap-2 text-sm">
                  <span className="text-dim">{p.label}</span>
                  <span className="h-2.5 overflow-hidden rounded-sm bg-paper" style={{ width: `${p.max * 2}%` }}>
                    <span className={`block h-full ${c.bar}`} style={{ width: `${(v / p.max) * 100}%` }} />
                  </span>
                  <span className="text-right">
                    {v.toFixed(1)} <span className="text-dim">/ {p.max}</span>
                  </span>
                </div>
              );
            })}
          </div>
          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <Fact k="CVSS" v={fmtCvss(f.cvss)} />
            <Fact k="EPSS" v={fmtEpss(f.epss_percentile)} />
            <Fact k="CISA KEV" v={f.kev ? "등재" : "미등재"} />
            <Fact k="의존성" v={`${f.scope === "prod" ? "운영" : "개발"}, ${f.direct ? "직접" : "간접"}`} />
            <Fact k="조치 비용" v={{ low: "낮음", medium: "보통", high: "높음" }[t.effort]} />
            <Fact k="코드 사용" v={reachLabel[t.reachability]} />
          </dl>
          {(f.missing ?? []).length > 0 && (
            <p className="mt-2 text-sm text-dim">확보하지 못한 데이터: {(f.missing ?? []).join(", ")}</p>
          )}
        </section>

        <section>
          <h3 className="text-sm font-semibold">이 순위가 나온 이유</h3>
          <ul className="mt-2 space-y-1 text-[15px] leading-relaxed">
            {t.rationale.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
          <p className="mt-2 text-sm text-dim">
            {decidedLabel[t.decided_by ?? "rule"]}
            {t.final_bucket !== t.rule_bucket && `. 규칙 결과 ${t.rule_bucket}에서 ${t.final_bucket}(으)로 조정: ${t.override_reason}`}
          </p>
        </section>

        {f.import_sites.length > 0 && (
          <section>
            <h3 className="text-sm font-semibold">코드에서 쓰는 곳 {f.import_sites.length}곳</h3>
            <ul className="mt-2 space-y-2">
              {f.import_sites.slice(0, 6).map((s) => (
                <li key={`${s.file}:${s.line}`} className="text-sm">
                  <p className="text-dim">
                    {s.file}:{s.line} <span className="text-ink">{s.kind === "runtime" ? "운영 코드" : "테스트 코드"}</span>
                  </p>
                  <pre className="mt-0.5 overflow-x-auto rounded bg-paper px-2 py-1 font-mono text-[12.5px]">{s.snippet}</pre>
                </li>
              ))}
            </ul>
          </section>
        )}

        {f.paths.length > 0 && !f.direct && (
          <section>
            <h3 className="text-sm font-semibold">들어온 경로</h3>
            <ul className="mt-1 space-y-0.5 text-sm text-dim">
              {f.paths.slice(0, 3).map((p, i) => (
                <li key={i}>{p.join(" > ")}</li>
              ))}
            </ul>
          </section>
        )}

        {r && (
          <section>
            <h3 className="text-sm font-semibold">조치안</h3>
            {r.kind === "mitigation_only" ? (
              <p className="mt-2 text-[15px] leading-relaxed">{r.mitigation ?? "수정 버전이 없습니다."}</p>
            ) : (
              <>
                <p className="mt-2 text-[15px]">
                  {r.from_version}에서 <span className="font-semibold">{r.to_version}</span>(으)로 올립니다.{" "}
                  <span className="text-dim">
                    {r.kind === "upgrade_direct" ? "직접 의존성 업그레이드" : "package.json overrides 설정"}, 깨질 위험{" "}
                    {{ low: "낮음", medium: "보통", high: "높음" }[r.breaking_risk]}
                  </span>
                </p>
                {r.package_json_patch && (
                  <pre className="mt-2 overflow-x-auto rounded bg-paper px-3 py-2 font-mono text-[12.5px]">
                    {JSON.stringify(r.package_json_patch, null, 2)}
                  </pre>
                )}
                {r.commands.map((cmd) => (
                  <pre key={cmd} className="mt-2 overflow-x-auto rounded bg-ink px-3 py-2 font-mono text-[12.5px] text-white">
                    {cmd}
                  </pre>
                ))}
              </>
            )}
            {r.notes && <p className="mt-2 text-sm text-dim">{r.notes}</p>}
          </section>
        )}

        {t.verification ? (
          <Verify v={t.verification} />
        ) : (
          t.final_bucket === "NOW" && <p className="text-sm text-dim">이 조치안은 아직 샌드박스에서 검증하지 않았습니다.</p>
        )}
      </div>
    </article>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-2 border-b border-rule py-1">
      <dt className="text-dim">{k}</dt>
      <dd className="text-right">{v}</dd>
    </div>
  );
}

function Verify({ v }: { v: Verification }) {
  const test = v.steps.find((s) => s.name === "test");
  const tone = v.verdict === "verified" ? "border-ink" : v.verdict === "failed" ? "border-now" : "border-next";
  return (
    <section>
      <h3 className="text-sm font-semibold">샌드박스 검증</h3>
      <div className={`mt-2 rounded border-l-4 bg-paper px-3 py-2 ${tone}`}>
        <p className="font-semibold">{verdictLabel[v.verdict]}</p>
        <p className="text-sm">{reasonLabel[v.reason] ?? v.reason}</p>
      </div>
      <ol className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm">
        {v.steps.map((s) => (
          <li key={s.name} className="flex items-center gap-1.5">
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                s.status === "passed" ? "bg-ink" : s.status === "failed" ? "bg-now" : "bg-rule"
              }`}
              aria-hidden
            />
            {stepLabel[s.name] ?? s.name}{" "}
            <span className="text-dim">{{ passed: "통과", failed: "실패", skipped: "없음" }[s.status]}</span>
          </li>
        ))}
      </ol>
      <p className="mt-3 text-sm leading-relaxed">
        {v.tests_run > 0
          ? `실행된 테스트 ${v.tests_run}개.`
          : "테스트가 없어서 설치, 빌드, 재스캔까지만 확인했습니다."}{" "}
        {test?.status === "failed" && v.verdict === "verified" && (
          <>조치 전에도 실패하던 테스트 {test.failed_tests?.length ?? 0}개는 그대로이고 새로 실패한 테스트는 없습니다. </>
        )}
        {v.regressions.length > 0 && <>새로 실패: {v.regressions.join(", ")}. </>}
        <span className="text-dim">
          시도 {v.attempt}회, 새로 생긴 취약점 {v.new_findings.length}건. 테스트가 이 패키지를 쓰는 코드를 실행하지 않을 수 있습니다.
        </span>
      </p>
    </section>
  );
}
