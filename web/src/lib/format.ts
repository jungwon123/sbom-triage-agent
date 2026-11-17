import type { Bucket, Item } from "./api";
import type { Triage, Verification } from "./types";

export const BUCKETS: Bucket[] = ["NOW", "NEXT", "MONITOR"];

export const bucketMeaning: Record<Bucket, string> = {
  NOW: "이번 주에 조치",
  NEXT: "다음 스프린트에 조치",
  MONITOR: "계속 지켜보기",
};

export const bucketColor: Record<Bucket, { bar: string; soft: string; text: string }> = {
  NOW: { bar: "bg-now", soft: "bg-now-soft", text: "text-now" },
  NEXT: { bar: "bg-next", soft: "bg-next-soft", text: "text-next" },
  MONITOR: { bar: "bg-monitor", soft: "bg-monitor-soft", text: "text-monitor" },
};

export const reachLabel: Record<Triage["reachability"], string> = {
  used_symbol: "취약한 코드를 사용함",
  imported_only: "import만 함",
  unused: "운영 코드에서 쓰지 않음",
  unknown: "사용 여부 판단 못 함",
};

export const decidedLabel: Record<NonNullable<Triage["decided_by"]>, string> = {
  rule: "규칙으로 분류",
  agent: "AI가 코드를 읽고 판단",
  agent_fallback: "AI 판단 실패, 규칙 결과 사용",
};

export const verdictLabel: Record<Verification["verdict"], string> = {
  verified: "검증 통과",
  failed: "검증 실패",
  inconclusive: "판단 불가",
};

export const reasonLabel: Record<string, string> = {
  ok: "취약점이 사라졌고 새로 깨진 것이 없습니다.",
  target_remains: "조치 후에도 대상 취약점이 남아 있습니다.",
  new_now: "조치 후 새 고위험 취약점이 생겼습니다.",
  regression: "조치 전에는 통과하던 빌드나 테스트가 실패했습니다.",
  install_failed: "의존성 설치에 실패했습니다.",
  apply_failed: "조치 적용에 실패했습니다.",
  timeout: "시간 상한을 넘겨 중단했습니다.",
  mitigation_only: "적용할 수정 버전이 없어 검증하지 않았습니다.",
  baseline_test_uncomparable: "조치 전 테스트 결과에서 테스트 이름을 얻지 못해 비교할 수 없습니다.",
  baseline_build_failed: "조치 전에도 빌드가 실패하던 상태입니다.",
};

export const stepLabel: Record<string, string> = {
  copy: "복사", apply: "조치 적용", install: "설치", setup: "설정", build: "빌드", test: "테스트", rescan: "재스캔",
};

export const fmtCvss = (v: number | null) => (v === null ? "없음" : v.toFixed(1));
export const fmtEpss = (p: number | null) => (p === null ? "없음" : `상위 ${Math.max(1, Math.round((1 - p) * 100))}%`);

const order: Record<Bucket, number> = { NOW: 0, NEXT: 1, MONITOR: 2 };
export const byPriority = (a: Item, b: Item) =>
  order[a.triage.final_bucket] - order[b.triage.final_bucket] || b.triage.risk - a.triage.risk;
export const byCvss = (a: Item, b: Item) => (b.finding.cvss ?? -1) - (a.finding.cvss ?? -1) || b.triage.risk - a.triage.risk;
