import { bucketColor, changeLabel } from "../lib/format";
import type { Change } from "../lib/types";

interface Props {
  changes: Change[];
  /** When given, a change whose finding is still in the run becomes a button that selects it. */
  onSelect?: (findingId: string) => void;
}

/** What a re-check found, one line per change: package, vulnerability, what moved. */
export default function Changes({ changes, onSelect }: Props) {
  return (
    <ul className="mt-2 space-y-1 text-sm">
      {changes.map((c) => {
        const bucket = c.after ?? c.before;
        const name = `${c.package} ${c.version}`;
        return (
          <li key={`${c.finding_id}:${c.kind}`} className="flex flex-wrap items-baseline gap-x-2">
            <span className="w-[7.5em] shrink-0 font-semibold">{changeLabel[c.kind]}</span>
            {onSelect && c.kind !== "removed" ? (
              <button type="button" className="text-link underline" onClick={() => onSelect(c.finding_id)}>
                {name}
              </button>
            ) : (
              <span>{name}</span>
            )}
            <span className="font-mono text-[12.5px] text-dim">{c.vuln_id}</span>
            {c.before && c.after && c.before !== c.after ? (
              <span>
                {c.before} → <span className={`font-semibold ${bucketColor[c.after].text}`}>{c.after}</span>
              </span>
            ) : (
              bucket && <span className={bucketColor[bucket].text}>{bucket}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
