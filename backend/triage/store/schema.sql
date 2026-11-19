-- SBOM Triage operating store. Applied by `triage db init`; every statement is safe to run again.
-- Columns hold what gets filtered and joined; `body` holds the full record as the code models it.

CREATE TABLE IF NOT EXISTS schema_version (
    version     integer PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS runs (
    id          text PRIMARY KEY,                 -- also the artifact directory name
    name        text,                             -- the service or repository the run is about
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    meta        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS runs_name_created ON runs (name, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    run_id           text NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    finding_id       text NOT NULL,
    seq              integer NOT NULL,            -- order within the run
    ecosystem        text NOT NULL,
    package          text NOT NULL,
    version          text NOT NULL,
    vuln_id          text NOT NULL,
    aliases          text[] NOT NULL DEFAULT '{}',
    scope            text NOT NULL,
    direct           boolean NOT NULL,
    cvss             double precision,
    epss_percentile  double precision,
    kev              boolean NOT NULL,
    body             jsonb NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);
CREATE INDEX IF NOT EXISTS findings_package ON findings (lower(package), version);
CREATE INDEX IF NOT EXISTS findings_vuln ON findings (vuln_id);
CREATE INDEX IF NOT EXISTS findings_aliases ON findings USING gin (aliases);

CREATE TABLE IF NOT EXISTS triage (
    run_id        text NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    finding_id    text NOT NULL,
    seq           integer NOT NULL,
    rule_bucket   text NOT NULL,
    final_bucket  text NOT NULL,
    risk          integer NOT NULL,
    decided_by    text NOT NULL,
    needs_review  boolean NOT NULL,
    verdict       text,                           -- sandbox verdict, when there is one
    body          jsonb NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);
CREATE INDEX IF NOT EXISTS triage_bucket ON triage (run_id, final_bucket);

CREATE TABLE IF NOT EXISTS events (
    id      bigserial PRIMARY KEY,
    run_id  text NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    ts      double precision NOT NULL,
    body    jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS events_run ON events (run_id, id);

-- Append-only: the application never updates or deletes a decision. The latest row per target wins.
CREATE TABLE IF NOT EXISTS decisions (
    id          bigserial PRIMARY KEY,
    run_id      text NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    target      text NOT NULL,                    -- "<package>@<version>"
    status      text NOT NULL CHECK (status IN ('approved', 'rejected', 'held')),
    decided_by  text NOT NULL,
    reason      text NOT NULL DEFAULT '',
    decided_at  timestamptz NOT NULL,
    body        jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_run_target ON decisions (run_id, target, id);

CREATE TABLE IF NOT EXISTS http_cache (
    key         text PRIMARY KEY,                 -- sha256 of url + request body, same formula as the file cache
    url         text NOT NULL,
    body        jsonb NOT NULL,
    fetched_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_version (version) VALUES (1) ON CONFLICT DO NOTHING;
