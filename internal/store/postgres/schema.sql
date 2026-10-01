-- mcpsight index schema (Greyquill Software). Plan §7.
-- Idempotent: safe to run on every startup. Plain SQL, no ORM.
--
-- Every scan records both mcpsight_version and rubric_version so historical grades
-- stay interpretable when the rubric changes — we never silently re-grade.

CREATE TABLE IF NOT EXISTS servers (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source        TEXT NOT NULL,              -- npm | pypi | oci | http
    identifier    TEXT NOT NULL,              -- package spec or URL
    canonical_url TEXT,
    registry      TEXT,                        -- official | smithery | ...
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, identifier)
);

CREATE TABLE IF NOT EXISTS scans (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_id      BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    version        TEXT,                        -- server-reported version
    scanned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    mcpsight_version   TEXT NOT NULL,
    rubric_version INT  NOT NULL,
    score          INT  NOT NULL,
    grade          TEXT NOT NULL,
    manifest_hash  TEXT NOT NULL,
    duration_ms    BIGINT NOT NULL DEFAULT 0,
    manifest_json  JSONB                        -- kept to diff consecutive scans for drift
);
CREATE INDEX IF NOT EXISTS scans_server_time ON scans (server_id, scanned_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id     BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    analyzer    TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail_json JSONB,
    tool_name   TEXT
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings (scan_id);

CREATE TABLE IF NOT EXISTS tool_defs (
    id                        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id                   BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name                      TEXT NOT NULL,
    description               TEXT,
    schema_json               JSONB,
    token_count_by_model_json JSONB
);
CREATE INDEX IF NOT EXISTS tool_defs_scan ON tool_defs (scan_id);

CREATE TABLE IF NOT EXISTS drift_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_id    BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    from_scan_id BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    to_scan_id   BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    diff_json    JSONB,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS drift_events_server ON drift_events (server_id, detected_at DESC);
