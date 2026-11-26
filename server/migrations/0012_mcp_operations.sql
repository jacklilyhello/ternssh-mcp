CREATE VIEW mcp_active_targets AS
SELECT t.id AS token_id, t.user_id, s.id AS server_id, i.version AS identity_version, a.revision
FROM mcp_tokens t
JOIN mcp_authorizations a ON a.user_id = t.user_id
JOIN json_each(a.selection) item
JOIN servers s ON s.id = item.value ->> '$.id' AND s.user_id = t.user_id
JOIN mcp_target_identities i ON i.server_id = s.id AND i.version = item.value ->> '$.identityVersion';

-- A diagnostic request ID remains spent for the lifetime of its pairing.
CREATE TABLE mcp_diagnostic_requests (
  token_id TEXT NOT NULL REFERENCES mcp_tokens(id) ON DELETE CASCADE,
  request_id TEXT NOT NULL,
  PRIMARY KEY (token_id, request_id)
);

-- File handles name only objects committed by this feature. Replacing one creates
-- a new immutable storage object and atomically changes the handle's version.
CREATE TABLE mcp_files (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  identity_version TEXT NOT NULL,
  storage_id TEXT NOT NULL UNIQUE,
  bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND 1048576),
  sha256 TEXT NOT NULL
);

CREATE TABLE mcp_transfers (
  id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL REFERENCES mcp_tokens(id) ON DELETE CASCADE,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  identity_version TEXT NOT NULL,
  revision INTEGER NOT NULL,
  direction TEXT NOT NULL CHECK(direction IN ('upload','download')),
  file_id TEXT NOT NULL,
  storage_id TEXT NOT NULL,
  previous_id TEXT,
  bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND 1048576),
  sha256 TEXT NOT NULL,
  expires INTEGER NOT NULL,
  claimed INTEGER NOT NULL DEFAULT 0 CHECK(claimed IN (0,1))
);
CREATE INDEX idx_mcp_transfers_expires ON mcp_transfers(expires);

-- Keep existing inventory history when extending the audit result constraint.
DROP TRIGGER mcp_trim_recent_calls;
DROP INDEX idx_mcp_recent_calls_user;
ALTER TABLE mcp_recent_calls RENAME TO mcp_list_history;
CREATE TABLE mcp_recent_calls (
  id INTEGER PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  target TEXT,
  result TEXT NOT NULL CHECK (result IN ('listed','completed','failed','timeout','unknown','uploaded','downloaded'))
);
CREATE INDEX idx_mcp_recent_calls_user ON mcp_recent_calls(user_id, id DESC);

CREATE TRIGGER mcp_trim_recent_calls AFTER INSERT ON mcp_recent_calls
BEGIN
  DELETE FROM mcp_recent_calls WHERE id IN (
    SELECT id FROM mcp_recent_calls WHERE user_id = NEW.user_id
      ORDER BY id DESC LIMIT -1 OFFSET 20
  );
END;

INSERT INTO mcp_recent_calls (id,user_id,at,result)
SELECT id,user_id,at,result FROM mcp_list_history ORDER BY id;
DROP TABLE mcp_list_history;
