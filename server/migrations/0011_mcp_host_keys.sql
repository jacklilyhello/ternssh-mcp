CREATE TABLE mcp_host_keys (
  server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  identity_version TEXT NOT NULL,
  fingerprint TEXT NOT NULL
);
