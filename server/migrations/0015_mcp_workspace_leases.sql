-- Diagnostic and workspace requests share a pairing-scoped, single-use ID.
-- Only workspace rows occupy a host slot and count towards the hourly quota.
ALTER TABLE mcp_diagnostic_requests ADD COLUMN workspace_server_id TEXT;
ALTER TABLE mcp_diagnostic_requests ADD COLUMN workspace_started_at INTEGER;
ALTER TABLE mcp_diagnostic_requests ADD COLUMN workspace_lease_until INTEGER;
CREATE INDEX mcp_workspace_slots ON mcp_diagnostic_requests(workspace_server_id, workspace_lease_until)
  WHERE workspace_lease_until IS NOT NULL;
CREATE INDEX mcp_workspace_recent ON mcp_diagnostic_requests(workspace_server_id, workspace_started_at)
  WHERE workspace_started_at IS NOT NULL;
