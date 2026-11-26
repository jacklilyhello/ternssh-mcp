-- The web owner binds one approval key to one client token. Rotation requires
-- revocation and a new pairing, so an old receipt cannot move to another key.
CREATE TABLE mcp_batch_keys (
  token_id TEXT PRIMARY KEY REFERENCES mcp_tokens(id) ON DELETE CASCADE,
  spki TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64)
);
CREATE TRIGGER mcp_batch_key_immutable BEFORE UPDATE ON mcp_batch_keys
BEGIN
  SELECT RAISE(ABORT, 'Approval key already registered');
END;

CREATE TABLE mcp_batch_approvals (
  token_id TEXT NOT NULL REFERENCES mcp_batch_keys(token_id) ON DELETE CASCADE,
  batch_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  commands TEXT CHECK (commands IS NULL OR (json_valid(commands) AND json_type(commands) = 'array')),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (token_id, batch_id),
  FOREIGN KEY (token_id, batch_id) REFERENCES mcp_command_batches(token_id, batch_id) ON DELETE CASCADE
);
CREATE INDEX mcp_approval_expiry ON mcp_batch_approvals(expires_at) WHERE commands IS NOT NULL;

CREATE TRIGGER mcp_signed_batch_immutable BEFORE UPDATE OF token_id,batch_id,digest,fingerprint,expires_at ON mcp_batch_approvals
BEGIN
  SELECT RAISE(ABORT, 'Immutable batch approval');
END;
CREATE TRIGGER mcp_signed_batch_erase_only BEFORE UPDATE OF commands ON mcp_batch_approvals
WHEN NEW.commands IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'Immutable approved commands');
END;

CREATE TRIGGER mcp_signed_batch_grant AFTER UPDATE OF revision ON mcp_authorizations
WHEN OLD.revision != NEW.revision
BEGIN
  UPDATE mcp_batch_approvals SET commands=NULL WHERE commands IS NOT NULL AND token_id IN (
    SELECT id FROM mcp_tokens WHERE user_id=OLD.user_id
  );
END;
CREATE TRIGGER mcp_signed_batch_grant_deleted AFTER DELETE ON mcp_authorizations
BEGIN
  UPDATE mcp_batch_approvals SET commands=NULL WHERE commands IS NOT NULL AND token_id IN (
    SELECT id FROM mcp_tokens WHERE user_id=OLD.user_id
  );
END;
CREATE TRIGGER mcp_signed_batch_identity AFTER UPDATE OF version ON mcp_target_identities
WHEN OLD.version != NEW.version
BEGIN
  UPDATE mcp_batch_approvals SET commands=NULL WHERE commands IS NOT NULL AND (token_id,batch_id) IN (
    SELECT token_id,batch_id FROM mcp_command_batches WHERE server_id=OLD.server_id
  );
END;
CREATE TRIGGER mcp_signed_batch_identity_deleted AFTER DELETE ON mcp_target_identities
BEGIN
  UPDATE mcp_batch_approvals SET commands=NULL WHERE commands IS NOT NULL AND (token_id,batch_id) IN (
    SELECT token_id,batch_id FROM mcp_command_batches WHERE server_id=OLD.server_id
  );
END;
