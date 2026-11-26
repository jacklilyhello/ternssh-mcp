-- A receipt keeps its batch ID spent for the lifetime of this pairing.
-- Erasing a command body never makes an old ID available for a new proposal.
CREATE TABLE mcp_command_batches (
  token_id TEXT NOT NULL REFERENCES mcp_tokens(id) ON DELETE CASCADE,
  batch_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id TEXT NOT NULL,
  server_name TEXT NOT NULL,
  revision INTEGER NOT NULL,
  identity_version TEXT NOT NULL,
  timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 600000),
  digest TEXT NOT NULL CHECK (length(digest) = 64),
  challenge TEXT NOT NULL DEFAULT (lower(hex(randomblob(32))))
    CHECK (length(challenge) = 64 AND challenge NOT GLOB '*[^0-9a-f]*'),
  commands TEXT CHECK (commands IS NULL OR (json_valid(commands) AND json_type(commands) = 'array')),
  expires INTEGER NOT NULL,
  PRIMARY KEY (token_id, batch_id)
);
CREATE INDEX mcp_batch_expiry ON mcp_command_batches(expires) WHERE commands IS NOT NULL;
CREATE INDEX mcp_batch_user ON mcp_command_batches(user_id) WHERE commands IS NOT NULL;
CREATE INDEX mcp_batch_server ON mcp_command_batches(server_id) WHERE commands IS NOT NULL;

CREATE TRIGGER mcp_batch_immutable_receipt
BEFORE UPDATE OF token_id,batch_id,user_id,server_id,server_name,revision,identity_version,timeout_ms,digest,challenge,expires
ON mcp_command_batches
BEGIN
  SELECT RAISE(ABORT, 'Immutable proposal receipt');
END;

CREATE TRIGGER mcp_batch_erase_only BEFORE UPDATE OF commands ON mcp_command_batches
WHEN NEW.commands IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'Immutable proposal content');
END;

CREATE TRIGGER mcp_batch_new_grant AFTER UPDATE OF revision ON mcp_authorizations
WHEN NEW.revision != OLD.revision
BEGIN
  UPDATE mcp_command_batches SET commands = NULL WHERE user_id = OLD.user_id AND commands IS NOT NULL;
END;

CREATE TRIGGER mcp_batch_removed_grant AFTER DELETE ON mcp_authorizations
BEGIN
  UPDATE mcp_command_batches SET commands = NULL WHERE user_id = OLD.user_id AND commands IS NOT NULL;
END;

CREATE TRIGGER mcp_batch_changed_identity AFTER UPDATE OF version ON mcp_target_identities
WHEN NEW.version != OLD.version
BEGIN
  UPDATE mcp_command_batches SET commands = NULL WHERE server_id = OLD.server_id AND commands IS NOT NULL;
END;

CREATE TRIGGER mcp_batch_removed_identity AFTER DELETE ON mcp_target_identities
BEGIN
  UPDATE mcp_command_batches SET commands = NULL WHERE server_id = OLD.server_id AND commands IS NOT NULL;
END;
