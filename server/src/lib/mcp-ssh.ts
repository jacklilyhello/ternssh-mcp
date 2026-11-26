import { getPinnedMcpConfig, type McpTarget } from "../db/mcp-host-keys";
import { ExecCompletionError, SSHSession } from "../ssh/session";
import { SshOperationError as McpSshError } from "../ssh/errors";
import { connectToHost } from "./resolve-host";

export type { McpTarget } from "../db/mcp-host-keys";
const diagnostics = {
  utc: "/bin/date -u '+%Y-%m-%dT%H:%M:%SZ'",
  system_name: "/bin/uname -s",
  check_exit: "printf '%s\\n' 'ternssh diagnostic' >&2; exit 1",
} as const;
export type McpDiagnostic = keyof typeof diagnostics;
export interface McpDiagnosticResult {
  status: "completed" | "failed" | "timeout" | "unknown";
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  error?: string;
  outputTruncated?: true;
}

export { McpSshError };

export function isMcpDiagnostic(value: unknown): value is McpDiagnostic {
  return typeof value === "string" && Object.hasOwn(diagnostics, value);
}

export function fixedDiagnosticCommand(diagnostic: McpDiagnostic): string {
  if (!isMcpDiagnostic(diagnostic)) throw new McpSshError("Unknown diagnostic");
  return diagnostics[diagnostic];
}

export function executeFixedDiagnostic(session: SSHSession, diagnostic: McpDiagnostic, check: () => Promise<void>) {
  return session.execCommand(fixedDiagnosticCommand(diagnostic), 10_000, check, 16 * 1024);
}

export async function openPinnedMcpSession(
  db: D1Database, target: McpTarget, recheck: () => Promise<void>, signal?: AbortSignal,
): Promise<SSHSession> {
  signal?.throwIfAborted();
  await recheck();
  const config = await getPinnedMcpConfig(db, target);
  signal?.throwIfAborted();
  if (!config) throw new McpSshError("An authenticated web SSH connection with a verified host key is required");

  const deadline = AbortSignal.timeout(20_000);
  const connectionSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  let socket;
  try {
    socket = await connectToHost(config.host, config.port, connectionSignal);
  } catch {
    signal?.throwIfAborted();
    if (deadline.aborted) throw new McpSshError("SSH connection timed out", true);
    throw new McpSshError("SSH connection failed");
  }

  let onDeadline: (() => void) | undefined;
  try {
    return await new Promise<SSHSession>((resolve, reject) => {
      const session: SSHSession = new SSHSession({ send() {}, close() {} }, socket, config, true, false, undefined, true, {
        beforeCredentials: async () => {
          try { await recheck(); } catch (error) {
            reject(error);
            throw new McpSshError("Authorization changed");
          }
        },
        authenticated: () => resolve(session),
        closed: (failure) => {
          const message = failure === "host_key" ? "SSH host key verification failed"
            : failure === "authentication" ? "SSH authentication failed" : "SSH connection closed";
          reject(new McpSshError(message));
        },
      });
      onDeadline = () => {
        reject(signal?.aborted ? signal.reason : new McpSshError("SSH authentication timed out", true));
        session.close();
      };
      connectionSignal.addEventListener("abort", onDeadline, { once: true });
      if (connectionSignal.aborted) return onDeadline();
      void session.startHandshake().catch(() => session.close());
    });
  } finally {
    if (onDeadline) connectionSignal.removeEventListener("abort", onDeadline);
  }
}

export async function runMcpDiagnostic(
  db: D1Database, target: McpTarget, diagnostic: McpDiagnostic, recheck: () => Promise<void>,
): Promise<McpDiagnosticResult> {
  if (!isMcpDiagnostic(diagnostic)) throw new McpSshError("Unknown diagnostic");
  let session: SSHSession | undefined;
  let authorizationError: unknown;
  const check = async () => {
    try { await recheck(); } catch (error) {
      authorizationError = error;
      throw error;
    }
  };
  try {
    session = await openPinnedMcpSession(db, target, check);
    const result = await executeFixedDiagnostic(session, diagnostic, check);
    return { status: result.exitCode === 0 ? "completed" : "failed", ...result, signal: null };
  } catch (error) {
    if (authorizationError) throw authorizationError;
    if (error instanceof ExecCompletionError) {
      const { stdout, stderr, exitCode, signal } = error;
      const status = error.timedOut ? "timeout" : signal !== null || exitCode !== null ? "failed" : "unknown";
      return { status, stdout, stderr, exitCode, signal, error: error.message,
        ...(error.outputTruncated ? { outputTruncated: true } : {}) };
    }
    const timedOut = error instanceof McpSshError && error.timedOut;
    return { status: timedOut ? "timeout" : "failed", stdout: "", stderr: "", exitCode: null,
      signal: null, error: error instanceof McpSshError ? error.message : "SSH diagnostic could not start" };
  } finally {
    session?.close();
  }
}
