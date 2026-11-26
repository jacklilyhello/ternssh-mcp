// Only the CI bundle for the rolling-output test resolves the job's SSH import here.
export { fixedDiagnosticCommand, isMcpDiagnostic, McpSshError } from "../../src/lib/mcp-ssh.ts";

export async function openPinnedMcpSession() {
  return {
    async execCommand(_command, _timeout, check, _limit, append) {
      await check();
      for (const [part, stream] of [["first", "stdout"], ["next", "stdout"], ["error", "stderr"], ["last", "stdout"]]) {
        const response = await fetch("https://peer.invalid/" + part);
        if (!response.ok) throw new Error("Fixture output unavailable");
        append(stream, new Uint8Array(await response.arrayBuffer()));
      }
      return { exitCode: 23 };
    },
    close() {},
  };
}
