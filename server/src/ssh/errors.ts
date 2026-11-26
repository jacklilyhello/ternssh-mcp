/** An operation failure whose message is safe for the calling client. */
export class SshOperationError extends Error {
  constructor(message: string, readonly timedOut = false) {
    super(message);
    this.name = "SshOperationError";
  }
}
