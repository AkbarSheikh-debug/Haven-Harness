export class HnError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    this.name = new.target.name;
  }
}

/** A second writer tried to open a session that already has one. */
export class SessionAlreadyOwnedError extends HnError {
  constructor(sessionId: string) {
    super('SESSION_ALREADY_OWNED', `Session ${sessionId} already has a writer.`);
  }
}

/** The log was written by a newer version. Never guess at a newer format. */
export class SessionVersionError extends HnError {
  constructor(found: number, supported: number) {
    super('SESSION_VERSION', `Log version ${found} is newer than supported version ${supported}.`);
  }
}

/** The log failed verification, so it cannot be written to. */
export class SessionUnverifiedError extends HnError {
  constructor(path: string) {
    super('SESSION_UNVERIFIED', `Log ${path} failed verification. It can be read but not written.`);
  }
}

/** The log could not be made durable. No model call or tool may run. */
export class FlushFailedError extends HnError {
  constructor(cause: unknown) {
    super('FLUSH_FAILED', 'Could not make the session log durable.', { cause });
  }
}

export class ForkBoundaryError extends HnError {
  constructor(seq: number) {
    super('FORK_BOUNDARY', `Cannot fork at seq ${seq}: it is not a closed, balanced step.`);
  }
}
