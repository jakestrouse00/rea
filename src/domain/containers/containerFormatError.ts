export type ContainerFailureKind = "format" | "limit" | "unsupported";

/** A malformed or over-bounded container observation, distinct from file I/O. */
export class ContainerFormatError extends Error {
  constructor(
    readonly kind: ContainerFailureKind,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ContainerFormatError";
  }
}

/** Fail closed when a bounded read exceeds its declared byte budget. */
export const containerLimitError = (
  subject: string,
  observedBytes: number,
  maximumBytes: number,
): ContainerFormatError =>
  new ContainerFormatError(
    "limit",
    `${subject} requires ${String(observedBytes)} bytes, exceeding the ${String(maximumBytes)}-byte read budget`,
  );
