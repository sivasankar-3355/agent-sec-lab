export class AppError extends Error {
  readonly code: string;
  readonly status: number;
  readonly causes: readonly string[];

  constructor(code: string, message: string, status = 500, causes: readonly string[] = []) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.status = status;
    this.causes = causes;
  }

  toResponse(): { code: string; message: string; causes?: string[] } {
    const body: { code: string; message: string; causes?: string[] } = {
      code: this.code,
      message: this.message,
    };
    if (this.causes.length > 0) body.causes = [...this.causes];
    return body;
  }
}

export class NotConfiguredError extends AppError {
  constructor(message: string) {
    super("not_configured", message, 500);
  }
}

export class SandboxUnavailableError extends AppError {
  constructor(message = "sandbox control not available") {
    super("sandbox_unavailable", message, 503);
  }
}

export class AuthorizationDeniedError extends AppError {
  constructor(message = "authorization denied") {
    super("forbidden", message, 403);
  }
}

export class PolicyViolationError extends AppError {
  constructor(message: string) {
    super("policy_violation", message, 403);
  }
}

export class EgressDeniedError extends AppError {
  constructor(message = "egress not permitted") {
    super("egress_denied", message, 403);
  }
}

export class UnauthenticatedError extends AppError {
  constructor(message = "missing or invalid token") {
    super("unauthorized", message, 401);
  }
}

export class ValidationError extends AppError {
  constructor(message: string) {
    super("validation_error", message, 422);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string) {
    super("not_found", message, 404);
  }
}

export class A2AError extends AppError {
  constructor(message: string, status = 502) {
    super("a2a_error", message, status);
  }
}
