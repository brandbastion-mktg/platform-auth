// Types for platform-auth.
//
// The module ships as plain .mjs so every application can use it whatever its
// language; this declaration is for the TypeScript ones. Only the
// framework-agnostic core is declared, which is all an application needs when
// it serves with node:http and does its own cookie and redirect glue.
export const CLIENT_VERSION: string;

export interface HandoffClaims {
  userId: string;
  email: string;
  appId: string;
}

export interface SessionUser {
  id: string;
  email: string;
}

/** Verify a handoff token minted by the platform. `expectedApp` is required. */
export function verifyHandoff(
  token: string | null | undefined,
  expectedApp: string,
  secret: string,
  opts?: { now?: number },
): HandoffClaims | null;

export interface PlatformAuth {
  /** Mint this applet's own session value. */
  issue(input: { userId: string; email: string; now?: number }): string;
  /** Read this applet's own session value, or null. */
  read(value: string | null | undefined, opts?: { now?: number }): SessionUser | null;
  appId: string;
  version: string;
  attach: unknown;
  required: unknown;
  handoff: unknown;
  signOut: unknown;
}

export function platformAuth(config: {
  appId: string;
  secret: string | undefined;
  platformUrl: string;
  cookieName: string;
  sessionHours?: number;
}): PlatformAuth;
