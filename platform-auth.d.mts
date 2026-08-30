// Types for platform-auth.
//
// The module ships as plain .mjs so every application can use it whatever its
// language; this declaration is for the TypeScript ones. Only the
// framework-agnostic core is declared, which is all an application needs when
// it serves with node:http and does its own cookie and redirect glue.
export const CLIENT_VERSION: string;

/**
 * The page ids a person may open inside this application.
 *
 * `null` means EVERY page, and is what a token or session minted before 1.2.0
 * carries. `[]` is the different, real answer of "no pages at all". Never test
 * these by hand: use `allows`, which is the one place that rule lives.
 */
export type PagePermissions = string[] | null;

export interface HandoffClaims {
  userId: string;
  email: string;
  appId: string;
  pages: PagePermissions;
}

export interface SessionUser {
  id: string;
  email: string;
  pages: PagePermissions;
}

/** Is `pageId` in the set the platform issued? `null` permissions allow everything. */
export function allows(pages: PagePermissions | undefined, pageId: string): boolean;

/** Verify a handoff token minted by the platform. `expectedApp` is required. */
export function verifyHandoff(
  token: string | null | undefined,
  expectedApp: string,
  secret: string,
  opts?: { now?: number },
): HandoffClaims | null;

export interface PlatformAuth {
  /** Mint this applet's own session value. */
  issue(input: {
    userId: string; email: string; pages?: PagePermissions; now?: number;
  }): string;
  /** Read this applet's own session value, or null. */
  read(value: string | null | undefined, opts?: { now?: number }): SessionUser | null;
  /** `allows` bound to a request whose user `attach` has already set. */
  mayOpen(req: { user?: SessionUser | null } | null | undefined, pageId: string): boolean;
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
