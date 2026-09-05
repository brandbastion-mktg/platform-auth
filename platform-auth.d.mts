// Types for platform-auth.
//
// The module ships as plain .mjs so every application can use it whatever its
// language; this declaration is for the TypeScript ones. Only the
// framework-agnostic core is declared, which is all an application needs when
// it serves with node:http and does its own cookie and redirect glue.
import type { KeyObject } from 'node:crypto';

export const CLIENT_VERSION: string;

/**
 * The page ids a person may open inside this application.
 *
 * `null` means EVERY page, and is what a token or session minted before 1.2.0
 * carries. `[]` is the different, real answer of "no pages at all". Never test
 * these by hand: use `allows`, which is the one place that rule lives.
 */
export type PagePermissions = string[] | null;

/**
 * The ids of the OTHER applications a person may open, so a tool menu can leave
 * out the ones they cannot (1.3.0).
 *
 * `null` means EVERY tool, and is what a token or session minted before 1.3.0
 * carries. `[]` is the different, real answer of "no other tool at all". Never
 * test these by hand: use `holds`, which is the one place that rule lives.
 */
export type ToolPermissions = string[] | null;

export interface HandoffClaims {
  userId: string;
  email: string;
  appId: string;
  pages: PagePermissions;
  apps: ToolPermissions;
}

export interface SessionUser {
  id: string;
  email: string;
  pages: PagePermissions;
  apps: ToolPermissions;
}

/** Is `pageId` in the set the platform issued? `null` permissions allow everything. */
export function allows(pages: PagePermissions | undefined, pageId: string): boolean;

/** Does this person hold the application `appId`? `null` permissions mean every tool. */
export function holds(apps: ToolPermissions | undefined, appId: string): boolean;

/**
 * The platform's public key (2.0.0): 32 raw bytes as base64url, or a PEM, or an
 * existing KeyObject. Not secret; configuration.
 */
export function publicKeyFromRaw(raw: string | KeyObject): KeyObject;

/**
 * What a handoff token is checked against (2.0.0). A `v2.` token is checked
 * against `publicKey` and nothing else; any other token against `secret` and
 * nothing else. A plain string is the pre-2.0.0 form and means `secret`.
 */
export type HandoffKeys = string | { publicKey?: string | KeyObject | null; secret?: string | null };

/** Verify a handoff token minted by the platform. `expectedApp` is required. */
export function verifyHandoff(
  token: string | null | undefined,
  expectedApp: string,
  keys: HandoffKeys,
  opts?: { now?: number },
): HandoffClaims | null;

export interface PlatformAuth {
  /** Mint this applet's own session value. */
  issue(input: {
    userId: string; email: string; pages?: PagePermissions; apps?: ToolPermissions; now?: number;
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
  /** THIS application's own session secret (32+ chars). */
  secret: string | undefined;
  /** The platform's public key (2.0.0). Without it only shared-secret handoffs are accepted. */
  publicKey?: string | KeyObject | null;
  platformUrl: string;
  cookieName: string;
  sessionHours?: number;
}): PlatformAuth;
