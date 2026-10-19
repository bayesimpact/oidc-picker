// Reads and checks the configuration: the issuer, the clients that may sign in, and the profiles
// shown on the picker. Profiles can live in their own file, read again whenever it changes.
import { readFileSync, statSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { parse } from "yaml"

export interface Profile {
  sub: string
  email: string
  name?: string
  description?: string
  /** Extra claims, added to the ID token, the access token and the userinfo response. */
  claims?: Record<string, unknown>
}

export interface ClientConfig {
  id: string
  /** Absent for a public client (authorization code with PKCE). */
  secret?: string
  /** Exact URIs, or patterns where `*` matches any characters except `/`, `?` and `#`. */
  redirectUris: string[]
  postLogoutRedirectUris: string[]
}

export interface Config {
  issuer: string
  port: number
  /** Address the HTTP server listens on. Use 0.0.0.0 inside a container. */
  host: string
  /** Audience (`aud`) of the access tokens. */
  audience: string
  /** Show the picker on every interactive sign-in, even when a session exists. */
  alwaysPick: boolean
  /** Accept grant_type=password for scripts. The password is ignored. */
  passwordGrant: boolean
  /**
   * The header a gatekeeper in front of the picker sets to the person it signed in (an
   * oauth2-proxy's X-Auth-Request-Email, for instance). When set, the picker and its sign-in pages
   * refuse a request without it, and log who picked which profile; the password grant is off.
   */
  actorHeader?: string
  /** Signing and cookie keys are kept here, so a restart keeps tokens valid. */
  keysFile?: string
  clients: ClientConfig[]
  /** Returns the current profiles, read again from `profilesFile` when it changed. */
  profiles: () => Profile[]
}

const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"])

/** True for the hosts of a local machine: anyone who reaches the server can sign in as anyone. */
export function isLocalHostname(hostname: string): boolean {
  return (
    LOCAL_HOSTNAMES.has(hostname) || hostname.endsWith(".localhost") || hostname.endsWith(".test")
  )
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): Config {
  const raw = parse(readFileSync(path, "utf8")) ?? {}
  return buildConfig(raw, { baseDir: dirname(resolve(path)), env })
}

export function buildConfig(
  raw: Record<string, any>,
  { baseDir = process.cwd(), env = process.env }: { baseDir?: string; env?: NodeJS.ProcessEnv } = {},
): Config {
  const port = Number(env.OIDC_PICKER_PORT ?? raw.port ?? 5556)
  const issuer = trimTrailingSlash(String(env.OIDC_PICKER_ISSUER ?? raw.issuer ?? `http://localhost:${port}`))
  const issuerUrl = new URL(issuer)
  const allowNonLocal = env.OIDC_PICKER_ALLOW_NON_LOCAL_ISSUER === "1" || raw.allowNonLocalIssuer === true
  if (!isLocalHostname(issuerUrl.hostname) && !allowNonLocal) {
    throw new Error(
      `The issuer ${issuer} is not on a local host. oidc-picker signs in anyone without a password: ` +
        "it is for local development only. Set allowNonLocalIssuer: true to override.",
    )
  }

  const actorHeader = raw.actorHeader === undefined ? undefined : String(raw.actorHeader).toLowerCase()

  const clients = asArray(raw.clients, "clients").map(readClient)
  if (clients.length === 0) {
    throw new Error("The configuration has no client")
  }

  const inlineProfiles = raw.profiles === undefined ? undefined : asArray(raw.profiles, "profiles").map(readProfile)
  const profilesFile = raw.profilesFile === undefined ? undefined : resolve(baseDir, String(raw.profilesFile))
  if (inlineProfiles === undefined && profilesFile === undefined) {
    throw new Error("The configuration needs profiles or profilesFile")
  }

  return {
    issuer,
    port,
    host: String(env.OIDC_PICKER_HOST ?? raw.host ?? "127.0.0.1"),
    audience: String(raw.audience ?? `${issuer}/api`),
    alwaysPick: raw.alwaysPick ?? true,
    // A script's password grant would go around the gatekeeper.
    passwordGrant: actorHeader ? false : (raw.passwordGrant ?? true),
    actorHeader,
    keysFile: raw.keysFile === undefined ? undefined : resolve(baseDir, String(raw.keysFile)),
    clients,
    profiles: profilesFile ? watchedProfiles(profilesFile, inlineProfiles ?? []) : () => inlineProfiles ?? [],
  }
}

/** Inline profiles first, then the ones of the file. The file is parsed again when its mtime changes. */
function watchedProfiles(file: string, inline: Profile[]): () => Profile[] {
  let mtime = -1
  let cached: Profile[] = []
  return () => {
    const current = statSync(file).mtimeMs
    if (current !== mtime) {
      const raw = parse(readFileSync(file, "utf8")) ?? []
      cached = asArray(Array.isArray(raw) ? raw : raw.profiles, "profiles").map(readProfile)
      mtime = current
    }
    return uniqueBySub([...inline, ...cached])
  }
}

function readClient(raw: any, index: number): ClientConfig {
  const id = raw?.id
  if (typeof id !== "string" || id === "") {
    throw new Error(`clients[${index}] needs an id`)
  }
  const redirectUris = asArray(raw.redirectUris, `clients[${index}].redirectUris`).map(String)
  if (redirectUris.length === 0) {
    throw new Error(`clients[${index}] needs at least one redirect URI`)
  }
  return {
    id,
    secret: raw.secret === undefined ? undefined : String(raw.secret),
    redirectUris,
    postLogoutRedirectUris: asArray(raw.postLogoutRedirectUris ?? redirectUris, "postLogoutRedirectUris").map(String),
  }
}

function readProfile(raw: any, index: number): Profile {
  const email = raw?.email
  if (typeof email !== "string" || !email.includes("@")) {
    throw new Error(`profiles[${index}] needs an email`)
  }
  return {
    sub: String(raw.sub ?? email),
    email,
    name: raw.name === undefined ? undefined : String(raw.name),
    description: raw.description === undefined ? undefined : String(raw.description),
    claims: raw.claims ?? undefined,
  }
}

function asArray(value: unknown, name: string): any[] {
  if (value === undefined || value === null) return []
  if (!Array.isArray(value)) throw new Error(`${name} must be a list`)
  return value
}

function uniqueBySub(profiles: Profile[]): Profile[] {
  const seen = new Map<string, Profile>()
  for (const profile of profiles) if (!seen.has(profile.sub)) seen.set(profile.sub, profile)
  return [...seen.values()]
}

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/u, "")
}
