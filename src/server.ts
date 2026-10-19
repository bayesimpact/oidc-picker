// The OpenID provider (node-oidc-provider) and the few routes around it: the profile picker,
// a userinfo endpoint that accepts the JWT access tokens, and a password grant for scripts.
import { randomUUID } from "node:crypto"
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"
import { createLocalJWKSet, importJWK, type JWK, jwtVerify, SignJWT } from "jose"
import Provider, { type ClientMetadata, errors, interactionPolicy } from "oidc-provider"
import type { ClientConfig, Config, Profile } from "./config.ts"
import { loadKeys } from "./keys.ts"
import { renderPicker } from "./picker.ts"

const ACCESS_TOKEN_TTL = 3600
const PRIVATE_JWK_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi"])

export interface Picker {
  provider: Provider
  server: Server
  listen: () => Promise<string>
  close: () => Promise<void>
}

export async function createPicker(config: Config): Promise<Picker> {
  const keys = await loadKeys(config.keysFile)
  const basePath = trimTrailingSlash(new URL(config.issuer).pathname)
  // The default resource of every authorization request: its access token is a JWT for it.
  const defaultResource = `${config.issuer}/api`
  const signingKey = await importJWK(keys.jwks.keys[0], "RS256")
  const verificationKeys = createLocalJWKSet({ keys: keys.jwks.keys.map(publicJwk) })

  const findProfile = (sub: string | undefined) => config.profiles().find((profile) => profile.sub === sub)

  const policy = interactionPolicy.base()
  if (config.alwaysPick) {
    // An existing session does not skip the picker, except for silent requests (prompt=none).
    policy.get("login")?.checks.push(
      new interactionPolicy.Check("pick_profile", "A profile must be picked", (ctx) =>
        ctx.oidc.prompts.has("none") || ctx.oidc.result?.login
          ? interactionPolicy.Check.NO_NEED_TO_PROMPT
          : interactionPolicy.Check.REQUEST_PROMPT,
      ),
    )
  }

  const extraClaimNames = [...new Set(config.profiles().flatMap((profile) => Object.keys(profile.claims ?? {})))]

  const provider = new Provider(config.issuer, {
    clients: config.clients.map((client) => clientMetadata(client, config.passwordGrant)),
    jwks: keys.jwks as any,
    cookies: { keys: keys.cookieKeys },
    findAccount: async (_ctx, sub) => {
      const profile = findProfile(sub)
      return profile ? { accountId: sub, claims: async () => claimsOf(profile) } : undefined
    },
    claims: {
      openid: ["sub"],
      email: ["email", "email_verified"],
      profile: ["name", "preferred_username", ...extraClaimNames],
    },
    scopes: ["openid", "offline_access", "profile", "email"],
    interactions: {
      policy,
      url: (_ctx, interaction) => `${basePath}/interaction/${interaction.uid}`,
    },
    features: {
      devInteractions: { enabled: false },
      rpInitiatedLogout: {
        enabled: true,
        // Signs out at once: no confirmation page in local development.
        logoutSource: async (ctx, form) => {
          const autoSubmit = form.replace("</form>", '<input type="hidden" name="logout" value="yes"></form>')
          ctx.body = `<!doctype html><html><body>${autoSubmit}<script>document.forms[0].submit()</script></body></html>`
        },
      },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => defaultResource,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, resourceIndicator) => ({
          scope: "",
          audience: resourceIndicator === defaultResource ? config.audience : resourceIndicator,
          accessTokenFormat: "jwt",
          accessTokenTTL: ACCESS_TOKEN_TTL,
          jwt: { sign: { alg: "RS256" } },
        }),
      },
    },
    extraTokenClaims: async (_ctx, token) => {
      const profile = findProfile((token as { accountId?: string }).accountId)
      return profile ? { email: profile.email, ...profile.claims } : undefined
    },
    pkce: { required: (_ctx, client) => client.clientAuthMethod === "none" },
    clientBasedCORS: () => true,
    ttl: {
      AccessToken: ACCESS_TOKEN_TTL,
      IdToken: ACCESS_TOKEN_TTL,
      Interaction: 3600,
      Session: 14 * 24 * 3600,
      Grant: 30 * 24 * 3600,
      RefreshToken: 30 * 24 * 3600,
    },
  })
  provider.proxy = true
  allowRedirectPatterns(provider, config.clients)

  if (config.passwordGrant) {
    // For scripts, like Dex's password connector: the username picks the profile, the password is ignored.
    provider.registerGrantType(
      "password",
      async (ctx) => {
        const params = ctx.oidc.params as Record<string, string | undefined>
        const profile = config
          .profiles()
          .find((candidate) => candidate.email === params.username || candidate.sub === params.username)
        if (!profile) {
          throw new errors.InvalidGrant("no profile has this username")
        }
        const clientId = ctx.oidc.client!.clientId
        const scope = params.scope ?? "openid"
        const now = Math.floor(Date.now() / 1000)
        const accessToken = await new SignJWT({ client_id: clientId, scope, email: profile.email, ...profile.claims })
          .setProtectedHeader({ alg: "RS256", kid: keys.jwks.keys[0].kid, typ: "at+jwt" })
          .setIssuer(config.issuer)
          .setSubject(profile.sub)
          .setAudience(config.audience)
          .setIssuedAt(now)
          .setExpirationTime(now + ACCESS_TOKEN_TTL)
          .setJti(randomUUID())
          .sign(signingKey)
        const idToken = await new SignJWT({ ...claimsOf(profile) })
          .setProtectedHeader({ alg: "RS256", kid: keys.jwks.keys[0].kid })
          .setIssuer(config.issuer)
          .setAudience(clientId)
          .setIssuedAt(now)
          .setExpirationTime(now + ACCESS_TOKEN_TTL)
          .sign(signingKey)
        ctx.body = {
          access_token: accessToken,
          id_token: idToken,
          token_type: "Bearer",
          expires_in: ACCESS_TOKEN_TTL,
          scope,
        }
      },
      new Set(["username", "password", "scope"]),
    )
  }

  const callback = provider.callback()

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://local")
    if (basePath && url.pathname !== basePath && !url.pathname.startsWith(`${basePath}/`)) {
      return send(res, 404, "text/plain", "Not found")
    }
    const path = url.pathname.slice(basePath.length) || "/"

    if (path === "/" || path === "") {
      return send(res, 200, "text/plain", `oidc-picker\nDiscovery: ${config.issuer}/.well-known/openid-configuration\n`)
    }
    if (path === "/me") {
      return userinfo(req, res)
    }
    const interaction = /^\/interaction\/([^/]+)(\/login)?$/u.exec(path)
    if (interaction) {
      return interaction[2] ? pick(req, res) : showInteraction(req, res)
    }

    // node-oidc-provider finds its mount path from originalUrl, like under Express.
    const forwarded = req as IncomingMessage & { originalUrl?: string }
    forwarded.originalUrl = req.url
    req.url = `${path}${url.search}`
    return callback(req, res)
  }

  /** The person the gatekeeper signed in, or null when one is required and missing. */
  function actorOf(req: IncomingMessage): string | null | undefined {
    if (!config.actorHeader) return undefined
    const value = req.headers[config.actorHeader]
    const actor = Array.isArray(value) ? value[0] : value
    return actor?.trim() || null
  }

  async function showInteraction(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (actorOf(req) === null) {
      return send(res, 403, "text/plain", "Sign in through the gatekeeper first.")
    }
    const details = await provider.interactionDetails(req, res)
    if (details.prompt.name === "login") {
      const html = renderPicker({
        action: `${basePath}/interaction/${details.uid}/login`,
        clientId: String(details.params.client_id),
        profiles: config.profiles(),
        loginHint: details.params.login_hint as string | undefined,
        accentColor: config.accentColor,
      })
      return send(res, 200, "text/html; charset=utf-8", html)
    }
    if (details.prompt.name === "consent") {
      // Every request is granted in full: there is nobody to ask.
      const grant = details.grantId
        ? await provider.Grant.find(details.grantId)
        : new provider.Grant({ accountId: details.session!.accountId, clientId: String(details.params.client_id) })
      const missing = details.prompt.details as {
        missingOIDCScope?: string[]
        missingOIDCClaims?: string[]
        missingResourceScopes?: Record<string, string[]>
      }
      if (missing.missingOIDCScope) grant!.addOIDCScope(missing.missingOIDCScope.join(" "))
      if (missing.missingOIDCClaims) grant!.addOIDCClaims(missing.missingOIDCClaims)
      for (const [indicator, scopes] of Object.entries(missing.missingResourceScopes ?? {})) {
        grant!.addResourceScope(indicator, scopes.join(" "))
      }
      const grantId = await grant!.save()
      return finish(req, res, { consent: details.grantId ? {} : { grantId } })
    }
    return send(res, 400, "text/plain", `Unsupported prompt: ${details.prompt.name}`)
  }

  async function pick(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      return send(res, 405, "text/plain", "Method not allowed")
    }
    const actor = actorOf(req)
    if (actor === null) {
      return send(res, 403, "text/plain", "Sign in through the gatekeeper first.")
    }
    const form = new URLSearchParams(await readBody(req))
    const profile = findProfile(form.get("sub") ?? undefined)
    if (!profile) {
      return send(res, 400, "text/plain", "Unknown profile")
    }
    if (actor) {
      // The audit trail of who signs in as whom: one JSON line on stdout.
      const details = await provider.interactionDetails(req, res)
      console.log(JSON.stringify({ event: "pick", at: new Date().toISOString(), actor, profile: profile.email, client: details.params.client_id }))
    }
    return finish(req, res, { login: { accountId: profile.sub } }, { mergeWithLastSubmission: false })
  }

  async function finish(
    req: IncomingMessage,
    res: ServerResponse,
    result: Record<string, unknown>,
    options?: { mergeWithLastSubmission?: boolean },
  ): Promise<void> {
    const location = await provider.interactionResult(req, res, result, options)
    res.writeHead(303, { Location: location })
    res.end()
  }

  async function userinfo(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const origin = req.headers.origin
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin)
      res.setHeader("Vary", "Origin")
    }
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Authorization",
      })
      return void res.end()
    }
    const token = /^Bearer (.+)$/iu.exec(req.headers.authorization ?? "")?.[1]
    const unauthorized = (description: string) => {
      res.setHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="${description}"`)
      return send(res, 401, "application/json", JSON.stringify({ error: "invalid_token", error_description: description }))
    }
    if (!token) {
      return unauthorized("no access token")
    }
    try {
      const { payload } = await jwtVerify(token, verificationKeys, { issuer: config.issuer })
      const profile = findProfile(payload.sub)
      if (!profile) {
        return unauthorized("the profile of this token no longer exists")
      }
      return send(res, 200, "application/json", JSON.stringify(claimsOf(profile)))
    } catch {
      return unauthorized("invalid access token")
    }
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      if (!res.headersSent) {
        send(res, 500, "text/plain", error instanceof Error ? error.message : String(error))
      }
    })
  })

  return {
    provider,
    server,
    listen: () =>
      new Promise((resolve) => {
        server.listen(config.port, config.host, () => {
          const address = server.address()
          resolve(typeof address === "object" && address ? `http://${config.host}:${address.port}` : "")
        })
      }),
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  }
}

export function claimsOf(profile: Profile): { sub: string; [claim: string]: unknown } {
  return {
    sub: profile.sub,
    email: profile.email,
    email_verified: true,
    name: profile.name ?? profile.email,
    preferred_username: profile.email,
    ...profile.claims,
  }
}

/** True when `uri` matches `pattern`, where `*` stands for any characters except `/`, `?` and `#`. */
export function matchesRedirectPattern(uri: string, pattern: string): boolean {
  const regex = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"))
    .join("[^/?#]*")
  return new RegExp(`^${regex}$`, "u").test(uri)
}

// node-oidc-provider only knows exact redirect URIs. Patterns are checked here, per client.
function allowRedirectPatterns(provider: Provider, clients: ClientConfig[]): void {
  const byClient = new Map(clients.map((client) => [client.id, client]))
  const prototype = provider.Client.prototype as any
  const redirectUriAllowed = prototype.redirectUriAllowed
  const postLogoutRedirectUriAllowed = prototype.postLogoutRedirectUriAllowed
  prototype.redirectUriAllowed = function (this: { clientId: string }, value: string) {
    return (
      redirectUriAllowed.call(this, value) ||
      (byClient.get(this.clientId)?.redirectUris ?? []).some((pattern) => matchesRedirectPattern(value, pattern))
    )
  }
  prototype.postLogoutRedirectUriAllowed = function (this: { clientId: string }, value: string) {
    return (
      postLogoutRedirectUriAllowed.call(this, value) ||
      (byClient.get(this.clientId)?.postLogoutRedirectUris ?? []).some((pattern) =>
        matchesRedirectPattern(value, pattern),
      )
    )
  }
}

function clientMetadata(client: ClientConfig, passwordGrant: boolean): ClientMetadata {
  const exact = (uris: string[]) => uris.filter((uri) => !uri.includes("*"))
  // A client needs one exact redirect URI to be valid. Patterns are checked by allowRedirectPatterns.
  const redirectUris = exact(client.redirectUris)
  return {
    client_id: client.id,
    ...(client.secret ? { client_secret: client.secret } : { token_endpoint_auth_method: "none" }),
    redirect_uris: redirectUris.length > 0 ? redirectUris : ["http://localhost/oidc-picker-pattern-only"],
    post_logout_redirect_uris: exact(client.postLogoutRedirectUris),
    grant_types: ["authorization_code", "refresh_token", ...(passwordGrant ? ["password"] : [])],
    response_types: ["code"],
  }
}

function publicJwk(jwk: JWK): JWK {
  return Object.fromEntries(Object.entries(jwk).filter(([key]) => !PRIVATE_JWK_FIELDS.has(key))) as JWK
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks).toString("utf8")
}

function send(res: ServerResponse, status: number, contentType: string, body: string): void {
  res.writeHead(status, { "Content-Type": contentType, "Cache-Control": "no-store" })
  res.end(body)
}

function trimTrailingSlash(path: string): string {
  return path.replace(/\/+$/u, "")
}
