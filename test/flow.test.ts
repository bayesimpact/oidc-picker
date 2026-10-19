// End-to-end: a browser-like client runs the authorization code flow with PKCE against a real
// server, then the tokens are checked the way an API checks them.
import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { createServer } from "node:net"
import { after, before, describe, it } from "node:test"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { buildConfig } from "../src/config.ts"
import { createPicker, matchesRedirectPattern, type Picker } from "../src/server.ts"

const CLIENT_ID = "web"
const REDIRECT_URI = "https://feature-x.app.localhost:8800/callback"

let picker: Picker
let issuer: string

before(async () => {
  const port = await freePort()
  issuer = `http://localhost:${port}/dex`
  const config = buildConfig(
    {
      issuer,
      port,
      clients: [{ id: CLIENT_ID, redirectUris: ["http://localhost:5173", "https://*.app.localhost:8800/callback"] }],
      profiles: [
        { email: "admin@example.org", name: "Ada Admin", claims: { roles: ["admin"] } },
        { email: "member@example.org", name: "Max Member" },
      ],
    },
    { env: {} },
  )
  picker = await createPicker(config)
  await picker.listen()
})

after(() => picker.close())

describe("authorization code flow", () => {
  it("signs in with the picked profile and issues tokens an API accepts", async () => {
    const browser = new Browser()
    const verifier = randomBytes(32).toString("base64url")
    const authorize = new URL(`${issuer}/auth`)
    authorize.search = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid profile email offline_access",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      prompt: "consent",
      state: "s1",
    }).toString()

    const pickerPage = await browser.follow(authorize.href)
    assert.match(pickerPage.body, /Ada Admin/u)
    assert.match(pickerPage.body, /Max Member/u)
    const action = /action="([^"]+)"/u.exec(pickerPage.body)?.[1]
    assert.ok(action)

    const callback = await browser.follow(new URL(action, issuer).href, {
      method: "POST",
      body: new URLSearchParams({ sub: "admin@example.org" }),
      stopAt: REDIRECT_URI,
    })
    const code = new URL(callback.url).searchParams.get("code")
    assert.ok(code, `no code in ${callback.url}`)

    const tokens = await postForm(`${issuer}/token`, {
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    })
    assert.equal(tokens.status, 200, JSON.stringify(tokens.json))
    const { access_token, id_token, refresh_token } = tokens.json

    const jwks = await discoveredJwks()
    const access = await jwtVerify(access_token, jwks, { issuer, algorithms: ["RS256"] })
    assert.equal(access.payload.sub, "admin@example.org")
    assert.equal(access.payload.email, "admin@example.org")
    assert.deepEqual(access.payload.roles, ["admin"])
    const id = await jwtVerify(id_token, jwks, { issuer, audience: CLIENT_ID })
    assert.equal(id.payload.name, "Ada Admin")
    assert.equal(id.payload.email_verified, true)
    assert.ok(refresh_token, "offline_access gives a refresh token")

    const userinfo = await fetch(`${issuer}/me`, { headers: { Authorization: `Bearer ${access_token}` } })
    assert.equal(userinfo.status, 200)
    assert.deepEqual(await userinfo.json(), {
      sub: "admin@example.org",
      email: "admin@example.org",
      email_verified: true,
      name: "Ada Admin",
      preferred_username: "admin@example.org",
      roles: ["admin"],
    })

    const refreshed = await postForm(`${issuer}/token`, { grant_type: "refresh_token", client_id: CLIENT_ID, refresh_token })
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.json))
    await jwtVerify(refreshed.json.access_token, jwks, { issuer })

    // With an open session, the next sign-in shows the picker again.
    authorize.searchParams.delete("prompt")
    const again = await browser.follow(authorize.href)
    assert.match(again.body, /Pick a profile/u)
  })

  it("refuses a redirect URI that matches no pattern", async () => {
    const authorize = new URL(`${issuer}/auth`)
    authorize.search = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: "https://evil.example.org/callback",
      response_type: "code",
      scope: "openid",
      code_challenge: "x".repeat(43),
      code_challenge_method: "S256",
    }).toString()
    const response = await fetch(authorize, { redirect: "manual" })
    assert.equal(response.status, 400)
    assert.match(await response.text(), /redirect_uri/u)
  })
})

describe("password grant", () => {
  it("issues tokens for a profile, whatever the password", async () => {
    const tokens = await postForm(`${issuer}/token`, {
      grant_type: "password",
      client_id: CLIENT_ID,
      username: "member@example.org",
      password: "anything",
      scope: "openid email",
    })
    assert.equal(tokens.status, 200, JSON.stringify(tokens.json))
    const { payload } = await jwtVerify(tokens.json.access_token, await discoveredJwks(), { issuer })
    assert.equal(payload.sub, "member@example.org")
    const userinfo = await fetch(`${issuer}/me`, { headers: { Authorization: `Bearer ${tokens.json.access_token}` } })
    assert.equal((await userinfo.json()).name, "Max Member")
  })

  it("refuses an unknown username", async () => {
    const tokens = await postForm(`${issuer}/token`, {
      grant_type: "password",
      client_id: CLIENT_ID,
      username: "nobody@example.org",
      password: "x",
    })
    assert.equal(tokens.status, 400)
    assert.equal(tokens.json.error, "invalid_grant")
  })
})

describe("configuration", () => {
  it("refuses an issuer that is not local", () => {
    assert.throws(
      () => buildConfig({ issuer: "https://idp.example.org", clients: [{ id: "a", redirectUris: ["x"] }], profiles: [] }, { env: {} }),
      /not on a local host/u,
    )
  })

  it("matches redirect patterns within one path segment", () => {
    assert.ok(matchesRedirectPattern("https://a.app.localhost:8800", "https://*.app.localhost:8800"))
    assert.ok(!matchesRedirectPattern("https://a.evil.org/.app.localhost:8800", "https://*.app.localhost:8800"))
    assert.ok(!matchesRedirectPattern("https://a.app.localhost:8800.evil.org", "https://*.app.localhost:8800"))
  })
})

/** Follows redirects by hand and keeps cookies, like a browser. */
class Browser {
  private cookies = new Map<string, string>()

  async follow(
    url: string,
    { method = "GET", body, stopAt }: { method?: string; body?: URLSearchParams; stopAt?: string } = {},
  ): Promise<{ url: string; body: string }> {
    let current = url
    let request: RequestInit = { method, body }
    for (let hop = 0; hop < 10; hop++) {
      if (stopAt && current.startsWith(stopAt)) return { url: current, body: "" }
      const response = await fetch(current, {
        ...request,
        redirect: "manual",
        headers: { Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ") },
      })
      for (const cookie of response.headers.getSetCookie()) {
        const [pair] = cookie.split(";")
        const index = pair.indexOf("=")
        this.cookies.set(pair.slice(0, index), pair.slice(index + 1))
      }
      const location = response.headers.get("location")
      if (!location) return { url: current, body: await response.text() }
      current = new URL(location, current).href
      request = { method: "GET" }
    }
    throw new Error("too many redirects")
  }
}

async function postForm(url: string, form: Record<string, string>): Promise<{ status: number; json: any }> {
  const response = await fetch(url, { method: "POST", body: new URLSearchParams(form) })
  return { status: response.status, json: await response.json() }
}

async function discoveredJwks() {
  const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()
  assert.equal(discovery.issuer, issuer)
  assert.equal(discovery.userinfo_endpoint, `${issuer}/me`)
  assert.ok(discovery.end_session_endpoint)
  return createRemoteJWKSet(new URL(discovery.jwks_uri))
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const server = createServer().listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number }
      server.close(() => resolve(port))
    })
  })
}
