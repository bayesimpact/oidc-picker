// Behind a gatekeeper (actorHeader): the picker refuses a request the gatekeeper did not let
// through, logs who picked which profile, and turns the password grant off.
import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { createServer } from "node:net"
import { after, before, describe, it, mock } from "node:test"
import { buildConfig } from "../src/config.ts"
import { createPicker, type Picker } from "../src/server.ts"

const CLIENT_ID = "web"
const REDIRECT_URI = "https://feature-x.app.localhost:8800/callback"
const HEADER = "X-Auth-Request-Email"

let picker: Picker
let issuer: string

before(async () => {
  const port = await freePort()
  issuer = `http://localhost:${port}`
  const config = buildConfig(
    {
      issuer,
      port,
      actorHeader: HEADER,
      clients: [{ id: CLIENT_ID, redirectUris: [REDIRECT_URI] }],
      profiles: [{ email: "member@example.org", name: "Max Member" }],
    },
    { env: {} },
  )
  assert.equal(config.passwordGrant, false)
  picker = await createPicker(config)
  await picker.listen()
})

after(() => picker.close())

function authorizeUrl(): string {
  const url = new URL(`${issuer}/auth`)
  url.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email",
    code_challenge: createHash("sha256").update(randomBytes(32).toString("base64url")).digest("base64url"),
    code_challenge_method: "S256",
    state: "s",
  }).toString()
  return url.href
}

describe("behind a gatekeeper", () => {
  it("refuses the picker without the gatekeeper's header", async () => {
    const page = await new Browser({}).follow(authorizeUrl())
    assert.equal(page.status, 403)
    assert.doesNotMatch(page.body, /Max Member/u)
  })

  it("shows the picker with it, and logs who picked whom", async () => {
    const browser = new Browser({ [HEADER]: "someone@example.org" })
    const page = await browser.follow(authorizeUrl())
    assert.match(page.body, /Max Member/u)
    const action = /action="([^"]+)"/u.exec(page.body)?.[1]
    assert.ok(action)
    const log = mock.method(console, "log", () => {})
    const callback = await browser.follow(new URL(action, issuer).href, {
      method: "POST",
      body: new URLSearchParams({ sub: "member@example.org" }),
      stopAt: REDIRECT_URI,
    })
    const lines = log.mock.calls.map((call) => String(call.arguments[0]))
    log.mock.restore()
    assert.ok(callback.url.startsWith(REDIRECT_URI))
    const entry = lines.map((line) => JSON.parse(line)).find((line) => line.event === "pick")
    assert.deepEqual([entry.actor, entry.profile, entry.client], ["someone@example.org", "member@example.org", CLIENT_ID])
  })

  it("has no password grant", async () => {
    const response = await fetch(`${issuer}/token`, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "password", client_id: CLIENT_ID, username: "member@example.org", password: "x" }),
    })
    assert.notEqual(response.status, 200)
  })
})

class Browser {
  private cookies = new Map<string, string>()
  private headers: Record<string, string>
  constructor(headers: Record<string, string>) {
    this.headers = headers
  }

  async follow(
    url: string,
    { method = "GET", body, stopAt }: { method?: string; body?: URLSearchParams; stopAt?: string } = {},
  ): Promise<{ url: string; body: string; status: number }> {
    let current = url
    let request: RequestInit = { method, body }
    for (let hop = 0; hop < 10; hop++) {
      if (stopAt && current.startsWith(stopAt)) return { url: current, body: "", status: 302 }
      const response = await fetch(current, {
        ...request,
        redirect: "manual",
        headers: { ...this.headers, Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ") },
      })
      for (const cookie of response.headers.getSetCookie()) {
        const [pair] = cookie.split(";")
        const index = pair.indexOf("=")
        this.cookies.set(pair.slice(0, index), pair.slice(index + 1))
      }
      const location = response.headers.get("location")
      if (!location) return { url: current, body: await response.text(), status: response.status }
      current = new URL(location, current).href
      request = { method: "GET" }
    }
    throw new Error("too many redirects")
  }
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      server.close(() => (typeof address === "object" && address ? resolve(address.port) : reject(new Error("no port"))))
    })
  })
}
