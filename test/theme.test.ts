// The accent color of the picker, from `theme.accent`.
import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { buildConfig } from "../src/config.ts"
import { renderPicker } from "../src/picker.ts"

const base = {
  clients: [{ id: "web", redirectUris: ["http://localhost:5173"] }],
  profiles: [{ email: "member@example.org", name: "Max Member" }],
}

describe("theme.accent", () => {
  it("colors the buttons and avatars, in light and dark mode", () => {
    const config = buildConfig({ ...base, theme: { accent: "oklch(62.8% 0.2 303.9)" } }, { env: {} })
    const page = renderPicker({ action: "/x", clientId: "web", profiles: config.profiles(), accentColor: config.accentColor })
    assert.match(page, /:root:root \{ --accent: oklch\(62\.8% 0\.2 303\.9\); \}/u)
  })

  it("keeps the default accent without it", () => {
    const config = buildConfig(base, { env: {} })
    assert.doesNotMatch(renderPicker({ action: "/x", clientId: "web", profiles: [], accentColor: config.accentColor }), /:root:root/u)
  })

  it("refuses what is not a color", () => {
    for (const accent of ["red; } body { display: none", "</style><script>", "url(x){"]) {
      assert.throws(() => buildConfig({ ...base, theme: { accent } }, { env: {} }), /not a CSS color/u)
    }
  })
})
