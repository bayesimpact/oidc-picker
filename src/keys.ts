// Signing keys (RS256) and cookie keys. Kept in a file when one is configured, so a restart
// does not invalidate the tokens already in the browser.
import { randomBytes } from "node:crypto"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from "jose"

export interface Keys {
  jwks: { keys: JWK[] }
  cookieKeys: string[]
}

export async function loadKeys(file?: string): Promise<Keys> {
  if (file && existsSync(file)) {
    return JSON.parse(readFileSync(file, "utf8")) as Keys
  }
  const keys = await generateKeys()
  if (file) {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, `${JSON.stringify(keys, null, 2)}\n`, { mode: 0o600 })
  }
  return keys
}

async function generateKeys(): Promise<Keys> {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true })
  const jwk = await exportJWK(privateKey)
  jwk.kid = await calculateJwkThumbprint(jwk)
  jwk.alg = "RS256"
  jwk.use = "sig"
  return { jwks: { keys: [jwk] }, cookieKeys: [randomBytes(32).toString("base64url")] }
}
