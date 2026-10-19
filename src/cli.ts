#!/usr/bin/env node
import { loadConfig } from "./config.ts"
import { createPicker } from "./server.ts"

const path = process.argv[2] ?? process.env.OIDC_PICKER_CONFIG ?? "oidc-picker.yaml"
const config = loadConfig(path)
const picker = await createPicker(config)
await picker.listen()
console.log(`oidc-picker: issuer ${config.issuer}, listening on ${config.host}:${config.port}`)
console.log(`oidc-picker: ${config.profiles().length} profiles, ${config.clients.length} clients (${path})`)

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    picker.close().finally(() => process.exit(0))
  })
}
