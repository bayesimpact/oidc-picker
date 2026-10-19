// The sign-in page: one button per profile, a filter, nothing to type.
import type { Profile } from "./config.ts"

export function renderPicker({
  action,
  clientId,
  profiles,
  loginHint,
  accentColor,
}: {
  action: string
  clientId: string
  profiles: Profile[]
  loginHint?: string
  accentColor?: string
}): string {
  const items = profiles
    .map((profile) => {
      const label = profile.name ?? profile.email
      const chips = Object.entries(profile.claims ?? {})
        .map(([key, value]) => `<span class="chip">${escape(key)}: ${escape(formatClaim(value))}</span>`)
        .join("")
      const hinted = loginHint !== undefined && (loginHint === profile.email || loginHint === profile.sub)
      const search = [label, profile.email, profile.description ?? "", JSON.stringify(profile.claims ?? {})]
        .join(" ")
        .toLowerCase()
      return `<li data-search="${escape(search)}">
  <form method="post" action="${escape(action)}">
    <input type="hidden" name="sub" value="${escape(profile.sub)}">
    <button type="submit"${hinted ? " autofocus" : ""}>
      <span class="avatar" aria-hidden="true">${escape(initials(label))}</span>
      <span class="who">
        <strong>${escape(label)}</strong>
        <span class="email">${escape(profile.email)}</span>
        ${profile.description ? `<span class="description">${escape(profile.description)}</span>` : ""}
        ${chips ? `<span class="chips">${chips}</span>` : ""}
      </span>
    </button>
  </form>
</li>`
    })
    .join("\n")

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pick a profile</title>
<style>
  :root { color-scheme: light dark; --bg: #fafafa; --card: #fff; --text: #0a0a0a; --muted: #737373; --line: #e5e5e5; --accent: #2f5bea; }
  @media (prefers-color-scheme: dark) { :root { --bg: #0a0a0a; --card: #171717; --text: #fafafa; --muted: #a1a1a1; --line: #262626; --accent: #7d9bff; } }${accentColor ? `\n  :root:root { --accent: ${accentColor}; }` : ""}
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.4 system-ui, sans-serif; }
  main { max-width: 640px; margin: 0 auto; padding: 32px 16px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  p.lead { color: var(--muted); margin: 0 0 20px; }
  input[type=search] { width: 100%; padding: 10px 12px; font: inherit; color: inherit; background: var(--card); border: 1px solid var(--line); border-radius: 8px; margin-bottom: 16px; }
  ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
  form { margin: 0; }
  button { width: 100%; display: flex; gap: 12px; align-items: flex-start; text-align: left; padding: 12px; font: inherit; color: inherit; background: var(--card); border: 1px solid var(--line); border-radius: 10px; cursor: pointer; }
  button:hover, button:focus-visible { border-color: var(--accent); outline: none; }
  .avatar { flex: none; width: 36px; height: 36px; border-radius: 50%; display: grid; place-items: center; background: var(--accent); color: #fff; font-weight: 600; font-size: 13px; }
  .who { display: grid; gap: 2px; min-width: 0; }
  .email, .description { color: var(--muted); overflow-wrap: anywhere; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
  .chip { font-size: 12px; padding: 1px 6px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); }
  .empty { color: var(--muted); }
</style>
</head>
<body>
<main>
  <h1>Pick a profile</h1>
  <p class="lead">Sign in to <strong>${escape(clientId)}</strong> as anyone below. Local development only: no password is checked.</p>
  ${profiles.length > 5 ? '<input type="search" id="filter" placeholder="Filter by name, email or claim" autofocus>' : ""}
  ${profiles.length === 0 ? '<p class="empty">No profile is configured.</p>' : `<ul id="profiles">\n${items}\n</ul>`}
</main>
<script>
  const filter = document.getElementById("filter")
  filter?.addEventListener("input", () => {
    const query = filter.value.trim().toLowerCase()
    for (const item of document.querySelectorAll("#profiles li")) {
      item.hidden = query !== "" && !item.dataset.search.includes(query)
    }
  })
</script>
</body>
</html>`
}

function initials(label: string): string {
  const words = label.replace(/@.*/u, "").split(/[\s._-]+/u).filter(Boolean)
  return (words.length > 1 ? `${words[0][0]}${words[1][0]}` : (words[0] ?? "?").slice(0, 2)).toUpperCase()
}

function formatClaim(value: unknown): string {
  return Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value)
}

function escape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}
