# oidc-picker

A local OpenID Connect provider for development. The sign-in page lists profiles: click one and
you are signed in as that person, with no password.

It is for local development only. Anyone who reaches the server can sign in as anyone, so it
refuses to start when the issuer is not on a local host (`localhost`, `127.0.0.1`, `[::1]`,
`*.localhost`, `*.test`).

Built on [node-oidc-provider](https://github.com/panva/node-oidc-provider), a certified OpenID
provider: the protocol part is not ours.

## What it does

- Authorization code flow with PKCE, refresh tokens (`offline_access`), discovery, JWKS.
- Access tokens are RS256 JWTs that an API can check with the JWKS. The userinfo endpoint
  (`/me`) accepts them.
- The picker shows on every interactive sign-in, so you can switch from one profile to another.
  Silent requests (`prompt=none`) keep the current session. Set `alwaysPick: false` to keep
  sessions like a normal provider.
- Logout (`end_session_endpoint`) without a confirmation page.
- Redirect URI patterns: `https://*.app.localhost:8800` matches one host per branch or worktree.
  `*` never matches `/`, `?` or `#`.
- Profiles with any extra claims (roles, groups, tenant...), in the tokens and in userinfo.
- Profiles in a separate file, read again when it changes: no restart.
- Signing keys kept in a file (`keysFile`): a restart does not sign you out.
- `grant_type=password` for scripts: the username picks the profile, the password is ignored.

## Start

```bash
cp oidc-picker.example.yaml oidc-picker.yaml
npm install
npm start
```

Node 22.18 or later runs the TypeScript sources directly, without a build.

With Docker:

```bash
docker build -t oidc-picker .
docker run --rm -p 5556:5556 -v "$PWD:/config" oidc-picker
```

Then point your app at the issuer, `http://localhost:5556` in the example, with the client id of
the configuration.

## Configuration

See [oidc-picker.example.yaml](oidc-picker.example.yaml). Environment variables override a few
keys: `OIDC_PICKER_ISSUER`, `OIDC_PICKER_PORT`, `OIDC_PICKER_HOST`, `OIDC_PICKER_CONFIG` (path of
the file).

An issuer with a path works too, for example `http://localhost:5556/dex` to take the place of a
local Dex without changing the apps.

A profile needs an `email`. `sub` defaults to the email. Every email is reported as verified.

```yaml
profiles:
  - email: admin@example.org
    name: Ada Admin
    description: Every permission
    claims:
      roles: [admin]
```

New claim names are read at startup: restart after adding one. New profiles and new values do
not need a restart when they come from `profilesFile`.

## Behind a gatekeeper

To reach the picker from outside your machine (a shared test environment, for instance), put it
behind a gatekeeper that signs people in first, such as
[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy), and allow the issuer with
`allowNonLocalIssuer: true`. Then set `actorHeader` to the header the gatekeeper adds with the
signed-in person:

```yaml
allowNonLocalIssuer: true
actorHeader: X-Auth-Request-Email
```

With `actorHeader` set:

- the picker and its sign-in pages answer 403 to a request without the header, a second barrier
  if a route of the gatekeeper is ever left open;
- each pick is logged as one JSON line on stdout, with who picked which profile for which client:
  `{"event":"pick","at":"…","actor":"…","profile":"…","client":"…"}`;
- the password grant is off, since a script would get around the gatekeeper with it.

The gatekeeper must remove the header from incoming requests and set it itself; otherwise anyone
can send it. Browsers call the token, JWKS, discovery and userinfo endpoints without the
gatekeeper's cookie, so leave those open: they give nothing without a code or a token obtained
through the picker.

## Token for a script

```bash
curl -s http://localhost:5556/token -d grant_type=password -d client_id=my-web-app -d username=admin@example.org -d password=x -d scope="openid email"
```

## Development

```bash
npm test
npm run typecheck
```

## License

MIT
