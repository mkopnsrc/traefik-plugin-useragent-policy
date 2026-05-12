# Traefik Plugin: User-Agent Policy

A Traefik middleware plugin that gates HTTP requests by `User-Agent` — deny by default, with allow rules (regex), optional per-rule deny exceptions, optional OS filtering, log-only staging for new rules, path bypass, and periodic in-memory metrics.

> **Renamed from `traefik-plugin-block-useragents` in v0.8.0-alpha.** See **Migration** below if you're upgrading from v0.7.x.

## Features
- Blocks all `User-Agent`s by default.
- Allows user-defined browsers via custom regex patterns (e.g., `MyBrowser/12[0-1].*`).
- Per-rule `action: allow | deny` lets a narrow deny carve specific UAs out of a broader allow.
- Optional OS type filtering with regex patterns. See examples below.
- `mode: log-only` for staged rollout; `bypassPaths` for health checks; periodic JSON metrics summaries.
- No external APIs, no third-party imports — single-file stdlib-only plugin.

## Notes
 - Requirements: At least one `allowedBrowsers` entry with `name` and its `regex` is required.
 - OS Patterns: `allowedOSTypes` expects regex patterns. Use exact strings (e.g., `Windows NT 10\.0`) or wildcards (e.g., `Android [8-9]\.[0-9]+`) as needed.
 - No Dependencies: The plugin is lightweight with no external dependencies.

## Migration from `traefik-plugin-block-useragents`

The repository was renamed from `traefik-plugin-block-useragents` to `traefik-plugin-useragent-policy` in **v0.8.0-alpha**. The change is module-path-only — no config field renames, no behavior changes, no API breakage in `CreateConfig` / `New`.

**Two paths to update depending on how you load the plugin.** Pick the one matching your Traefik static config.

### If you use `experimental.plugins:` (Traefik catalog / registry)

Update both the local plugin key, the `moduleName`, and the `version`:

```diff
 experimental:
   plugins:
-    block_useragents:
-      moduleName: "github.com/mkopnsrc/traefik-plugin-block-useragents"
-      version: "v0.7.1-alpha"
+    useragent_policy:
+      moduleName: "github.com/mkopnsrc/traefik-plugin-useragent-policy"
+      version: "v0.8.0-alpha"
```

`version:` is **required** under `experimental.plugins:` — Traefik fetches the named tag from the module URL.

### If you use `experimental.localPlugins:` (mounted source directory)

Update the local plugin key and the `moduleName`. Do **not** add a `version:` line — `experimental.localPlugins` does not accept it (Traefik will fail to start with `field not found, node: version`).

```diff
 experimental:
   localPlugins:
-    block_useragents:
-      moduleName: "github.com/mkopnsrc/traefik-plugin-block-useragents"
+    useragent_policy:
+      moduleName: "github.com/mkopnsrc/traefik-plugin-useragent-policy"
```

The version of the plugin in this mode is whatever is in the mounted directory; pin it via your deployment, not via Traefik config.

### Common to both

Update any middleware references from `block_useragents:` to `useragent_policy:` (or whatever local key you choose) in the `http.middlewares.*.plugin.<key>` block — the key must be the same one you used under `experimental.{plugins,localPlugins}`.

GitHub redirects requests for the old repo URL to the new one, so existing pinned-to-v0.7.x configs continue to resolve. New deployments should use the new path. Tags from v0.7.x and earlier remain published under the new repo.

## Security

User-Agent strings are sent by the client and can be set to any value. This plugin filters honest clients (legacy browsers, opportunistic crawlers, automated tools that send their real UA); it does **not** stop a determined spoofer who can copy a permitted browser's UA verbatim. Treat it as user-agent enforcement, not a security control.

Two optional knobs harden behavior in non-trivial deployments:

| Option | Default | Recommended in production | Purpose |
| --- | --- | --- | --- |
| `strictMatch` | `false` | `true` | Prepend `\b` to each browser/OS regex so patterns must begin at a word boundary. Prevents the rule from matching when the token sits inside a longer word (e.g., `Chrome/130` no longer matches inside `MyChrome/130`). Patterns preceded by non-word characters such as `-`, `/`, or `.` (e.g., `X-Chrome/130`) still match because `\b` only requires a word/non-word transition. Existing patterns generally keep working. |
| `clientIPHeader` | `""` | `"X-Forwarded-For"` (only when behind a trusted proxy) | When set, the first comma-separated value of the named header is logged as the client IP instead of `req.RemoteAddr` (which is the proxy peer behind Traefik). The header value is trusted verbatim — only enable when Traefik's `forwardedHeaders.trustedIPs` is configured to validate or strip the header. |

Blocked-request log lines record the request **path** without the query string, so signed-URL tokens and session parameters carried in `?token=...` are not surfaced into logs.

## Policy options

These knobs change *which* requests get evaluated and *what happens* on a block decision. All are optional with safe defaults.

| Option | Default | Purpose |
| --- | --- | --- |
| `mode` | `"enforce"` | `"enforce"` blocks matched requests with HTTP 403. `"log-only"` logs what *would* have been blocked (with a `Would-Block` marker so the line is distinguishable from a real block) and forwards the request to the next handler. Use `"log-only"` to stage new rules without breaking traffic. |
| `bypassPaths` | `[]` | List of literal URL path prefixes (matched with `strings.HasPrefix` against `req.URL.Path`). Requests whose path matches any prefix skip *all* User-Agent checks and pass straight through. Intended for `/healthz`, `/.well-known/`, etc. — not regex, just literal prefix match. |
| `action` (per `allowedBrowsers` entry) | `"allow"` | `"allow"` (or empty) means the rule grants access when matched. `"deny"` makes the rule block matched UAs even if a later allow rule would also match — useful for narrowly excluding known bad actors (e.g., `HeadlessChrome`) from a broader allowlist. **At least one entry must use `"allow"`**, otherwise no request could ever pass. |

When both deny and allow rules are present, the evaluation order per request is:

1. Path matches a `bypassPaths` prefix → forward immediately.
2. Empty `User-Agent` → blocked (or would-block).
3. Any deny rule matches → blocked (or would-block).
4. No allow rule matches → blocked (or would-block).
5. `allowedOSTypes` configured and none match → blocked (or would-block).
6. Otherwise → forward.

## Observability

The plugin maintains in-memory atomic counters for every request and supports per-reason log sampling. There is no HTTP metrics endpoint — middlewares cannot add routes, and Traefik's metrics layer is not reachable from a Yaegi-loaded plugin. Instead, metrics are emitted as a periodic JSON log line that you can scrape from your log pipeline.

| Option | Default | Purpose |
| --- | --- | --- |
| `metricsLogInterval` | `""` (disabled) | Go duration string (e.g. `"60s"`, `"5m"`). When set to a positive duration, a background goroutine emits one JSON summary log line at that cadence. The goroutine is bound to the `context.Context` Traefik passes to `New()` and exits cleanly on plugin teardown — no leaks across config reloads. |
| `logSampleN` | `0` (log all) | Per-reason log-sampling stride. `0` or `1` logs every blocked request. `N>1` logs the 1st, then every `N`th, occurrence per reason. Reduces log volume during floods. **Has no effect on counters** — every block still increments its counter. |

Counter fields in the periodic summary line:

- `total` — every request that entered the middleware
- `allowed` — passed all checks and forwarded to next
- `bypass` — matched a `bypassPaths` prefix and forwarded
- `blocked_no_ua` — blocked due to empty `User-Agent`
- `blocked_deny` — blocked by a `deny` rule
- `blocked_browser` — blocked because no allow rule matched
- `blocked_os` — blocked because no `allowedOSTypes` rule matched

Counters are cumulative — derive rates by diffing successive snapshots in your log pipeline. Each Traefik router instance gets its own counter set; the middleware `name` prefix on each log line lets you keep them separate.

Counters in a snapshot are read independently, so `total` may briefly differ from `bypass + allowed + sum(blocked_*)` if a request is in flight when the snapshot is taken. The skew is at most one in-flight request per worker; rates derived from snapshot diffs are unaffected.

`bypassPaths` matches against `req.URL.Path` as received — the path is **not** normalized, so `/healthz/../admin` matches the prefix `/healthz`. Configure bypass entries only for trusted endpoints (health checks, well-known paths) where a path-traversed request reaching the next handler would not represent privilege escalation.

## Usage
1. Add the plugin to your Traefik configuration.
2. Configure the plugin with the desired browser patterns.
3. Attach the plugin to your Traefik middleware.

## Traefik Experimental Plugin Registry (traefik.yml)
Required under `experimental.plugins`: both `moduleName` and `version`. Pick a published tag from this repo's [releases page](https://github.com/mkopnsrc/traefik-plugin-useragent-policy/releases).
```yaml
experimental:
  plugins:
    useragent_policy:
      moduleName: "github.com/mkopnsrc/traefik-plugin-useragent-policy"
      version: "v0.8.0-alpha"
```

## Traefik Local Plugin (traefik.yml)
### Ensure Local Plugin directory is mounted in the Traefik container.
```yaml
experimental:
  localPlugins:
    useragent_policy:
      moduleName: "github.com/mkopnsrc/traefik-plugin-useragent-policy"
```

## Middleware Configuration
### Browsers Only
```yaml
http:
  middlewares:
    block-ua:
      plugin:
        useragent_policy:
          allowedBrowsers:
            - name: "Chrome"
              regex: "Chrome/13[0-3].*" # Chrome 130-133
            - name: "Firefox"
              regex: "Firefox/13[1-5].*" # Firefox 131-135
```


### Browsers with OS Types Filtering
```yaml
http:
  middlewares:
    block-ua:
      plugin:
        useragent_policy:
          allowedBrowsers:
            - name: "Chrome"
              regex: "Chrome/13[0-3].*" # Chrome 130-133
            - name: "Firefox"
              regex: "Firefox/13[1-5].*" # Firefox 131-135
            - name: "Edg" # Microsoft Edge
              regex: "Edg/10[0-9]" # Edge 100-109
            - name: "Brave"
              regex: "Brave/1\\.[7][5-9]" # Brave 1.75-1.79 (note: \. escapes the literal dot)
            - name: "CriOS" # Chrome for iOS
              regex: "CriOS/13[0-9]"
          allowedOSTypes:
            - "Windows NT 10\\.0" # Windows 10
            - "Mac OS X 10\\.[0-9]+" # macOS 10.x
            - "Linux" # Linux
            - "X11" # Unix
            - "Android" # Android
            - "iOS" # iOS
```

### Recommended Production Configuration
Anchored matching, real client IP from a trusted proxy header, and bypass for health checks / well-known paths. See **Security** and **Policy options** for the rationale behind each knob.
```yaml
http:
  middlewares:
    block-ua:
      plugin:
        useragent_policy:
          strictMatch: true                # \b-anchor each pattern; prevents partial-word matches
          clientIPHeader: "X-Forwarded-For" # only when behind a trusted proxy that sets/strips this
          bypassPaths:
            - "/healthz"
            - "/.well-known/"
          allowedBrowsers:
            - name: "Chrome"
              regex: "Chrome/13[0-3]"
            - name: "Firefox"
              regex: "Firefox/13[1-5]"
          allowedOSTypes:
            - "Windows NT 10\\.0"
            - "Mac OS X 10\\.[0-9]+"
            - "Linux"
            - "Android"
            - "iOS"
```

### Mixing Allow and Deny Rules
Per-rule `action` lets a narrow deny carve out specific UAs from a broader allow. Deny rules are evaluated before allow rules.
```yaml
http:
  middlewares:
    block-ua:
      plugin:
        useragent_policy:
          allowedBrowsers:
            - name: "Chrome"
              regex: "Chrome/13[0-3]"
              # action: "allow" is the default and may be omitted
            - name: "ChromeHeadless"        # carved out from the Chrome allow above
              regex: "HeadlessChrome"
              action: "deny"
            - name: "PhantomJS"
              regex: "PhantomJS"
              action: "deny"
```

### Staged Rollout (log-only) with Observability
Stage a stricter ruleset without breaking traffic: log what *would* be blocked, forward the request anyway, emit a metrics summary every minute, and sample noisy block reasons so the log volume stays manageable.
```yaml
http:
  middlewares:
    block-ua:
      plugin:
        useragent_policy:
          mode: "log-only"            # would-blocks log a "Would-Block" line and pass through
          metricsLogInterval: "60s"   # one JSON summary log line per minute
          logSampleN: 100             # log 1st + every 100th occurrence per reason
          allowedBrowsers:
            - name: "Chrome"
              regex: "Chrome/13[0-3]"
            - name: "Firefox"
              regex: "Firefox/13[1-5]"
```

## Router Usage
```yaml
http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      service: my-service
      middlewares:
        - block-ua
```

## Publishing to the Traefik Plugins Catalog

This plugin is structured for inclusion in the [Traefik Plugins Catalog](https://plugins.traefik.io). Discovery is automatic: Traefik's catalog scans GitHub for public repositories that have the `traefik-plugin` topic and a valid `.traefik.yml` manifest at the repository root.

**Catalog requirements (current state):**

| Requirement | Status |
| --- | --- |
| Public GitHub repository | ✅ |
| `LICENSE` at repo root (Apache-2.0) | ✅ |
| `.traefik.yml` manifest with `displayName`, `type`, `import`, `summary`, `description`, `testData` | ✅ |
| `import:` matches the Go module path declared in `go.mod` | ✅ |
| At least one published version tag | ✅ (latest: see [releases](https://github.com/mkopnsrc/traefik-plugin-useragent-policy/releases)) |
| `traefik-plugin` topic on the GitHub repo (catalog discovery) | Set via `gh repo edit --add-topic traefik-plugin` |
| Plugin loads cleanly under Yaegi (stdlib-only imports) | ✅ — no third-party dependencies |
| `testData` in `.traefik.yml` is a valid working config | ✅ |

The catalog runs the plugin against the manifest's `testData` block to validate it loads. Keep `testData` minimal-and-correct — it is a sanity check, not a feature showcase.

**To submit / re-list after a release:**

1. Push the new tag (e.g. `v0.8.0-alpha`) and publish a GitHub Release.
2. Catalog typically re-indexes within a few hours of a tag push on a topic-flagged repo. No manual submission step is required for an already-listed plugin.
3. For first-time inclusion, after adding the `traefik-plugin` topic you may also need to file a tracking issue at the [Traefik plugins repository](https://github.com/traefik/plugins) — see their current onboarding instructions.

For a non-catalog deployment (private fork, on-prem, development), use `experimental.localPlugins:` and skip the catalog entirely — see the **Migration** section above for the difference.
