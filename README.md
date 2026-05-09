# Traefik Plugin: Block User-Agent

A Traefik middleware plugin to block all HTTP requests by default and allowing only HTTP requests based on the user-specified `User-Agent` patterns for Browser and OS types.

## Features
- Blocks all `User-Agent` by default.
- Allows user-defined browsers via:
  - Custom regex patterns (e.g., `MyBrowser/12[0-1].*`).
- Optional OS type filtering with regex patterns. See example below.
- No external APIs or caching; relies entirely on user configuration.

## Notes
 - Requirements: At least one `allowedBrowsers` entry with `name` and it's `regex` is required.
 - OS Patterns: `allowedOSTypes` expects regex patterns. Use exact strings (e.g., `Windows NT 10\.0`) or wildcards (e.g., `Android [8-9]\.[0-9]+`) as needed.
 - No Dependencies: The plugin is lightweight with no external dependencies.

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

## Usage
1. Add the plugin to your Traefik configuration.
2. Configure the plugin with the desired browser patterns.
3. Attach the plugin to your Traefik middleware.

## Traefik Experimental Plugin Registry (traefik.yml)
```yaml
experimental:
  plugins:
    block_useragents:
      moduleName: "github.com/mkopnsrc/traefik-plugin-block-useragents"
      version: "v1.0" # Optional
```

## Traefik Local Plugin (traefik.yml)
### Ensure Local Plugin directory is mounted in the Traefik container.
```yaml
experimental:
  localPlugins:
    block_useragents:
      moduleName: "github.com/mkopnsrc/traefik-plugin-block-useragents"
```

## Middleware Configuration
### Browsers Only
```yaml
http:
  middlewares:
    block-ua:
      plugin:
        block_useragents:
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
        block_useragents:
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
