# Rupa Silverworks contact API

Standalone Go service deployed as a Vercel Function at `POST /api/contact`. The API validates input, verifies Cloudflare Turnstile, rate-limits repeated requests, and sends the inquiry through Mailbux SMTP over STARTTLS. This repository contains only the API service.

## Local setup

1. Install Go 1.23 or newer.
2. Copy `.env.local.example` to `.env.local` and add the Mailbux app password.
3. Run the local Go server:

```sh
go run ./cmd/server
```

The API is available at `http://localhost:8080/api/contact`, and its health check is available at `http://localhost:8080/healthz`. The runner loads `.env.local` automatically; environment variables already defined in the terminal take precedence.

Use Cloudflare's official test secret locally. The Turnstile site key belongs in the separate frontend project and must never be added to this service as a backend credential.

For the separate local frontend, use Cloudflare's always-pass test site key `1x00000000000000000000AA`, render the widget with action `contact`, and send the resulting token to this API. Submissions with real Mailbux credentials send real email.

## Vercel environment variables

Configure all variables from `.env.example` as server-side environment variables in Vercel.

`TURNSTILE_ALLOWED_HOSTNAME` accepts one hostname or a comma-separated list. The current Vercel preview hostname (`VERCEL_URL`) is also accepted automatically by the API, but it must still be permitted by the Cloudflare Turnstile widget.

`CONTACT_ALLOWED_ORIGINS` accepts a comma-separated list of full origins, for example `https://www.rupasilverworks.com,https://preview.example.com`. Browser preflight requests from these origins receive a `204`; all other cross-origin requests are rejected. Keep this list aligned with `TURNSTILE_ALLOWED_HOSTNAME`.

Mailbux configuration:

- Host: `my.mailbux.com`
- Port: `587`
- Encryption: STARTTLS
- Username: `website@rupasilverworks.com`
- Password: a Mailbux app password

## Verification

```sh
go test ./...
```

The in-memory limiter allows five requests per IP per ten-minute window. It is best-effort on serverless instances; use Upstash Redis when persistent, cross-instance limiting is required.
