# novaro

The NovaroPay command-line tool: forward your account's test-mode webhook
events to a server on your machine, make test events happen, and read or
resend events.

```sh
novaro login
novaro listen --forward-to localhost:3000/webhooks
novaro trigger payment.succeeded
```

## Install

The names below are the release's owner's (`novaro`), set by `HOMEBREW_TAP_OWNER` in `.goreleaser.yaml`.


- **macOS and Linux (Homebrew):** `brew install novaro/tap/novaro`
- **Windows (Scoop):** `scoop bucket add novaro https://github.com/novaro/scoop-bucket` then `scoop install novaro`
- **Debian, Ubuntu, Fedora:** the `.deb` and `.rpm` packages of a release
- **Docker:** `docker run --rm -it ghcr.io/novaro/novaro version`
- **Any system:** the archive for it from the releases page

Every release's `checksums.txt`, which names every archive and package, is signed with [cosign](https://github.com/sigstore/cosign), keyless:

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/.+/novaro-cli/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
```

## Commands

| Command | What it does |
| --- | --- |
| `novaro login` | Pairs novaro with your account in the browser: someone of the account allows it in the merchant portal, and novaro gets a CLI key (`rk_test_…`, test mode, 90 days), kept in the OS keychain, or, on a machine with none, in novaro's config file, readable by you alone. `--api-key sk_test_…` keeps that key instead, for CI. The key is sent only to the address login used, over https (or http to this machine). |
| `novaro logout` | Forgets the key on this machine. |
| `novaro listen` | Receives your test-mode events and POSTs each to `--forward-to`, signed as your endpoints' are; your server's answer is the delivery's attempt. `--events`, `--api-version`, `--latest`, `--headers`, `--skip-verify`, `--print-secret` (the secret listen last got with login's key on this device; else it opens a session, which replaces a running listen's), `--format json`. |
| `novaro trigger <event>` | Makes the event happen with a test payment and a magic UTR. `--list`, `--override field=value`. |
| `novaro events list\|retrieve\|resend` | Reads your events (`GET /events`) and resends one to an endpoint (`POST /events/{id}/retry`). `--live` with `--api-key sk_live_…` for live mode. |
| `novaro version`, `novaro completion` | The version; shell completion for bash, zsh, fish and PowerShell. |

Every command takes `--api-key` (or `NOVARO_API_KEY`, which stays out of
your shell history) and `--api-base`; `NOVARO_API_BASE` sets the API's
address, and `NOVARO_CONFIG_DIR` where the config lives.

## Develop

```sh
make check      # vet, lint, tests with the race detector (CI also runs go mod tidy -diff and goreleaser check)
make build      # ./novaro, talking to the local stack (http://localhost:28081)
```

A release is a tag: `git tag v0.1.0 && git push origin v0.1.0` (see `.goreleaser.yaml`).

## License

Apache-2.0
