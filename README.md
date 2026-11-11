<p align="center"><img src="src/assets/seal-id.svg" width="120" alt="Seal ID"></p>

# Seal ID

**Self-hosted identity proofs, signed with your OpenPGP key.**

Seal ID is a small set of PHP files you put on your own website. It lets you
prove — to anyone, without a central service — that you hold an OpenPGP key and
that you own your domains and social accounts: GitHub, X, Mastodon, Bluesky,
Reddit, YouTube, Hacker News, Facebook and more.

Every Seal ID can check every other Seal ID. Installations never take each
other's word for anything: each one fetches the other's signed statements,
verifies every signature and re-checks every proof itself. When you've checked
someone, you can **vouch** for them — a signed statement that shows up on both
profiles.

Part of the Seal family with [Seal Post](https://github.com/jeffbristow/sealpost)
and Seal Chat. Your Seal ID uses the same kind of key, so it can later prove the
Seal Chat ID you use is really yours.

## How it works

* Your identity is your address (e.g. `https://id.example.com`) plus your key.
* Everything you claim is a **signed statement** in an append-only chain: no
  statement can be changed or removed later without everyone noticing.
* Proofs work both ways: your key claims the account, and the account publishes
  a short text pointing back (`Verifying my Seal ID https://… sid1:…`).
* Your **private key never touches the server.** You sign in your browser
  (OpenPGP.js, bundled — the key stays in the tab) or with any PGP tool (gpg,
  Seal Post) and paste the signature.
* Built to work on ordinary shared hosting with no special settings: no
  database, no cron job, no command line. If your host blocks automated
  requests, add a DNS record and a mirror and others can still verify you.

The full protocol is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

| Proof | How it's checked |
|-------|------------------|
| Website | a line in `https://your-site/.well-known/seal-id.txt` |
| Domain (DNS) | a TXT record `_seal-id.your-domain` |
| GitHub | a public gist |
| X (Twitter) | a public post (via X's public embed service) |
| Mastodon / Fediverse | a public post |
| Bluesky | a post |
| Hacker News | your profile's "about" |
| Reddit | a post |
| YouTube | your channel description |
| Facebook | a **Public** post (read like a link preview: author + text); if Facebook hides it from servers, other Seal ID owners can still witness it |

## Install

Requirements: PHP 8.1+ with the `curl`, `sodium` and `openssl` extensions
(standard on nearly every host), HTTPS, and a (sub)domain or folder for it.

1. Upload the contents of `src/` to the web folder of your (sub)domain,
   e.g. `id.example.com`.
2. Copy `config.example.php` to `config.php` and set `setup_code` to a secret.
3. Open `https://id.example.com/setup.php`, enter the setup code, choose your
   name, load your OpenPGP key and sign your first statement.
4. In the admin page (`/admin.php`), add proofs and follow the instructions.
5. Recommended: add the DNS record shown under **Settings**, and press
   **Test now** to check that other Seal IDs can reach you.

Seal ID keeps its data in a `.sealid-data` folder **next to** the install
folder (outside the web root). Set `data_dir` in `config.php` to change that.

### Updates

From 1.1.0, Seal ID updates itself with one click: **Admin → Settings → Updates**.
It checks GitHub for a new release (at most every 12 hours, or when you press
**Check now**), and installs it only if the package is signed with Seal ID's
release key — a tampered or unsigned download is refused and nothing changes.
`config.php`, your data and `.well-known/` are never touched, and the files it
replaced are kept so **Undo** can put the previous version back.
(Coming from 1.0.0: upload 1.1.0 by hand once.)

### Your domains as your Seal ID address (1.2.0)

A domain you have proven with a **Website** or **Domain (DNS)** proof also works
as your Seal ID address: people can type `example.com` and land on your Seal ID.
For a website proof nothing more is needed; for a DNS proof, the record must also
name your Seal ID: `sid1:… id=https://id.example.com` (the admin shows the exact
value). If the domain stops proving it, it stops working as an alias.

### Badge for your website (1.2.0)

`https://<your Seal ID>/api.php?a=claim&domain=<domain>` answers whether your
Seal ID has a working proof for that domain (also `&service=github&handle=…`):

```json
{"ok": true, "verified": true, "status": "verified", "name": "…", "fp": "…", "url": "…", "profile": "…/", "avatar": "…"}
```

Use it to show a "Verified by Seal ID" badge on your site (cache it for an hour).

### Saved signing key (1.2.0, optional)

Signing by loading your key file (or pasting a signature from gpg / Seal Post)
always works. Optionally, under **Admin → Settings**, save the key:

* **On this device** — encrypted in this browser; unlocked with a passkey
  (Windows Hello, Touch ID, a phone — WebAuthn PRF) or a passphrase.
* **Encrypted copy on your server** — for your other devices; encrypted in the
  browser with your passphrase (PBKDF2-SHA256, 600,000 rounds, AES-256-GCM)
  before upload. Needs a fallback password to sign in on a new device.

The server never receives the key unencrypted.

### Seal Chat (1.2.0)

A **Seal Chat** proof links your Seal Chat ID (`sealchat:<onion>:<fingerprint>`).
If Seal Chat uses the same key as your Seal ID, it proves itself; otherwise
Seal Chat signs the proof with its own key and delivers the signature to
`api.php?a=attest`.

### Profile picture

Add a picture under **Admin → Profile**. It's cropped square and re-drawn on
your server (no photo metadata survives), and its fingerprint (SHA-256) becomes
part of your signed profile — so other Seal IDs show it only if it's exactly
the picture you signed.

### Supported keys

Ed25519 (GnuPG, OpenPGP.js, Seal Post, Seal Chat — including v6 keys) and RSA
2048+. Signing subkeys (e.g. a YubiKey setup) work.

## Development

```
php tests/run.php              # verifier + chain tests
node tests/make-fixtures.mjs   # regenerate OpenPGP.js test keys
node tests/make-chain.mjs      # regenerate the chain fixture
node tests/e2e.mjs <url> <setup_code>   # end-to-end against a fresh install
php tests/update-test.php      # updater: signed / tampered / forged packages, undo
```

### Releasing

1. Bump `SEALID_VERSION` in `src/lib/bootstrap.php`, commit, tag `v<version>`, push.
2. `node tools/release.mjs` → `dist/SealID-<version>.zip` + `.zip.sig`
   (needs the release signing key, which is never in this repository).
3. Publish a GitHub release for the tag with both files attached. Installs only
   accept assets named exactly `SealID-<version>.zip` and `SealID-<version>.zip.sig`.

## License

GPL-3.0. Bundles [OpenPGP.js](https://openpgpjs.org/) (LGPL-3.0).
