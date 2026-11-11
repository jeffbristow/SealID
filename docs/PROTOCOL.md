# Seal ID protocol — version 1

Seal ID lets one person prove, from a website they control, that they hold an
OpenPGP key and own a set of other accounts (domains, GitHub, X, Mastodon, …).
Every installation can independently verify every other installation. There is
no central server, and no installation ever has to trust another one's word:
everything that matters is signed by the owner's key and re-checked by the
verifier itself.

## 1. Identity

* One installation = one identity. The identity's **address** is the
  installation's base URL, e.g. `https://id.bristow.ch` (always `https://`, no
  trailing slash, lower-case host, an optional path is allowed).
* The identity is anchored on an **OpenPGP key**. Its fingerprint (upper-case
  hex, v4 = 40 chars, v6 = 64 chars) is shown everywhere. This is the same kind
  of key Seal Post and Seal Chat use, so a Seal Chat ID (a fingerprint) can later
  be proven with the same key.
* The private key never touches the server. The server only verifies.

Supported key algorithms (verification is pure PHP: sodium + openssl):
EdDSA/Ed25519 (legacy v4, algorithm 22, as made by GnuPG and OpenPGP.js),
Ed25519 (algorithm 27, RFC 9580 v6 keys) and RSA (2048+ bits). Signing may be
done by the primary key or by a signing-capable subkey with a valid binding
signature (and back-signature).

## 2. The signature chain

The identity is an append-only list of **links**. Each link is a statement
(`payload`) plus a detached, ASCII-armored OpenPGP signature of exactly those
bytes.

```json
{ "payload": "{\"v\":1,\"seq\":1,...}", "sig": "-----BEGIN PGP SIGNATURE-----..." }
```

The payload is a **single line of JSON** (no line breaks, no trailing
whitespace — so binary (0x00) and text (0x01) signatures hash identically).
Fields, in this order:

| field  | meaning |
|--------|---------|
| `v`    | `1` |
| `seq`  | 1, 2, 3 … with no gaps |
| `prev` | `null` for seq 1, else the lower-case hex SHA-256 of the previous link's payload string |
| `ts`   | Unix time (seconds) when it was made; never earlier than the previous link's |
| `url`  | the identity address (stops a link being replayed into another identity) |
| `fp`   | fingerprint of the key that signed this link |
| `type` | see below |
| `body` | type-specific object |

A link's **hash** is `sha256(payload)` in lower-case hex. The chain **head** is
`(seq, hash)` of the last link.

### Link types

| type      | body | notes |
|-----------|------|-------|
| `eldest`  | `{name, bio, avatar?, reset_from?}` | must be seq 1. `reset_from` = old fingerprint when the owner lost a key and started over |
| `profile` | `{name, bio, avatar?}` | replaces display name / bio / picture. `avatar` (1.1.0) = lower-case hex SHA-256 of the picture file; absent = no picture |
| `proof`   | `{service, handle}` | claims an account. The link's seq is the proof's id |
| `revoke`  | `{seqs: [n, …]}` | withdraws earlier `proof`, `vouch` or `mirrors` links |
| `vouch`   | `{target, target_fp, target_seq, target_hash, proofs: [{seq, service, handle, how}]}` | "I checked this other identity". `how` is `auto` (my server verified it) or `witnessed` (I looked at it myself) |
| `mirrors` | `{urls: [...]}` | other places a copy of the bundle can be fetched from (replaces earlier lists) |
| `rotate`  | `{new_fp, new_key}` | key change. Signed by the old key in `sig` **and** by the new key in `sig_new`. Later links use `fp = new_fp` |

Rules a verifier enforces: seq contiguous from 1; `prev` matches; `url` equals
the identity address; `fp` equals the current key (eldest key until a valid
`rotate`); the signature verifies with that key; `ts` never goes backwards.

## 3. The bundle

Everything a verifier needs is one JSON file, written as a **static file** at

    <address>/.well-known/seal-id.json

(also served by `<address>/api.php?a=bundle`). Being static, it is served by any
web host, can be cached by CDNs and can be copied verbatim to mirrors.

```json
{
  "seal_id": 1,
  "url": "https://id.bristow.ch",
  "fp": "current fingerprint",
  "keys": { "FP": "-----BEGIN PGP PUBLIC KEY BLOCK-----..." },
  "chain": [ {"payload": "...", "sig": "..."}, ... ],
  "locators": { "4": "https://x.com/jeff/status/123" },
  "vouched_by": [ {"url": "https://id.example.net", "seq": 7} ],
  "checks": { "4": {"status": "verified", "at": 1762860000} },
  "avatar": { "url": "api.php?a=avatar&h=…", "sha256": "…", "type": "image/webp" },
  "updated": 1762860000
}
```

Only `chain` (and the keys whose fingerprints it names) is trusted. The picture
at `avatar.url` (relative to the address) is shown only if its SHA-256 equals the
`avatar` hash in the newest signed profile statement. `locators`
(where a proof post lives), `vouched_by` (hints of who vouched) and `checks`
(this server's own last results) are unsigned hints that a verifier always
re-checks for itself.

## 4. Discovery and fallbacks (host independence)

A verifier looking up `https://host` tries, in order:

1. `https://host/api.php?a=bundle` (generated per request, so caches can't serve an old chain)
2. `https://host/.well-known/seal-id.json` (static copy, for hosts that block PHP requests)
3. Mirrors: from the DNS record below, then from mirrors it remembered (pinned)
   from earlier visits.

A response that is not valid bundle JSON (a bot-check page, 401/403, HTML) is
reported as **"host blocked automated checking"**, never as "invalid".

**DNS pin (optional, recommended):** a TXT record at `_seal-id.<host>`:

    v=sealid1; id=<identity address>; fp=<FINGERPRINT>; mirror=<https url>; …

A record applies to the identity named by `id=`; a record without `id=` applies
only to the identity at the host's root (`https://host`). Several records can
sit side by side for several identities on one host (1.2.0).

DNS is not filtered by web security systems, so a verifier always learns which
key to expect. A bundle (from anywhere) whose eldest/current key does not match
the DNS fingerprint is rejected.

**Another domain pointing to an identity:** `https://example.com/.well-known/seal-id`
may contain a single line with the identity address, so people can type a
plain domain.

## 5. Proofs

A `proof` link says *the key holder claims this account*. The account then has
to say *this account belongs to that Seal ID*, by publishing the **proof text**:

    Verifying my Seal ID https://id.bristow.ch sid1:<token>

`token` = the first 22 characters of base64url(SHA-256(payload of the proof
link)). It ties the post to that exact signed claim.

| service     | handle form       | where the proof text goes | how it is checked |
|-------------|-------------------|---------------------------|-------------------|
| `web`       | `example.com`     | a line in `https://example.com/.well-known/seal-id.txt` | fetch the file |
| `dns`       | `example.com`     | TXT record `_seal-id.example.com` = `sid1:<token>` | DNS lookup |
| `github`    | `username`        | a public gist (locator = gist URL) | GitHub API: owner + file content |
| `x`         | `username`        | a post (locator = post URL) | X oEmbed: author + text |
| `mastodon`  | `user@instance`   | a public post (locator = post URL) | instance API: account + content |
| `bluesky`   | `handle.tld`      | a post (locator = post URL) | public AppView API: author + text |
| `hackernews`| `username`        | the "about" field of the profile | HN Firebase API |
| `reddit`    | `username`        | a post (locator = post URL) | the post's `.json`: author + text |
| `youtube`   | `@handle`         | the channel description | channel page |
| `facebook`  | profile name/URL  | a public post (locator = post URL) | **witnessed** only (see below) |

Status of a proof as seen by a verifier:

* `verified` — fetched, author matches, token present.
* `failed` — fetched, but the author is wrong or the token is missing.
* `unreachable` — the service could not be reached or blocked us (not the owner's fault; retried later).
* `witnessed` — no automatic check; N other Seal IDs vouched with `how: witnessed`.
* `pending` — needs a locator that hasn't been given yet.
* `revoked` — withdrawn by a `revoke` link.

The owner's own server re-checks proofs lazily (when the profile is viewed and
the last check is older than 6 hours), so no cron job is required.

## 6. Vouching between installations

To vouch for `https://B`, installation A:

1. Fetches B's bundle (section 4) and verifies the whole chain (section 2).
2. Pins B: remembers `fp`, head `(seq, hash)` and mirrors. On later visits the
   new chain must **extend** the pinned one (the link at the pinned seq must
   have the pinned hash) and the key may only change through a valid `rotate`
   link. Otherwise B is shown with a red **"chain rewritten / key changed"**
   warning and A's owner must explicitly re-accept.
3. Re-checks every active proof of B itself.
4. A's owner picks which proofs to vouch for (automatic ones that verified,
   plus any they personally witnessed) and signs a `vouch` link in A's chain.
5. A notifies B: `POST https://B/api.php?a=inbox` with `{"from": "https://A", "seq": n}`.
   B fetches A's bundle, verifies A's chain and the vouch link, and lists A
   under "Verified by". If the POST fails (blocked host), nothing is lost: B's
   owner can import the vouch by pasting A's address, and B re-reads its known
   vouchers when it refreshes.

A visitor of B's profile sees "Verified by A" and can follow it to A, where the
signed vouch link can be checked independently.

## 7. API (`api.php`)

| request | purpose |
|---------|---------|
| `GET ?a=bundle` | the bundle (same as the static file), CORS `*` |
| `GET ?a=avatar` | the profile picture (1.1.0; WebP/PNG/JPEG, ≤ 512 KB, square) |
| `GET ?a=status` | this server's proof statuses; re-checks a few stale ones |
| `POST ?a=inbox` `{from, seq}` | vouch notification (rate-limited) |
| `POST ?a=reach` `{url}` | "can you reach me?" — fetches another installation's bundle and reports what it got. Used by the setup page's reachability test (rate-limited) |

All outgoing requests are HTTPS only, to public IP addresses only (private and
reserved ranges are refused, the resolved address is pinned for the
connection), at most 3 redirects (each re-checked), 1 MB, 10 seconds.

## 8. Signing

The server builds the exact payload; the owner signs it with their key and
sends back the signature. Version 1 offers:

* **In the browser** — OpenPGP.js (bundled, no CDN) loads the private key from a
  file or paste, unlocks it with the passphrase, keeps it in page memory only
  and never uploads it.
* **Copy and paste** — sign the payload elsewhere (e.g. `gpg --armor
  --detach-sign`, or a clearsigned message) and paste the result back.

Later: Seal Post and Seal Chat sign directly, phone approval by QR code.

Admin login uses the same mechanism: sign a one-time challenge. An optional
password can be set as a fallback.
