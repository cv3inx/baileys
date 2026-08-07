# Scaling to thousands of sockets in one process

Notes for running this fork as a multi-tenant bot platform. All numbers below were
measured on Node 24.19 / lru-cache v11 on the machine this was developed on — treat
them as orders of magnitude, not guarantees, and re-measure on your own hardware.

## TL;DR

```js
import { makeWASocket, makeSharedCacheBundle, makeGroupMetadataCache } from '@itsliaaa/baileys'

// once per process
const shared = makeSharedCacheBundle({ maxSockets: 2000 })
const groups = makeGroupMetadataCache()

// per bot
const sock = makeWASocket({
  auth,
  sharedCaches: shared,   // pool the JID-keyed caches
  cacheId: botId,         // stable unique id — namespaces this bot in the pool
  cachePreset: 'tiny',    // right-size whatever stays private
  cachedGroupMetadata: groups.get,   // avoid N identical group IQs
})

// keep group metadata fresh, or you send to a stale participant list
sock.ev.on('groups.update', ([e]) => e?.id && groups.invalidate(e.id))
sock.ev.on('group-participants.update', e => groups.invalidate(e.id))
```

## Measured at 1000 sockets in one process

| | value |
|---|---|
| build time | 1224 ms (1.22 ms/socket) |
| heap | 93 MB (95.4 KB/socket) |
| RSS | 411 MB |
| **steady-state max event-loop lag** | **5.91 ms** |
| steady-state mean lag | 0.14 ms |
| leftover timers | 1 |

Steady state = 1000 live sockets, 3 s observation. Lag during the build burst
peaks at ~78 ms, which is socket construction itself (key generation), not
per-message work — stagger your bot startup and it disappears.

Measured on real `makeWASocket()` instances (300 sockets, no traffic):

| | per socket | projected 5000 |
|---|---|---|
| before | 950.7 KB | 4.53 GB |
| after (`sharedCaches` + `tiny`) | 104.7 KB | 0.50 GB |

## What was wrong

**1. Empty caches were not free.** `new LRUCache({ max: N })` eagerly allocates its
index arrays, so cost is paid up front regardless of contents:

| `max` | empty cost |
|---|---|
| 1024 | 42 KB |
| 5000 | 198 KB |
| 20000 | 783 KB |

`makeWASocket()` allocated ~521 KB of *empty* caches per socket — about 2.5 GB at
5000 sockets before a single message arrived.

**2. Per-socket caches threw away shared work.** Session records, sender keys and
device lists are keyed by JID, which is globally unique. Nothing about them is
socket-specific, so N sockets talking to the same group each paid their own disk
read and held their own copy.

**3. Three caches were unbounded.** `sessionRecreateHistory`, `retryCounters` and
`migratedSessionCache` had a TTL but no `max`, so sustained retry traffic grew them
without limit until a TTL happened to fire.

**4. `ttlAutopurge: true` everywhere.** This schedules a timer per entry. Across
thousands of sockets that is thousands of timers churning one event loop.

**5. `Buffer.concat` per socket frame.** The noise handler rebuilt its whole receive
backlog on every `data` event — quadratic in chunk count. A 512 KB frame arriving in
512 B chunks took **160 ms**; it now takes **3.6 ms** (~45× faster).

**6. Untracked timer per buffered event.** `createBufferedFunction` allocated a
`setTimeout` per call that `destroy()` could not cancel. Timer count is now constant
(verified: 2 live timers at both 50 and 2000 calls).

**7. Dead import broke Yarn PnP.** `import Long from 'long'` in
`Socket/messages-recv.js` — `long` was never declared in `package.json` and `Long`
was never used. Under PnP (and `npm ci --strict`) importing the package threw
outright. Removed.

**8. XEdDSA sign/verify ran in pure JS — the real blocking culprit.** `libsignal`
falls back to `curve25519-js` for `sign`/`verify` (its `generateKeyPair` and ECDH
*do* use node's native x25519, which is why only these two were slow). Measured
**8.0 ms per sign and 7.6–18 ms per verify**, fully synchronous, on the one event
loop every socket shares. The `whatsapp-rust-bridge` dependency already exposed
native `calculateSignature`/`verifySignature` and the library simply wasn't using
them: **120× faster sign, 73× faster verify**. Event-loop lag under signature load
dropped from **209 ms to 2.4 ms (89×)**.

The native path is self-tested once at load before being trusted — it must
round-trip against itself, interoperate with libsignal in *both* directions, and
reject a tampered signature; any failure silently keeps pure JS. This matters
because these signatures gate device pairing and prekey upload, so a subtly broken
backend would not crash, it would get accounts rejected by WhatsApp. Note the two
backends produce different bytes for the same input — XEdDSA uses a randomised
nonce, so that is spec-conformant, and they cross-verify (checked over 200 random
key/message pairs plus 500 round trips).

`Curve.verify` also normalises a real API discrepancy: the native backend returns
`false` on failure while libsignal *throws*.

**9. `useMultiFileAuthState` leaked a Mutex per key id, forever.** `fileLocks` only
ever grew — one entry per pre-key/session id the bot had ever touched. Verified
directly: 20 000 unique ids left **20 000 retained entries before, 0 after**. Heap
cost is small (~32 B/entry) so it hides in noise, but it is monotonic for a
process that runs for months. Locks are now released once idle, with per-file
locking (and therefore write-safety) unchanged — confirmed by 200 concurrent
same-key writes and 200 parallel distinct-key writes.

**10. Deleted signal keys came back as `null` cache hits.** Pre-existing bug in
`makeCacheableSignalKeyStore`, unrelated to scale but found while testing the
namespaced cache. Callers delete a session or pre-key by setting it to `null`;
`store.set()` treats that as a delete, but the cache *stored* the `null`. A later
`get()` then hit the cache and returned `{ id: null }` instead of falling through to
the store — a key that reads as present-but-null rather than absent. Now evicted
instead of cached. Verified fixed against both the default `NodeCache` and a shared
namespace.

## New options

| option | meaning |
|---|---|
| `sharedCaches` | pools from `makeSharedCacheBundle()`; share across all sockets in the process |
| `cacheId` | stable unique id per bot. **Required** with `sharedCaches` |
| `cachePreset` | `'tiny' \| 'small' \| 'medium' \| 'large'`, or an object overriding slots |

Presets are per-socket entry ceilings for caches *not* served from a pool:

| preset | use when | session/senderKey |
|---|---|---|
| `tiny` | 1000+ sockets/process | 64 |
| `small` | 200–1000 | 256 |
| `medium` | 50–200 | 1024 |
| `large` | few sockets (**default**) | 5000 |

`makeSharedCacheBundle({ maxSockets, entriesPerSocket = 32 })` sizes pools as
`max(1000, maxSockets * entriesPerSocket)` — a total entry budget across all
sockets, so process memory is bounded by the pool rather than by socket count.

### Isolation

Each socket gets a namespaced view over the shared pool. Namespaces are isolated:
`bot-a` and `bot-b` can both hold key `sess:x` with different values. On socket
teardown, `close()` drops only that bot's entries.

Notably, `clear()` on a namespace is scoped to that namespace. `libsignal` calls it
on identity change and session delete; if it reached the shared backing store it
would wipe every other bot's sessions and cause a fleet-wide Bad MAC storm.

## Packaging / dependency alignment

Done at the library level so the package drops into a consumer that pins newer
versions (checked against a real bot using `@neoxr/wb` + this fork):

- **Dependency ranges widened to accept what consumers already resolve.**
  `@cacheable/node-cache` was `^1.4.0` while the consumer wanted `^3.1.1`; yarn
  silently gave Baileys 1.7.6, so two copies could coexist. Now
  `^1.4.0 || ^2.0.0 || ^3.0.0`, and `pino` is `^9.6.0 || ^10.0.0`. Verified v3 and
  pino 10.3.1 against every API Baileys actually uses.

  One real v3 incompatibility to know about: **v3's `mset` requires
  `{key, value}` and silently ignores `{key, val}`**. Baileys never calls `mset`
  on a NodeCache (only `mget`), so it is unaffected — but do not assume the v1
  shape works if you call it yourself. `NamespacedCache.mset` accepts both.

- `fflate`/`lru-cache`/`audio-decode` floors lowered, `@napi-rs/image` and `sharp`
  loosened from `~`/exact to `^`, and `better-sqlite3` to `>=12.1.1 <13` — these
  were needlessly tight and forced duplicate installs.

- **`sharp` is now marked optional** in `peerDependenciesMeta`. It was the only
  image peer *not* marked optional despite
  `Utils/messages-media.js:17-38` falling back to `@napi-rs/image` or `jimp`.

- **Added an `exports` map.** The package is `"type": "module"` with no `exports`,
  which meant no encapsulation and a `require()` example in the README that cannot
  work. The map deliberately keeps `./lib/*` and `./WAProto/*` open, because
  consumers deep-import them (one bot's `extractor/proto.js` writes to
  `node_modules/baileys/WAProto`). Verified: root, `./lib/...`, `./WAProto`, and
  `./package.json` all still resolve.

- **`makeLibSignalRepository` is now exported from the barrel**, so overriding
  `config.makeSignalRepository` no longer needs a deep import.

### The blocker this fixed

The dead `import Long from 'long'` was not theoretical — a real bot pinning commit
`fab9767` of this fork **could not import Baileys at all**:

```
Error: baileys tried to access long, but it isn't declared in its dependencies
Required by: baileys@.../lib/Socket/messages-recv.js
```

Yarn PnP enforces declared dependencies strictly, so the unused import was fatal.
Removing that one line makes the package import cleanly (310 exports). `long` is
*not* added as a dependency: nothing in `lib/` references it, and protobufjs pulls
it in for its own use.

## Breaking changes

1. **`ttlAutopurge` is now `false`** on all internal LRU caches. Entries still
   expire, but lazily on read instead of via a per-entry timer. If you relied on
   `dispose` firing at the exact TTL moment without a subsequent read, it now fires
   on the next read or eviction instead.

2. **`migratedSessionCache`, `sessionRecreateHistory` and `retryCounters` are now
   bounded** (`preset.session` / `preset.retry`). Previously unbounded. With
   `cachePreset: 'tiny'` these are small — if you run few sockets and want the old
   effectively-unlimited behaviour, use the default `large` or pass an explicit
   object: `cachePreset: { retry: 50000 }`.

3. **`makeLibSignalRepository(auth, logger, pnToLIDFunc, cacheOpts?)`** takes a
   fourth argument. Existing 3-arg calls keep working (defaults to `large`).

4. **`new MessageRetryManager(logger, maxMsgRetryCount, preset?)`** takes a third
   argument. Existing 2-arg calls keep working.

Not passing any new option leaves sizing at the previous values; only the
`ttlAutopurge` and bounding changes apply unconditionally.

## Compatibility with upstream Baileys

Checked against `WhiskeySockets/Baileys` `src/Types/Socket.ts` on `master`:

- The upstream `CacheStore` contract is `get`/`set`/`del`/`flushAll`/`close?`, and
  `PossiblyExtendedCacheStore` adds `mget`/`mset`/`mdel`. `NamespacedCache`
  implements all of it, plus the lru-cache surface (`delete`/`clear`/`size`) that
  `Signal/libsignal.js` drives its caches with.
- Upstream `mset` takes `{ key, value }` while NodeCache uses `{ key, val, ttl }`.
  Both shapes are accepted.
- Upstream `makeSignalRepository` takes 3 args. The optional 4th arg here is
  additive — verified that a user-supplied 3-arg factory and a bare 3-arg
  `makeLibSignalRepository()` call both still work, as does passing your own
  `userDevicesCache`/`msgRetryCounterCache`/`callOfferCache`/`placeholderResendCache`.
- `cachedGroupMetadata` is upstream's documented way to "prevent redundant requests
  to WA & speed up msg sending" and defaults to `undefined` here, meaning *every*
  group send issues a `groupMetadata()` IQ. With N bots in the same group that is N
  identical rate-limited queries. `makeGroupMetadataCache()` is the shared fix.

Upstream's own README carries no scaling, cache, or concurrency documentation — it
redirects to `baileys.wiki`, which is explicitly "a work in progress" and whose
`/docs/socket/...` paths currently 404. The authoritative reference is
`src/Types/Socket.ts` in the repo. Upstream also states it "discourage[s] any
stalkerware, bulk or automated messaging usage" — worth reading before you scale a
bot fleet, since WhatsApp bans on behavioural signals regardless of library.

## Still worth doing

Things this pass did **not** address, roughly in order of expected payoff:

- **No shared WS agent.** Each socket opens its own TCP connection with no
  connection/DNS reuse. Passing a shared `agent` with a raised `maxSockets` is
  worth testing.
- **AES-GCM message crypto is still synchronous**, but at 0.037 ms/op for 1 KB it
  is ~200× cheaper than the signature work that was fixed. Only worth moving to
  `worker_threads` if profiling under your real traffic shows it dominating — do
  not do it speculatively.
- **`better-sqlite3` is synchronous by design**, so `useSQLiteAuthState` blocks the
  loop on every key read/write. Fine for a handful of bots; for thousands prefer an
  async store (Redis/Postgres) or move SQLite to a worker.
- **`makeInMemoryStore` uses `writeFileSync`/`readFileSync`**
  (`Store/make-in-memory-store.js`) — blocking, and the whole store is serialised
  per save. Avoid its file persistence at fleet scale.
- **If your wrapper is obfuscated, verify the options reach the socket.** One real
  consumer goes through `@neoxr/wb`, whose bundles are string-array obfuscated —
  none of `userDevicesCache`, `msgRetryCounterCache`, `cachedGroupMetadata`, or even
  `browser` appear as readable strings, so there is no way to confirm by reading
  that it forwards its second `Client()` argument to `makeWASocket` verbatim. If a
  wrapper builds the config itself, `sharedCaches` / `cacheId` / `cachePreset` may
  be dropped before reaching the socket. The library-side changes that need **no**
  wrapper cooperation still apply unconditionally: native XEdDSA, the noise
  buffer, bounded caches, `ttlAutopurge: false`, the timer and lock leaks, and the
  `null`-cache delete bug. Only the opt-in pooling needs the wrapper to pass
  options through — test it against your wrapper before relying on it.

- Separately, that wrapper has **its own undeclared dependency**: it requires
  `@cacheable/node-cache` from `lib/Utils/memory-store.js` without declaring it,
  which breaks the same way under PnP. That one has to be fixed in the wrapper (or
  worked around with a `packageExtensions` entry in the consumer's `.yarnrc.yml`) —
  it is outside this library.
- **`DONATE_URL` injection** — unrelated to scale, but the library substitutes the
  maintainer's donation link into outbound messages when a URL is omitted
  (`Defaults/index.js`, used in `Utils/messages.js` and `Utils/rich-message-utils.js`).
  Your bots will send it under their own name.
- **No `exports` map in `package.json`** while `"type": "module"` is set, so the
  `require()` example in the README cannot work.
