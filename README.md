# IONA v27 — Production Hardening Bundle

> Superior Ethereum. BFT instant-finality, sub-second blocks, 2000–8000 TPS.

---

## Ce e nou în v27

- **Schema versioning completă**: migrări automate v0→v3, backup-uri, log de audit, guard pentru versiuni viitoare.
- **Unified EVM executor**: `KvStateDb` leagă revm de `KvState` real — balances, nonces, contracts din aceeași sursă de adevăr.
- **Fuzz CI automat**: 4 targets, corpus cached, crash artifacts, rulează la fiecare push.

## Quickstart (local)

```bash
cargo build --release
./scripts/run_3nodes_local.sh

# verifică
curl -s http://127.0.0.1:9001/health | jq .
```

## Quickstart (Docker)

```bash
# pregătește config-urile în ./data/node{1,2,3}/config.toml (poți porni de la config.toml din root)
docker compose up --build
```

## Chaos harness (local)

Rulare adversarial-ish local (restart-uri + „partition shuffle”):

```bash
cargo run --bin iona-chaos -- --nodes 6 --duration-s 180 --chaos-every-s 10
```

## Remote signer

Client minimal de remote signer: `iona::crypto::remote_signer::RemoteSigner`.
Contractul HTTP e în `docs/remote_signer.md`.

## Config

- By default, nodul caută `./config.toml`.
- Poți forța un fișier: `--config /path/config.toml`.
- CLI flags **suprascriu** fișierul, iar env vars `IONA_*` pot suprascrie ambele.


## Comparație cu Ethereum

| Metric | Ethereum mainnet | IONA v20 (prod) |
|--------|-----------------|-----------------|
| Block time | ~12s | **~300–500ms** |
| Finalizare | ~12s | **instantă (BFT)** |
| Gas/bloc | 30M | **86M** |
| TPS sustenabil | ~15–30 | **~2000–8000** |
| Mempool RBF | ✅ | ✅ |
| Mempool nonce ordering | ✅ | ✅ |
| Mempool TTL | ✅ | ✅ (~300 blocuri) |
| Prometheus metrics | ✅ | ✅ `/metrics` |
| Rate limiting RPC | depinde | ✅ per-IP |
| State root | Merkle Patricia | **SHA-256 Merkle** |
| WAL fsync | ✅ | ✅ + segment rotation |
| Faucet în prod | ❌ | ❌ (flag explicit) |
| Input validation | ✅ | ✅ |

---

## Arhitectură

```
┌─────────────────────────────────────────────────────────┐
│                     IONA v20 Node                        │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Consensus │  │ Mempool  │  │ Storage  │              │
│  │  Engine  │  │  (prod)  │  │  (prod)  │              │
│  │ BFT+fast │  │ nonce-   │  │ WAL+fsync│              │
│  │  quorum  │  │ ordered  │  │ Merkle   │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       │             │              │                     │
│  ┌────▼─────────────▼──────────────▼────┐               │
│  │            P2P (libp2p)               │               │
│  │   gossipsub + mdns + request-response │               │
│  └──────────────────────────────────────┘               │
│                                                          │
│  ┌──────────────────────────────────────┐               │
│  │         RPC (Axum)                   │               │
│  │  /health  /metrics  /tx  /block      │               │
│  │  rate-limited + input validated      │               │
│  └──────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────┘
```

---

## Rulare producție (3 noduri)

```bash
# Nod 1
RUST_LOG=info cargo run --release --bin iona-node -- \
  --listen /ip4/0.0.0.0/tcp/7001 \
  --rpc 0.0.0.0:9001 \
  --data /var/iona/node1 \
  --seed 1 --chain-id 1337 \
  --propose-timeout-ms 300 \
  --prevote-timeout-ms 200 \
  --precommit-timeout-ms 200 \
  --max-txs-per-block 4096 \
  --gas-target 43000000 \
  --fast-quorum true \
  --mempool-cap 200000

# Nod 2
RUST_LOG=info cargo run --release --bin iona-node -- \
  --listen /ip4/0.0.0.0/tcp/7002 \
  --rpc 0.0.0.0:9002 \
  --data /var/iona/node2 \
  --seed 2 --chain-id 1337 \
  [aceiași parametri]

# Testnet cu faucet (NU în producție)
cargo run --bin iona-node -- ... --enable-faucet true
```

---

## Endpoints RPC

| Endpoint | Metodă | Descriere |
|----------|--------|-----------|
| `/health` | GET | Status nod (height, peers, mempool) |
| `/metrics` | GET | Prometheus metrics |
| `/state` | GET | KV state curent |
| `/base_fee` | GET | EIP-1559 base fee curent |
| `/block/<height>` | GET | Bloc după înălțime |
| `/receipt/<block_id>` | GET | Receipts pentru bloc |
| `/mempool/stats` | GET | Statistici mempool detaliate |
| `/tx` | POST | Submit tranzacție |
| `/faucet/<addr>/<amount>` | POST | **Dezactivat în prod** |

---

## Prometheus Metrics

Scrape la `GET /metrics`. Configurare Prometheus:

```yaml
scrape_configs:
  - job_name: 'iona'
    static_configs:
      - targets: ['localhost:9001', 'localhost:9002', 'localhost:9003']
```

**Metrici cheie:**

| Metrică | Tip | Descriere |
|---------|-----|-----------|
| `iona_blocks_committed_total` | Counter | Blocuri finalizate |
| `iona_block_time_ms` | Histogram | Latența commit (ms) |
| `iona_consensus_height` | Gauge | Înălțimea curentă |
| `iona_txs_per_block` | Histogram | TX/bloc |
| `iona_gas_per_block` | Histogram | Gas/bloc |
| `iona_base_fee_per_gas` | Gauge | EIP-1559 base fee |
| `iona_mempool_size` | Gauge | TX în mempool |
| `iona_mempool_admitted_total` | Counter | TX admise |
| `iona_mempool_rejected_total` | Counter | TX respinse |
| `iona_mempool_evicted_total` | Counter | TX evictate |
| `iona_p2p_peers` | Gauge | Peers conectați |
| `iona_rpc_requests_total` | Counter | Request-uri RPC |
| `iona_wal_write_errors_total` | Counter | Erori WAL (alertă!) |

---

## Mempool Production

**Nou față de v18:**
- Cozi per-sender ordonate după nonce (nonce 0, 1, 2... în ordine)
- **RBF**: înlocuire tx cu același nonce dacă noul tip este ≥10% mai mare
- **TTL**: tx expiră după ~300 blocuri (~90s la 300ms/bloc)
- **Evicție**: când pool-ul e plin, se elimină tx-ul cu prioritatea cea mai mică
- Cap per-sender: max 64 tx pending per adresă

**Submit tx:**
```bash
curl -X POST http://localhost:9001/tx \
  -H "Content-Type: application/json" \
  -d '{
    "pubkey_hex": "...",
    "nonce": 0,
    "max_fee_per_gas": 10,
    "max_priority_fee_per_gas": 5,
    "gas_limit": 50000,
    "payload": "set hello world",
    "signature_b64": "...",
    "chain_id": 1337
  }'
```

---

## WAL Production

- **fsync** după fiecare write (datele sunt pe disc înainte de return)
- **Segment rotation** la 64 MiB — fișiere `wal/wal_00000000.jsonl`, `wal/wal_00000001.jsonl`, ...
- **Prune automată**: păstrează ultimele 3 segmente
- **Toleranță la corupție**: linii invalide sunt skip-uite cu warning, nu panic
- **Snapshot periodic**: la 30s, starea engine-ului e salvată în WAL → replay rapid la restart

---

## State Root

v20 folosește un **Merkle tree SHA-256** în loc de `blake3(serde_json(state))`:
- **Deterministic** cross-versiuni (serde_json-ul v18 era dependent de versiunea lib)
- Folii sortate: `kv:<key>`, `bal:<addr>`, `nonce:<addr>`, `burned`
- Noduri interne: `SHA256(0x01 || left || right)`
- Folii: `SHA256(0x00 || len(key) || key || len(val) || val)`

---

## Rate Limiting

Per-IP token bucket:
- Submit (`POST /tx`): 100 req/s
- Read: 500 req/s

Returnează `429`-equivalent JSON: `{"ok":false,"error":"rate limit exceeded"}`

---

## Checklist production deployment

- [ ] `--enable-faucet false` (default)
- [ ] `RUST_LOG=warn` sau `info` (nu `debug` în prod)
- [ ] Firewall: portul P2P (7001) accesibil, RPC (9001) intern sau cu proxy
- [ ] Prometheus + Grafana conectat la `/metrics`
- [ ] Alertă pe `iona_wal_write_errors_total > 0`
- [ ] Alertă pe `iona_rounds_advanced_total` rată mare (semn de contention)
- [ ] Backup periodic al directorului `--data`
- [ ] Cel puțin 4 validatori (quorum 3/4)

---

## Modificări față de v19

| Modul | Schimbare |
|-------|-----------|
| `mempool.rs` | Rescris complet: nonce queues, RBF, TTL, evicție, metrici |
| `wal.rs` | fsync, segment rotation (64MiB), prune, corrupt-line tolerance |
| `merkle.rs` | **NOU**: Merkle tree SHA-256 pentru state root deterministic |
| `metrics.rs` | **NOU**: 20+ metrici Prometheus |
| `rpc_limits.rs` | **NOU**: rate limiting per-IP + input validation |
| `execution.rs` | State root → Merkle în loc de blake3(JSON) |
| `consensus/engine.rs` | `on_block_received()` nou, snapshot periodic |
| `bin/iona-node.rs` | Rescris: metrics, rate limit, WAL prod, faucet gated |

## v23 superior (merged)
Acest pachet combină funcționalitățile din v20 (bootnodes + Kademlia DHT opțional + peer-store persistent) cu v22/v21 (config TOML, governance/slashing, static peers).

### Network flags / config
- `--bootnodes <multiaddr>` (repeatable) / `[network].bootnodes` în `config.toml`
- `--enable-mdns true|false` / `[network].enable_mdns`
- `--enable-kad true|false` / `[network].enable_kad`

Peer-urile configurate sunt persistate în `data_dir/peers.json`.
## Production hardening checklist

This repo now includes scaffolding for:
- **Fuzzing**: see `fuzz/README.md` (cargo-fuzz targets)
- **Property tests**: see `tests/proptests.rs`
- **Security docs**: `SECURITY.md` + `docs/threat_model.md`

Before running on a public network with real value:
- add per-peer rate limiting + connection limits in libp2p swarm
- add encrypted key storage / HSM / KMS
- add schema versioning + migrations for all on-disk formats
- run fuzzing continuously in CI and address findings


## ULTRA v2 package

This repo includes an ULTRA upgrade scaffold (config/ultra.toml, scripts/chaos, monitoring alerts, length-prefixed framing).
See docs/ULTRA_ROADMAP.md.
