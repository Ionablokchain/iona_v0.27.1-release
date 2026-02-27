## v27.2.0 — Formal Upgrade Specification: Safety Invariants, Wire Compat, Dual-Validate

### 1. Formal Upgrade Specification (`spec/upgrade/UPGRADE_SPEC.md`)

- **10-section formal spec** covering: scope/terms, compatibility matrix, activation rules,
  wire compatibility, data model, state transitions, safety properties, liveness assumptions,
  rollback policy, and conformance tests.
- **Formal definitions**: ProtocolVersion (PV), SchemaVersion (SV), SoftwareVersion (SW),
  ActivationPoint (H), GraceWindow (G).
- **Accept predicate**: `AcceptBlock(block, state)` with formal grace window semantics.
- **Producer/Validator rules**: formal specification of block production and validation.

### 2. Compatibility Matrix (`spec/upgrade/compat_matrix.md`)

- **PV x SV x SW compatibility table** for all release versions.
- **Upgrade path matrix** with rollback safety assessment.
- **P2P handshake compatibility** rules.

### 3. TLA+ Safety Model (`formal/upgrade.tla`)

- **Formal verification model** for protocol activation + safety invariants.
- **Invariants verified**: NoSplitFinality, FinalityMonotonic, DeterministicPV,
  AfterGraceOnlyNew, BeforeActivationOnlyOld.

### 4. Wire Compatibility (`src/protocol/wire.rs`)

- **`Hello` handshake** with `supported_pv`, `supported_sv`, `chain_id`, `genesis_hash`.
- **`check_hello_compat()`** — connection rule: `intersection(supported_pv) != {}`.
- **Session PV negotiation**: `min(max(local), max(remote))`.
- **Message type IDs** for forward compatibility (unknown IDs ignored).

### 5. Safety Invariant Checks (`src/protocol/safety.rs`)

- **S1: No split finality** — at most one finalized block per height.
- **S2: Finality monotonic** — finalized_height never decreases.
- **S3: Deterministic PV** — block PV matches local computation.
- **S4: State compatibility** — old PV not applied after activation.
- **M2: Value conservation** — token supply conserved across transitions.
- **M3: Root equivalence** — state root unchanged after format-only migration.

### 6. Dual-Validate / Shadow Validation (`src/protocol/dual_validate.rs`)

- **`ShadowValidator`** — pre-activation shadow validation of blocks under new PV rules.
- **Non-blocking**: failures logged as warnings, do not reject blocks.
- **Statistics tracking**: validated/passed/failed counters.

### 7. Crash-Safe Migration State (`src/storage/meta.rs`)

- **`MigrationState`** struct tracks in-progress migrations for crash-safe resume.
- **`begin_migration()` / `end_migration()`** — bracket migration with persistent state.
- **`has_pending_migration()`** — check for interrupted migrations at startup.

### 8. Upgrade Simulation Tests (`tests/upgrade_sim.rs`)

- **Rolling upgrade simulation** — 5-node network, no activation.
- **Activation with grace window** — PV transition at height H.
- **Deterministic PV verification** — 1000x repeatability check.
- **Finality invariant tests** — monotonicity, no-split.
- **Value conservation tests** — supply preserved.
- **Handshake compatibility** — rolling upgrade handshake simulation.
- **Shadow validation** — non-blocking pre-activation.
- **Migration conformance** — crash-safe resume, future version rejection.

### 9. Cross-Migration Determinism Tests (`tests/determinism.rs`)

- **M3 root equivalence** — state root identical before/after format migration.
- **M1 no key loss** — account keys preserved across migration.
- **M2 value conservation** — total supply unchanged.
- **PV function stability** — deterministic across 1000 calls.

### 10. Documentation Updates

- **`UPGRADE.md`** — formal spec references added.
- **`SECURITY.md`** — formal safety properties referenced.
- **`CHANGELOG.md`** — this entry.

---

## v27.1.0 — Update Infrastructure: Protocol Versioning, Migrations, Release Checklist

### 1. Protocol Versioning (`src/protocol/version.rs`)

- **`CURRENT_PROTOCOL_VERSION = 1`** — every block header now carries a `protocol_version` field.
- **`SUPPORTED_PROTOCOL_VERSIONS`** — list of versions this binary can validate/execute.
- **Activation schedule** — per-version activation height with grace windows for rolling upgrades.
- **`version_for_height()`** — determines which protocol version to use at any given block height.
- **`validate_block_version()`** — rejects blocks with unsupported or expired protocol versions.
- **Config integration** — `consensus.protocol_activations` in `config.toml` for operator-controlled upgrade scheduling.

### 2. Node Metadata (`src/storage/meta.rs`)

- **`NodeMeta`** struct tracks: `schema_version`, `protocol_version`, `node_version`, `updated_at`.
- **Compatibility check** — at startup, detects if on-disk data is too new for this binary.
- **Atomic persistence** — write via `.tmp` + rename.

### 3. Migration Registry (`src/storage/migrations/`)

- **Ordered, idempotent migrations** — each migration is a module (`m0004_protocol_version.rs`).
- **`MIGRATIONS` registry** — append-only list; `run_pending()` applies missing steps.
- **v3 -> v4 migration** — creates `node_meta.json` with protocol version tracking.

### 4. Schema Version Bump

- **`CURRENT_SCHEMA_VERSION = 4`** (was 3) — reflects the new `node_meta.json` file.

### 5. BlockHeader Protocol Version

- **`protocol_version: u32`** added to `BlockHeader` (default 1 for backward compat).
- **`build_block()`** sets `protocol_version` from `CURRENT_PROTOCOL_VERSION`.

### 6. Release Checklist (`scripts/check.sh`)

- **Automated gate**: fmt, clippy, test, release build, binary sanity, determinism, protocol version checks.
- **Exit 1 on any failure** — prevents shipping broken builds.

### 7. Determinism Test Suite (`tests/determinism.rs`)

- **Golden-vector tests** for `hash_bytes`, `tx_hash`, `tx_root`, `receipts_root`, `block.id()`, `state.root()`.
- **Order-independence** — state root is deterministic regardless of insertion order.

### 8. Documentation

- **`UPGRADE.md`** — step-by-step upgrade procedure, rollback plan, expected behavior.
- **`SECURITY.md`** — security impact assessment, threat model, disclosure policy.
- **`CHANGELOG.md`** — this entry.

---

## v27.0.0 — Production Hardening: Schema Migrations, Unified EVM, Fuzz CI

### 1. Schema Versioning & Automatic Migrations (`src/storage/mod.rs`)

- **`CURRENT_SCHEMA_VERSION = 3`** — every breaking on-disk format change now bumps this.
- **`SchemaMeta`** struct replaces the bare `{version}` marker with a full audit trail:
  `version`, `migrated_at` (ISO timestamp), `migration_log` (per-step messages).
- **Atomic writes** — schema.json is written via `.tmp` + rename, so a crash mid-migration
  leaves the schema at the last successful version, not a partial state.
- **Automatic migration path v0 → v3**:
  - v0→v1: introduce schema.json marker (existing nodes, no data change)
  - v1→v2: inject missing `vm` + `burned` fields into `state_full.json`; inject
    `epoch_snapshots` + `params` into `stakes.json`; creates `.v1.bak` backups
  - v2→v3: migrate flat `wal.jsonl` → segmented `wal/wal_00000000.jsonl`
- **Future-version guard** — returns a clear error if the binary is older than the data.
- **6 integration tests** in `tests/schema_migration.rs` covering each migration step,
  idempotency, backup creation, and future-version detection.

### 2. Unified EVM Executor (`src/evm/kv_state_db.rs`)

- **`KvStateDb`** — a `revm::Database + DatabaseCommit` implementation backed by
  the live `KvState`.  This closes the gap between the two previously isolated VM paths:
  - Old: `src/evm/` used a standalone `MemDb` with no access to real balances or nonces.
  - New: EVM transactions see and modify the same state that consensus commits.
- **Address bridge**: IONA 32-byte addresses ↔ EVM 20-byte addresses via
  `iona_to_evm_addr` / `evm_to_iona_addr` (last 20 bytes convention).
- **`execute_evm_on_state()`** — single entry point: takes `&mut KvState`, an `EvmTx`,
  block context (height, timestamp, base_fee, chain_id), runs revm, commits on success.
- **`evm_unified` payload type** in `execute_block_with_staking()`:
  `"evm_unified <hex-bincode-EvmTx>"` routes to the unified executor.
- **`BlockHeader`** gains `chain_id` (default 1337) and `timestamp` (default 0) with
  `#[serde(default)]` — fully backward-compatible with existing serialised blocks.

### 3. Fuzz CI — Automated, Corpus-Cached (`fuzz/`, `.github/workflows/ci.yml`)

- **`p2p_frame_decode`** fuzz target fully implemented (was a TODO stub):
  exercises bincode deserialization of `ConsensusMsg`, `Block`, `Tx`, and
  length-prefixed frames.
- **`vm_bytecode`** — new fuzz target: feeds arbitrary bytecode + calldata into
  the custom VM interpreter; any panic = CI failure.
- **Automated in CI**: new `fuzz` matrix job in `ci.yml` runs each target for 60s
  (configurable via `FUZZ_SECS`); uses nightly toolchain + cargo-fuzz.
- **Corpus caching**: corpus dir cached per target + `Cargo.lock` hash, grows across
  runs without full restart.
- **Crash artifacts**: uploaded automatically on job failure for local reproduction.
- **Additional CI jobs**: `schema-migration`, `proptests` (256 cases), `determinism`.

## v26.0.0 — Custom VM: Contract Deploy, Call & Full Integration

### New: Bytecode Opcodes (`src/vm/bytecode.rs`)
- Complete opcode set: arithmetic (ADD, SUB, MUL, DIV, MOD, EXP), bitwise (AND, OR, XOR, NOT, SHL, SHR)
- Comparison (LT, GT, EQ, ISZERO), SHA3, environment (CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, GAS, PC)
- Memory (MLOAD, MSTORE, MSTORE8, MSIZE), Storage (SLOAD, SSTORE)
- Stack ops: PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16, POP
- Control flow: JUMP, JUMPI, JUMPDEST, STOP, RETURN, REVERT, INVALID
- Logging: LOG0..LOG4
- Gas constants matching EVM: GAS_VERYLOW=3, GAS_LOW=5, GAS_SSTORE_SET=20000, GAS_LOG_BASE=375, etc.
- `push_data_size(opcode)` for correct JUMPDEST analysis

### New: VM State (`src/vm/state.rs`)
- `VmState` trait: `sload`, `sstore`, `get_code`, `set_code`, `emit_log`
- `VmStorage` struct: `storage` BTreeMap keyed by (contract, slot), `code` BTreeMap, `nonces`, `logs`
- `Memory` struct: linear byte array with `ensure()`, `load32`, `store32`, `store8`, `read_range`, `write_range`
- Memory bounds: max 4 MiB per execution; gas charged per new 32-byte word

### New: VM Interpreter (`src/vm/interpreter.rs`)
- Full 256-bit word stack (32-byte arrays, not u128)
- Native 256-bit arithmetic via byte-level operations: `word_add`, `word_sub`, `word_mul`, `word_div`, `word_rem`
- Bitwise: SHL/SHR with byte-level shifting
- Static JUMPDEST analysis before execution (prevents jumping into PUSH data)
- Memory expansion gas charged on every MLOAD/MSTORE
- SSTORE gas: 20,000 for new slot, 2,900 for update, 15,000 for clear
- LOG0..LOG4: gas = 375 + 375×topics + 8×data_bytes; events stored in VmStorage.logs
- CALLDATALOAD with out-of-bounds padding (zeroes)
- Implicit STOP at end of code

### New: VM Executor (`src/execution/vm_executor.rs`)
- `vm_deploy(state, sender, init_code, gas_limit) → VmExecResult`
  - Derives contract address: `blake3(sender || sender_nonce)[..32]`
  - Runs `init_code`; `return_data` becomes deployed bytecode
  - Rejects duplicate addresses (code already exists)
  - Enforces max code size: 24,576 bytes (EIP-170)
  - Reverts discard all state changes
  - Increments sender VM nonce on success
- `vm_call(state, sender, contract, calldata, gas_limit) → VmExecResult`
  - Loads code from `vm.code[contract]`
  - Fails cleanly if no code at address
  - Reverts discard state changes
  - Returns `return_data` and `logs` on success
- `derive_contract_address(sender, nonce) → [u8;32]`: deterministic, nonce-based
- `parse_vm_payload(payload) → Option<VmTxPayload>`: parses `vm deploy <hex>` and `vm call <contract> <calldata>`
- `VmExecResult`: success, reverted, gas_used, return_data, contract (on deploy), logs, error

### Updated: KvState (`src/execution.rs`)
- Added `vm: VmStorage` field — persists contract storage, bytecode, nonces
- `root()` now includes VM storage slots and contract code hashes in Merkle tree
- Two new Receipt fields used: `data: Option<String>` added to all Receipt constructions (previously missing field)

### Updated: execute_block_with_staking (`src/execution.rs`)
- Added `vm ` payload branch alongside `stake ` branch
- `vm deploy <hex>` → calls `vm_deploy`, contract address returned in `receipt.data`
- `vm call <contract> <calldata>` → calls `vm_call`, return data in `receipt.data`
- Malformed `vm ...` payloads → `receipt.success = false, error = "vm: malformed payload"`
- Gas used = intrinsic_gas + VM execution gas
- VM nonce for address derivation based on sender's current VM nonce

### Updated: types/mod.rs
- Added `data: Option<String>` to `Receipt` struct for VM return data / contract address

### New: RPC Endpoints (`src/bin/iona-node.rs`)
- `GET /vm/state` — lists all deployed contracts (address, code_bytes, storage_slots)
- `POST /vm/call` — read-only (view) simulation; does NOT commit state
  - Body: `{ "caller": "hex32", "contract": "hex32", "calldata": "hex", "gas_limit": u64 }`
  - Returns: `{ ok, reverted, gas_used, return_data, logs, error }`

### Updated: CLI (`src/bin/iona-cli.rs`)
- `iona-cli vm state` — queries GET /vm/state
- `iona-cli vm deploy <init_code_hex>` — prints signed tx template with `vm deploy` payload
- `iona-cli vm call <contract_hex> [calldata_hex]` — executes read-only call via POST /vm/call

### New: Tests (`tests/vm_integration.rs` — 25 tests)
**Interpreter unit tests (opcode correctness):**
- test_interpreter_add, test_interpreter_sub, test_interpreter_mul, test_interpreter_div, test_interpreter_mod
- test_interpreter_lt_gt_eq, test_interpreter_iszero
- test_interpreter_and_or_xor_not, test_interpreter_shl_shr
- test_interpreter_dup_swap, test_interpreter_jump_jumpi, test_interpreter_jumpi_conditional
- test_interpreter_calldataload, test_interpreter_sload_sstore, test_interpreter_log1
- test_interpreter_revert, test_interpreter_out_of_gas

**vm_executor lifecycle tests:**
- test_vm_deploy_and_call_counter — deploy + call roundtrip
- test_vm_state_root_changes_after_deploy — Merkle root updated
- test_vm_double_deploy_same_address_rejected — duplicate address guard
- test_vm_revert_discards_state — deploy revert leaves clean state
- test_vm_call_revert_discards_state — call revert leaves clean state
- test_vm_multiple_deploys_unique_addresses — nonce-based addresses differ

**Payload parsing tests:**
- test_parse_vm_payload_deploy, test_parse_vm_payload_call, test_parse_non_vm_payload_returns_none

**Gas / address tests:**
- test_gas_used_increases_with_more_work
- test_contract_address_derivation_is_deterministic
- test_contract_address_different_sender_different_address

---

## v25.0.0 — PoS Rewards & Staking Transactions

### New: Epoch Reward Distribution (`src/economics/rewards.rs`)
- `distribute_epoch_rewards()` called at every epoch boundary (every 100 blocks)
- Computes inflation: `total_staked × base_inflation_bps / 10_000 / epochs_per_year`
- Splits reward: validator commission + delegator share + treasury (`treasury_bps`)
- Auto-compounding: rewards added back to stake (growing TVL over time)
- Treasury accumulates at reserved address `"treasury"` in KvState
- All math uses `u128` to avoid overflow on large stake values

### New: Staking Transactions (`src/economics/staking_tx.rs`)
Payloads routed through normal tx signing pipeline:
- `stake delegate <validator> <amount>` — lock tokens as delegation
- `stake undelegate <validator> <amount>` — begin unbonding (locks for `unbonding_epochs`)
- `stake withdraw <validator>` — claim unbonded tokens after unbonding period
- `stake register <commission_bps>` — register self as validator (requires `min_stake`)
- `stake deregister` — remove self from validator set (no external delegators allowed)

### New: `execute_block_with_staking()` (`src/execution.rs`)
- Routes `stake *` payloads to staking module instead of KV engine
- Preserves fee deduction + nonce logic from normal path
- Backward-compatible: original `execute_block()` unchanged

### New: `/staking` RPC Endpoint (`src/bin/iona-node.rs`)
- Returns: validators (stake, jailed, commission), delegations, unbonding queue
- Shows total staked and all `EconomicsParams`
- Updated `App` struct with `staking_state: Arc<Mutex<StakingState>>` and `economics_params`

### CLI: Staking Subcommands (`src/bin/iona-cli.rs`)
- `iona-cli staking info` — live staking state from node
- `iona-cli staking delegate/undelegate/withdraw/register/deregister` — prints signed tx template

### Tests (`tests/pos_rewards.rs`)
13 new tests covering:
- Epoch boundary detection
- Reward distribution invariant (minted == distributed ± rounding)
- Treasury monotonic growth
- Jailed validators excluded from rewards
- Higher commission → more operator reward
- Delegator reward proportional to stake share
- Auto-compounding stake growth
- Full delegate → undelegate → withdraw lifecycle
- Register and deregister validator
- Cannot delegate to jailed validator
- Cannot deregister with active external delegators

## v24.12.0

## 24.12.0 — A+B+C single-shot hardening

- A) Sybil/eclipsing defense: peer diversity buckets + inbound gating + eclipse detection + reseed hooks.
- B) Gossipsub hardening: topic ACL + per-topic publish/forward caps + spam scoring hooks.
- C) State sync security: validator-set binding + anti-replay epoch/nonce binding (and aggregation scaffolding behind feature flag).


- End-to-end snapshot attestation aggregation (threshold) with manifest attachment.
- State sync delta chains: pathfinding over delta edges, sequential apply with verification, and robust fallback.
- Release-grade SLSA provenance workflow: signed provenance on releases (plus SBOM/audit/deny).

## v24.10.0

- Snapshot attestation (real): multi-validator collection over the network with threshold aggregation; manifests can embed attestations and nodes can request/serve aggregated attestations.
- State sync: delta *chains* support (h1→h2→h3…), pathfinding over available deltas, plus snapshot index exchange for efficient selection.
- Supply chain: SLSA/signed provenance workflow for CI (build provenance attestation), alongside existing SBOM + audit/deny.

## v24.9.0

- State sync: snapshot attestation + threshold verification support; delta sync support (snapshot-to-snapshot diffs).
- Consensus safety: double-sign protection with persisted guard + evidence emission.
- Supply chain: reproducible build check script, SBOM generation, cargo-audit/cargo-deny in CI; optional signed releases workflow.

## v24.8.0
- Mega++: P2P state sync resume with partial chunk re-request (no boundary-only truncation), peer selection uses RTT + measured throughput, and remote signer audit logs real client certificate fingerprint per request.

## v24.5.0
- One-shot Ultra upgrade: encrypted keystore option (AES-256-GCM + PBKDF2), snapshotting (zstd) + restore on startup, optional OpenTelemetry (OTLP) tracing layer (feature `otel`).
- Storage section: snapshot tuning + max_concurrent_tasks scaffold.

## v24.2.0

## v24.4.0
- Enterprise++ networking: peer_score decay, gossipsub publish/inbound caps, persistent quarantine list (survives restart).

- Connection limits + per-peer RR rate limiting
- Automatic schema migrations at startup (schema.json)
- CI fuzzing (PR + schedule)

## v24.3.0
- Enterprise P2P hardening: per-protocol rate limits (Block/Status/Range), per-protocol per-peer bandwidth caps.
- Global request-response bandwidth caps (in/out) with backpressure (drop/skip).
- Peer scoring refinement: strike decay + temporary quarantine with escalation to ban.


# Changelog

## v24.7.0

- Ultra-ultra bundle: P2P state sync (snapshot download) when `state_full.json` is missing.
- Added state-sync protocol `/iona/state/1.0.0` (manifest + chunked transfer).
- Remote signer client (`crypto::remote_signer`) with a tiny HTTP JSON contract.
- Added executable chaos harness `iona-chaos` (restart + partition shuffle scenarios).

## v24.1.0

- Hardening: removed unwrap/expect from critical paths (consensus/storage/RPC)
- Fixed storage::DataDir impl (compile fix)
- P2P anti-DoS: stricter request/response timeouts, range validation
- Added fuzzing harness (cargo-fuzz) + proptest scaffolding
- Version hygiene: Cargo.toml aligned with CLI/README

## v24.0.0

- Added full deployment bundle: `config.toml`, Dockerfile, docker-compose, systemd unit.
- Added `scripts/run_3nodes_local.sh` quickstart.
- Added GitHub Actions CI (build/test/clippy/rustfmt).
- Documentation refresh in README (config-first, quickstart sections).

## v23.x

- Merge of v22 config/governance/slashing + v20 hardened networking (bootnodes, optional Kademlia, persistent peer store).
