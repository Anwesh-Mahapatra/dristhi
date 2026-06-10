# CLAUDE.md — Drishti Normalization Engine (operating contract for Claude Code)

This file is read automatically at the start of every Claude Code session in this repo.
It is **binding**. If a request conflicts with anything here, stop and surface the conflict
before acting. Do not silently work around these rules.

The authoritative design is `docs/design/drishti-ai-normalization-design.md`. When this file
and the design disagree, the design wins on *what* to build; this file wins on *how* to build
it (process, governance, safety). Cite design sections (e.g. "§4.1", "D5") in PRs and ADRs.

---

## 0. What this repo is

Drishti is an open-source, multi-tenant SIEM. This track adds an **AI-native log
normalization engine** that replaces hand-written Python normalizers.

**The one architectural bet, never violate it:** the LLM is a *compiler, not a runtime*.
Claude runs **once per log-source format** (offline, control plane) and emits a declarative
mapping spec (DMS v1). A Go executor applies that spec to millions of events/sec with
**zero inference** on the hot path. Everything below follows from this.

Polyglot layout:
- `drishti-normalizer/` — Go. The hot-path executor + the `check`/`bench` harness (same binary).
- `discovery/` — Python (FastAPI + workers). The control-plane discovery service that calls the Anthropic API.
- `spec/schema/dms-v1.json` — the single DMS v1 JSON Schema (one schema, three consumers: Claude's strict-tool grammar, registry write-validation, Go compiler parse).
- `detections/`, `normalizers/`, `rules/`, `schemas/`, `scripts/` — **existing** detection-side code. Do not break it. The integration contract (§6.1) is: consume `raw.<source>-events`, produce `normalized.events`; detection side needs **zero required changes**.
- `docs/` — design, ADRs, governance.

Infra already running on the Ubuntu 24.04 VM: Redpanda (`:19092`), Schema Registry (`:8081`), Redpanda Console (`:8080`). This track adds Postgres 16 and Redis.

---

## 1. HARD GATE — do not start the build out of order

**Gate zero (§8):** the detection engine must be green first. `matcher.py`, `state.py`, and
`rule_loader._to_match_spec()` (M1.3) must be complete and verified end-to-end **before any
N1+ executor code is written**. Until then, only Prompt 0 (governance scaffolding) and the
N0 *contract* work that does not depend on a runtime are permitted.

**Build order (§8): N0 → N1 → N2 → N3 → N4 → N5. Strictly sequential.**
Do **not** start N(k+1) until N(k)'s exit criteria pass and are recorded in
`docs/governance/GATES.md`. If asked to skip ahead, refuse and explain the dependency.

---

## 2. Architectural invariants (rejecting a violation is correct behavior)

1. **No generated code, ever (D5).** The model emits DMS specs only — a closed vocabulary of ~25 ops enumerated in `spec/schema/dms-v1.json`. Never have the model emit Python/Go/regex-as-program/shell. An unknown op or unknown key is a **compile error**, never partial execution (§2.1).
2. **Closed vocabulary + strict schema.** The DMS JSON Schema is the contract. Executors accept only `spec_version` values they implement. Discovery uses forced strict tool calling (`tool_choice` + `strict: true`) so the model *cannot* emit off-schema (D4, §3.5).
3. **Content addressing = identity.** Specs are authored as YAML, stored as **canonical JSON** (sorted keys, no insignificant whitespace); `spec_hash = sha256(canonical_json)` is the identity. Idempotency is structural, not regenerative (D2, §2.1, §7-Q5).
4. **Runtime determinism is absolute.** Same spec + same raw bytes → byte-identical OCSF. RE2 regex only (no backtracking). Avro fields are schema-ordered. **Sort all map keys (`attrs`, `attrs_num`, `unmapped`) before Avro encode** — Go map iteration is randomized and will break byte-identity otherwise (§7-Q5). Do not chase bit-identical *LLM* output; engineer around it (D2).
5. **The validation harness IS the production binary in `check` mode (D7).** Never validate specs with a Python reimplementation of executor semantics — it drifts. Same binary, same container image, engine parity by construction.
6. **The data plane never blocks on the control plane (§1).** No parser for a source → events go to `dlq.normalization` tagged `no_parser`; a watcher auto-opens a discovery job; ingestion keeps moving. Discovery is asynchronous onboarding, not an ingestion dependency.
7. **A bad spec push must never take down the data path.** Compile error on hot-reload → keep the previous plan, emit `drishti_plan_compile_errors_total`, alarm. Never crash the executor on a bad spec (§4.2, §5.2).
8. **`normalized.events` are immutable.** New format eras (D8, §4.3) never rewrite history. Re-normalization from raw is an explicit, separate offline job if ever wanted.
9. **Nothing is dropped silently.** Every spec has a non-empty `otherwise` branch preserving the raw message; every unparseable/failing event goes to DLQ **with a typed reason**, never a silently-wrong value (§2.6, §5.4).
10. **Tenant isolation is structural.** `tenant_id` scopes every schema and query; compacted-topic keys are `tenant_id:source_type`. **Tenant samples never cross tenant boundaries** and are never attached to community parsers — only lint-clean specs move (§4.4, §6-Q6).

---

## 3. Audit & provenance contract (this is the "audit compliant" part — enforce it)

Every artifact this system produces must be traceable to who/what made it, from what input, validated how.

**Per `parser_version` (DB columns already specified in §4.1 — populate all of them):**
`created_by` (`ai:claude-fable-5` | `human:<id>`), `model_id`, `prompt_version`,
`sample_digest_hash`, `spec_hash`, `validation_report`, `status`, timestamps
(`created_at`/`validated_at`/`activated_at`). A version with missing provenance must not reach `active`.

**Per event (rides in OCSF `metadata`, §6.2):** `parser_id`, `parser_version`, `spec_hash`.
When a detection looks wrong you must be able to name the exact spec that produced the field.

**Immutable job audit trail (§3.2):** every `discovery_job` state transition is appended to a
`job_event` table (job_id, from_state, to_state, actor, detail, ts). The job row + job_event
*is* the audit log — never mutate history, only append.

**Human-in-loop decisions are logged.** Every `review_item` resolution writes a **new
human-authored `parser_version`** (`created_by='human:<id>'`), revalidated like any other
(§3.7). Community promotion requires a logged maintainer approval gate (§4.4-3).

**Versioned prompt assets.** Everything in `discovery/worker/prompts/` is versioned and
content-hashed; `prompt_version` recorded on every spec it produces (§3.5). Changing a prompt
is a tracked change with an ADR if it alters discovery behavior.

**Decisions are recorded as ADRs.** `docs/adr/NNNN-title.md`. D1–D9 from the design are
transcribed as ADRs 0001–0009 at bootstrap. Any new non-trivial decision → new ADR, append-only.

**Reproducibility:** pin everything — Go module versions, Python deps (`uv` lockfile), OCSF
version (`1.5.0`), model IDs (recorded in provenance, never floating), the DMS schema (frozen;
its stability is also what lets Anthropic cache the strict-tool grammar, §2.7).

**Secrets:** `ANTHROPIC_API_KEY` and all credentials come from env / secret manager, never the
repo. A secret-scan pre-commit hook + CI step is mandatory (see §6).

---

## 4. Security & data-handling rules (logs are hostile, attacker-controlled input — §3.9)

- **No prose channel, no side effects in discovery.** Forced single tool, strict schema. The model cannot act on an injected instruction; it can only fill DMS fields. Prompt rule 9 is defense-in-depth; the architecture is the real control.
- **The spec is the entire blast radius.** Worst case of a malicious spec = wrong field mappings, caught by held-out validation + review gates. No network, file, or code ops exist in the vocabulary. Keep it that way.
- **Constant/PII lint on the registry write path (§3.9-4).** Scan all `constants` and `value_map` values against IP / hostname / email / secret-shaped patterns. Block tenant data from fossilizing into specs. This is also the community-promotion gate.
- **Regex safety.** RE2 only (Go `regexp`); enforce compile-time caps on pattern length/count as policy. A hostile pattern (LLM- or human-emitted) must not be able to DoS the executor.
- **Sample custody (§3.2, §3.9-5).** Tenant samples → tenant-prefixed, encrypted-at-rest bucket, accessed only by the worker role, **TTL-purged** after the job. `review_item.sample_values` capped at ≤5 examples, purged on resolve. Document retention in `docs/governance/DATA-RETENTION.md`.
- **Entity-shaped extractions from free text are capped at confidence 0.6** by prompt rule (§2.9) — an IP-shaped token in prose is not a source IP. Never lift that ceiling.

---

## 5. Repo conventions & commands

- **Branch per gate / feature:** `n0/contract-harness`, `n1/executor-core`, … Small, reviewable PRs. One concern per PR.
- **Conventional commits** (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`). Reference the design section in the body (e.g. "implements §3.6 validation report").
- **Every PR description must include:** what changed, which design section it implements, which exit criterion it advances, and a "why / tradeoffs" paragraph with links to the design section + any official doc relied on (§8 reference list).
- **Tests are not optional.** The golden NDJSON fixture (N0) is the regression oracle for everything after it. No merge that reddens it.

**Build/test/lint/bench targets** (create as a `Makefile` at bootstrap; keep these names stable):
```
make build        # build the Go normalizer binary + check the Python service imports
make test         # go test ./... + pytest
make lint         # golangci-lint + ruff + mypy + jsonschema self-check on dms-v1.json
make schema       # validate spec/schema/dms-v1.json is valid 2020-12 JSON Schema
make golden       # replay the N0 golden fixture through `drishti-normalizer check`, diff
make bench        # cmd/normalizer bench — EPS/allocs per plan path
make secrets      # gitleaks/detect-secrets scan
make up / make down  # docker compose for local Redpanda+PG+Redis (dev only)
```

Commands you give me to run should be **copy-pasteable one-liners** (Anwesh runs them directly
in the terminal). No multi-line heredocs in instructions.

---

## 6. How Claude Code should work in this repo

1. **Plan before writing.** For any non-trivial task, produce a short plan (files to touch, order, how you'll verify against the exit criteria) and pause for confirmation before large changes.
2. **Stay inside the current gate.** Do not implement future-gate functionality "while you're here." Scope creep breaks the gated-delivery contract (§1).
3. **Explain decisions, leave doc links.** Anwesh is building this to understand it, not to own a black box. For each module, write the PR description (or a short `WHY.md` for big subsystems) explaining the design choice with links to the design section and the relevant official docs. Never introduce a dependency or pattern without saying why and linking its docs.
4. **Learning-mode toggle.** If a prompt says **"skeleton mode"**, do NOT write full implementations: emit typed function/struct skeletons with `// TODO` bodies, the real signatures and wire formats, and inline documentation links — Anwesh completes the body himself. Default (no toggle) = full implementation in reviewable increments.
5. **Verify, then claim done.** Run `make test`/`make golden`/`make lint` (whichever apply) and paste results. A gate is "done" only when its exit-criteria check is recorded in `docs/governance/GATES.md`.
6. **Never commit secrets.** If you need a credential, read it from env and add a key to `.env.example`. Run `make secrets` before any commit that touches config.
7. **Ask before destructive or irreversible operations** — dropping DB tables/data, force-pushes, deleting topics, rewriting git history, deleting `normalizers/windows_normalizer.py` (that deletion is the final migration step, §6.3, and only after burn-in). Read-only exploration needs no permission.
8. **Provenance is part of "implemented."** A feature that writes a `parser_version`, runs a discovery job, or resolves a review item is not done until it populates the §3 provenance/audit fields.

---

## 7. Reference index

Design doc sections: D1–D9 decisions (top), §1 overview/invariant, §2 DMS spec, §3 discovery
service, §4 registry + eras + fingerprinting, §5 Go executor, §6 integration + migration,
§7 the six questions, §8 build order, §9 references.

Load-bearing external docs (also in §9):
- OCSF schema browser / repo — https://schema.ocsf.io · https://github.com/ocsf/ocsf-schema
- Anthropic strict tool use — https://platform.claude.com/docs/en/agents-and-tools/tool-use/strict-tool-use
- Anthropic prompt caching — https://docs.claude.com/en/docs/build-with-claude/prompt-caching
- Anthropic Batch API — https://docs.claude.com/en/docs/build-with-claude/batch-processing
- franz-go (`pkg/sr`) — https://github.com/twmb/franz-go
- hamba/avro — https://github.com/hamba/avro
- Confluent wire format — https://docs.confluent.io/platform/current/schema-registry/fundamentals/serdes-develop/index.html#wire-format
- RE2 syntax — https://github.com/google/re2/wiki/Syntax
- Postgres `FOR UPDATE SKIP LOCKED` — https://www.postgresql.org/docs/current/sql-select.html
- KEDA Kafka scaler — https://keda.sh/docs/latest/scalers/apache-kafka/
- Redpanda — https://docs.redpanda.com
- Sigma / pySigma — https://github.com/SigmaHQ/sigma-specification · https://sigmahq-pysigma.readthedocs.io
- Apache Avro — https://avro.apache.org/docs/
