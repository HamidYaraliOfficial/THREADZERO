# Architecture

```
            ┌────────────────────────── web studio (Next.js, static export) ─────────────────────────┐
            │  Architecture Studio · DSL Editor · Trust Boundary Canvas (2D/3D) · Simulators · Labs   │
            └───────────────▲──────────────────────────────────────────────────────────────▲──────────┘
                            │ REST (FastAPI)                                                │ WebAssembly in the browser
 ┌─────────────────────────┴───────────────┐   JSON    ┌───────────────────────────┐   ┌───┴────────────────────┐
 │ Python: orchestration, project loader,  │◀─────────▶│ Haskell core              │   │ WASM security runtime   │
 │ code generators (WAT/Rego/JS/TS/guards),│  stdin/   │ lexer · templates · parser│   │ authorize · validate_*  │
 │ runtime host, registry, signing, tests, │  stdout   │ type system · solver ·    │   │ classify_data · audit   │
 │ reports, CI, git adapters, AI tools     │           │ graph analyzer · policy   │   │ deterministic, no host  │
 └─────────────────────────────────────────┘           │ IR · refactoring engine   │   │ imports, fuel limited   │
                                                       └───────────────────────────┘   └─────────────────────────┘
```

* **Haskell** owns every semantic decision: the typed DSL, Security AST, semantic analysis, the finite-domain constraint solver (with SMT-LIB export adapter), graph verification,
  policy precedence/conflicts/optimisation, coverage, generated test cases and the refactoring engine (graph transformations with pre/postconditions).
* **Python** turns the analysis (`threadzero-core analyze`) into artifacts and runs everything around it. The Python layer never re-implements analysis rules.
* **WASM** is the execution target. The ABI is a packed `int32` request struct (`authorize(in, out)`, `validate_flow`, `validate_boundary`, `inspect_context`, `classify_data`, `audit_event`, `deny_reason`).
  Tables (boundary requirements, data/zone permissions) live in the module's data section.

## Verification strategy

Four independent evaluators of the same policy IR must agree on every generated and random request: the Haskell decision engine, the WASM module (wasmtime and browser), the Python reference engine,
and the generated JavaScript wrapper / Rego policy (checked with `node` and `opa` when installed).

## Reproducibility

`compile` writes `threadzero.lock` (compiler + ruleset + schema versions, source hashes). Artifacts and the signed `.tzpkg` contain no timestamps; the manifest hash is stable across runs and machines.
