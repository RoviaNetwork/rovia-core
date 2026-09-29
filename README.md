# rovia-core

The engine-independent canonical core of Rovia: configuration models,
subscription parsing, routing evaluation, and engine contracts. Pure Swift,
no UI, no network in tests, no engine dependency.

Part of [RoviaNetwork](https://github.com/RoviaNetwork). App lives in
[RoviaNetwork/rovia](https://github.com/RoviaNetwork/rovia), engine
integration in [RoviaNetwork/rovia-engine](https://github.com/RoviaNetwork/rovia-engine).

## Packages

| Package | What it owns |
|---|---|
| `core/config` (`RoviaConfig`) | Canonical models, strict loader, validation. Root: nothing here imports anything else. |
| `core/subscription` (`RoviaSubscription`) | Share-link parsing (vless/trojan/ss), subscription fetch/decode/import, file store, TCP latency probe. Depends on `RoviaConfig` only. |
| `core/routing` (`RoviaRouting`) | Route evaluation, server selection, diagnostics. Depends on `RoviaConfig` only. |
| `engines/api` (`RoviaEngineAPI`) | `TunnelEngine` / `EngineConfigCompiler` contracts. Depends on `RoviaConfig` only. |

Dependency rule: the graph is a DAG rooted at `RoviaConfig`. Nothing here
imports UI, networking runtimes, or engine implementations. Test fixtures
live next to the tests as SPM resources (`Bundle.module`), never as
repository-relative paths.

## Verify

```sh
for p in core/config core/subscription core/routing engines/api; do
  swift test --package-path "$p"
done
```
