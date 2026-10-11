# Contributing to Hammerhead

Development is on `v0.2-dev` in [talarurus/hammerhead](https://github.com/talarurus/hammerhead), module `github.com/talarurus/hammerhead`. Go 1.26.0 is the module minimum; use supported patches for ordinary development. The development version is `0.2.0-dev`, not a published v0.2 release. Git is required for real Git fixture tests; Make is optional.

```sh
git clone --branch v0.2-dev https://github.com/talarurus/hammerhead.git
cd hammerhead
make build
./hammerhead version
```

## Verification

Format only files you changed, then verify without rewriting unrelated files:

```sh
gofmt -w path/to/changed.go
gofmt -l cmd internal   # must print no filenames
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

Use Go 1.26.9 for the frozen G12 checkpoint and check the current supported toolchain as well. `make test` runs race tests; `make check` and `make fmt` write formatting changes. Do not use them as a read-only formatting check. Tests use owned temporary directories, synthetic patterns, deterministic stage/readiness barriers and parent watchdogs. Never submit real credentials, create privileged devices, or weaken a containment/status/process/output assertion to obtain a pass. Report failures, corrections and retries.

## CI and platform evidence

`.github/workflows/ci.yml` handles pushes and PRs targeting both `main` and `v0.2-dev`, with `contents: read` and no publishing/deployment. Each OS runs module minimum Go **1.26.0** and setup-go’s **stable** alias with latest resolution. At this reconciliation current stable is Go 1.27.2; `stable` tracks future supported releases. The version and native architecture are printed in each job.

| Environment | Native execution | Compile-only targets |
| --- | --- | --- |
| GitHub `ubuntu-24.04` | Linux amd64: formatting, vet, full/race tests, integrated gates, repeated descendant cleanup | All four targets below |
| GitHub `macos-15-intel` | macOS amd64: same gates | All four targets below |
| Local G12 host | macOS arm64: Go 1.26.9 and current Go checks | All four targets below |
| Local OrbStack Docker, arm64 Go image | Linux arm64 on native arm64 VM CPU: Go 1.26.9/current checks | All four targets below |

These explicit standard labels follow [GitHub’s hosted-runner architecture table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners); no privileged or assumed arm64 runner is required. Local results do not establish GitHub workflow execution; those jobs require a later authorized push/PR. Cross-compilation is never runtime filesystem/process validation.

```sh
build_dir=$(mktemp -d)
for target_os in darwin linux; do
  for target_arch in arm64 amd64; do
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
      go build -o "$build_dir/hammerhead-$target_os-$target_arch" ./cmd/hammerhead
  done
done
```

Keep temporary binaries outside source. This builds only; do not run GoReleaser or publish a release as part of the foundation gates.

## Check architecture

`internal/check/check.go` defines:

```go
type Check interface {
    Meta() Meta
    Run(ctx context.Context, sc *ScanContext) error
}
```

Emit through `sc.Emit(finding)` and return its budget error immediately. Native content reads, including binary classification, must use `sc.ReadFile` and its typed outcomes. Never walk/open content directly, suppress an eligible read failure, or infer absence from incomplete/excluded root facts. Use the supplied Git snapshot; no check launches subprocesses. Per-run options and caller slices must stay isolated.

Register explicitly in `internal/engine/registry.go::DefaultRegistry`, with no `init()` registration. Rule changes require independent scope approval and positive/negative/boundary/redaction regression cases. C15 adds no detector. Findings and their IDs remain serializable data; titles are not variant identities or explanation catalog keys.

## Security and review

Only existing bounded Git execution is supported; pass explicit argv, never a shell command. Respect rooted/exclusion boundaries, cooperative cancellation and producer budgets. Sanitization protects terminal presentation; producer redaction separately protects secret material. Neither promises path privacy, perfect detection, an OS sandbox or interruption of arbitrary kernel I/O. See [SCAN-RESULT.md](docs/contracts/SCAN-RESULT.md), [OUTPUT.md](docs/contracts/OUTPUT.md) and [SECURITY.md](SECURITY.md).

Keep historical v0.1 fixtures/tag/release assets immutable. [testdata/contracts/README.md](testdata/contracts/README.md) distinguishes contract examples from captured historical and active reporter goldens. Describe behavior, scope, exact validation evidence and remaining limits in review artifacts. Keep commits focused; independent G12 approval precedes any commit/push for this checkpoint. The frozen roadmap and later phases are not changed by documentation reconciliation.
