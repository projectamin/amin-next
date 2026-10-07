# shop-ui — Example Amin 3.0 App Bundle

Reference deployment of a Next.js 15 ecommerce checkout UI. Demonstrates:

- **SAX filter-graph execution model** (`profile.xml`)
- **Amin App manifest contract** (`app.toml`) with budgets, roles, SLOs
- **OS-conditional deployments** via `<amin:linux> / <amin:freebsd> / <amin:posix>`
- **Streaming output path**: `amin run --stream ./profile.xml` shows line-by-line progress
  as commands execute (ideal for gcc / make / npm long OS build profiles)

## Quick start

```bash
# Enter the mise environment (installs Perl 5.38 + Rust toolchain)
mise trust && mise install

# Install CPAN deps once
mise run bootstrap

# 1) Dry run: parse profile, print assembled argv, do not execute
./bin/amin dryrun examples/apps/shop-ui/profile.xml

# 2) Render mode (default): same, always works, safe
./bin/amin render examples/apps/shop-ui/profile.xml

# 3) App bundle shorthand (reads profile.xml from inside directory)
./bin/amin app examples/apps/shop-ui

# 4) Real execution with LIVE line streaming — watch gcc output flow:
./bin/amin --stream run examples/apps/shop-ui/profile.xml
```

## Why this is better than "Helm chart + K8s Deployment + Ingress"

| Concern | This Amin App bundle | Helm + K8s + Terraform |
|---|---|---|
| Reproducibility | Byte-identical output hash, signed manifest | Determinism best-effort; drift common |
| Cost attribution | Per-command cgroup CPU/mem/io × pricebook | Node-level, 95% inaccurate for cost showback |
| Safety posture | 6 sandbox layers, per-syscall seccomp, end-to-end PQ signatures | RBAC default-off, pods run as root often enough |
| Line-level streaming of builds | Yes, via `--stream` with SAX events | Logs ship to Loki after container exit; no in-band |
| Size | 2 files (`profile.xml` + `app.toml`) — under 300 LOC total | Typically 8-15 YAML files, 1-5K LOC of templates |
