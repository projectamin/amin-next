# Amin App Bundle Contract (v3.0)

An **Amin App** is a self-contained, signed, reproducible, relocatable bundle of everything needed to deploy *one logical service* on Amin's fabric. It is the native deployment unit that replaces Docker images + K8s manifests + Helm charts + Terraform modules for teams living the "Amin native" way.

Every app is a directory (or a `.amina` tar.zstd archive) with this structure:

```
my-shop-ui/                      ← App directory (name = "my-shop-ui")
├── profile.xml                  ← SAX profile. REQUIRED.
├── app.toml                     ← Identity, roles, budgets, replicas. REQUIRED.
├── README.md                    ← Human docs (how to run, caveats)
├── machine_spec.xml             ← Optional: custom filter list for this app
│                                  (defaults to Amin built-in registry)
├── filters/                     ← Optional: Type P / Type N plugin filters
│   ├── StripeWebhookVerifier.pm ←   Perl Safe plugin (Type P), signed .aminsig
│   └── image-optimizer.elf      ←   Native disposable child (Type N), signed
├── files/                       ← Optional: static assets referenced by profile
│   ├── nginx.conf.template
│   └── systemd.service.in
├── tests/                       ← Optional: post-deploy SAX test profiles
│   └── smoke.xml                ←   curl /health, assert 200, assert <100ms
└── examples/                    ← Optional: reference adminlist + networkmap
    ├── adminlist-3tier.xml
    └── networkmap-prod.xml
```

## app.toml fields

| Field | Required | Description |
|---|---|---|
| `id` | ✓ | Globally unique app ID (reverse DNS recommended: `com.acme.shop-ui`) |
| `version` | ✓ | SemVer 2.0 + optional git SHA suffix: `1.2.3+abc1234` |
| `authors` | ✓ | `["Name <email>", ...]` — every release MUST be composite-signed with at least 1 author key. |
| `description` | ✓ | One-line + long markdown blurb |
| `tier` | ✓ | `dev / staging / prod / pci / hipaa` — selects sandbox tier (strictest first) |
| `supported_os` | ✓ | OS matrix the Amin App declares compatibility with.  Must match `backend.kind` exactly.  Enum:  `linux>=6.2`, `freebsd>=14`, `illumos`, `ios>=14`, `android>=33`, `posix`.  POSIX fallback MUST be listed unless the app genuinely needs Linux-only cgroups. |
| `schedule.replicas` | ✓ | `{ min=2, max=20, cpu="200%", mem="4G", per_host_density=64 }` |
| `schedule.anti_affinity` |  | rack / host / zone / region |
| `storage` |  | `[ { name="assets", size="50G", class="nvme", backup="daily+pitr7" } ]` |
| `network.ports` |  | `[ { name="http", number=80, public=true, lb="anycast" } ]` |
| `iam.roles` |  | `[ { role="blob.put", on="blob:user-uploads/*" } ]` |
| `secrets` |  | `[ { name="stripe_webhook_secret", kms_key="prod-app-01", source="env" } ]` |
| `observability` |  | `{ slos = [{name="p95-latency-ms", lte=250, window="30d"}], logs="ecs-fields-v8" }` |
| `billing.owner` |  | Team/cost-center for per-process cgroup invoicing |
| `compliance` |  | `{ fedramp_mod = ["AC","SC","SI"], pci_dss = ["3.4","6.5"] }` |

## Provable Reproducibility

Given identical inputs (same app bundle, same `filter registry hash`, same host firmware/OS measured-boot log), **running `amin app render ./my-shop-ui` twice on two different Amin control planes MUST produce byte-identical `provenance.xml` output before signature.** Any deviation → provenance verification fails. This is how Amin apps are "more deterministic than Nix + Docker combined."

## AI-Assisted Authoring (Tier 0 LLM path)

The command:
```
amin app scaffold --from-prompt "I need a Next.js 15 ecommerce checkout UI with Stripe webhook verification, static assets on S3-compatible blob, deployed on 4 replicas, rate limit 500 rps per IP, SOC 2 compliant"
```
produces a skeleton app bundle with `profile.xml` + `app.toml` + scaffold `filters/` + scaffold `tests/smoke.xml`. Output is marked **Tier 0 LLM-generated** — before it can deploy to prod it must be signed by ≥1 human and upgraded to Tier 2 Signature via `aminsig sign`.
