# KRON

**India's first on-premise SIEM built for Indian compliance, Indian teams, and Indian budgets.**

---

## What is KRON?

KRON is a Security Information and Event Management (SIEM) platform that:

- Runs **completely on your own hardware** — no data leaves your organization
- Works on a **₹30,000 old server** — not a ₹25 lakh dedicated appliance
- Sends alerts via **WhatsApp** — not a dashboard nobody checks
- Speaks **Hindi** — not just English
- Ships with **Indian compliance templates** — CERT-In, RBI, DPDP Act out of the box
- Runs in **autopilot mode** — for organizations with no dedicated security staff
- Deploys in **30 minutes** — not 6 months

---

## Why KRON?

Every existing SIEM was built for a US enterprise with a $2M security budget and a dedicated SOC team. India has millions of organizations — banks, hospitals, manufacturers, NBFCs — that need real security but cannot afford Splunk, cannot send their data to Microsoft's cloud, and have no security team to operate QRadar.

KRON fills that gap.

---

## Quick Start

### On any Linux machine (8 GB RAM minimum):
```bash
curl -fsSL https://install.kron.security | sudo bash
```

### USB install (air-gap):
Download `kron-nano.iso` → write to USB → boot target machine → follow wizard.

### Kubernetes (Standard/Enterprise):
```bash
helm repo add kron https://charts.kron.security
helm install kron kron/kron -f values.yaml
```

---

## Documentation

| Document | Description |
|---|---|
| [PRD.md](./PRD.md) | Product requirements, personas, success metrics |
| [Features.md](./Features.md) | Complete feature specification by tier |
| [Architecture.md](./Architecture.md) | System architecture, data flows, deployment topology |
| [TechStack.md](./TechStack.md) | Every technology choice with rationale |
| [Database.md](./Database.md) | Full schema, indexes, retention, migrations |
| [API.md](./API.md) | Complete REST + WebSocket API reference |
| [Security.md](./Security.md) | Security architecture, encryption, access control |
| [Deployment.md](./Deployment.md) | Install and upgrade guides for all tiers |
| [AIInstructions.md](./AIInstructions.md) | AI/ML implementation — ONNX models, Mistral integration |
| [UIUX.md](./UIUX.md) | UI/UX specification, screen inventory, design system |
| [Runbooks.md](./Runbooks.md) | Operational runbooks for every major failure scenario |
| [Roadmap.md](./Roadmap.md) | v1.0 / v1.5 / v2.0 feature roadmap |

---

## Deployment Tiers

| | KRON Nano | KRON Standard | KRON Enterprise |
|---|---|---|---|
| Hardware | 8 GB RAM, any x86 | 16–32 GB RAM | 128 GB+ per node |
| Storage engine | DuckDB | ClickHouse | ClickHouse HA |
| Scale | 50 endpoints, 1K EPS | 500 endpoints, 50K EPS | Unlimited |
| Multi-tenancy | — | ✓ (MSSP ready) | ✓ |
| HA | — | — | ✓ |
| Price | Free / ₹2,999/mo | ₹8–25K/mo | Custom |

---

## License

KRON Nano is open-source (Apache 2.0).  
KRON Standard and Enterprise are commercial products.  
See LICENSE.md for details.

---

## Contact

**Jashan** — Founder  
Website: kron.security  
Email: hello@kron.security
