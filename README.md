# terraview

[![CI](https://github.com/kanchichitaliya/terraview/actions/workflows/ci.yml/badge.svg)](https://github.com/kanchichitaliya/terraview/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/terraview)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

LLM-powered Terraform security analyzer.

Most IaC scanners flag individual misconfigurations in isolation. terraview goes further: it builds a resource dependency graph from your Terraform plan, finds cross-resource attack chains, and uses an LLM to reason about architectural risk — things no static rule can catch.

**Example finding static scanners miss:**

```
CRITICAL | CHAIN-001: Public EC2 with open SSH leads to admin IAM role

aws_instance.web is internet-exposed with a public IP and open SSH (port 22).
It is attached to aws_iam_instance_profile.ec2_profile, which grants
aws_iam_role.ec2_role — a role with wildcard admin permissions via
aws_iam_role_policy.ec2_admin_policy. An attacker with SSH access can query
the instance metadata service (IMDS) to retrieve temporary credentials for
the admin role and pivot to any resource in the AWS account.

MITRE: T1552.005 (Credential Access → Privilege Escalation)
Blast radius: aws_instance.web, aws_iam_instance_profile.ec2_profile,
              aws_iam_role.ec2_role, aws_iam_role_policy.ec2_admin_policy,
              aws_security_group.open_sg
Remediation:
  1. Set associate_public_ip_address = false
  2. Restrict security group to known CIDRs
  3. Replace Action:'*' with least-privilege actions
```

That finding connects five resources into a single attack narrative. Checkov gives you five separate alerts with no context.

---

## How it works

terraview runs three analysis layers in sequence:

**1. Static analysis:** Built-in single-resource checks run against the graph directly. Optionally ingest findings from Checkov — terraview enriches missing severity and remediation fields via LLM so you get full context even on the free tier.

**2. Graph traversal:** Parses your Terraform into a directed resource graph and walks it to find cross-resource attack chains — IAM privilege escalation paths, public exposure chains, and blast radius analysis.

**3. LLM reasoning:** Sends the resource graph and existing findings to an LLM to identify architectural gaps, missing controls, and risks that span multiple resources.

Every finding includes a MITRE ATT&CK technique, blast radius, and a Terraform remediation snippet. Findings are deduplicated across all three layers before the report is written.

---

## Quickstart

```bash
git clone https://github.com/kanchichitaliya/terraview
cd terraview
poetry install --extras anthropic
export ANTHROPIC_API_KEY=sk-ant-...

terraview scan ./examples/vulnerable
```

Output is a Markdown report written to `report.md` by default.

---

## CI pipeline (recommended)

Operate on a resolved Terraform plan so all variable values are known and only changing resources are in scope:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# Optional: Checkov on the plan for rule-based findings
checkov -f plan.json --framework terraform_plan -o json 2>/dev/null > checkov.json

# Scan — exits 1 on any CRITICAL finding
terraview scan --plan plan.json --checkov-output checkov.json --format sarif --output results.sarif
```

SARIF output is rendered as inline PR annotations by GitHub Actions:

```yaml
- name: Terraform security scan
  run: |
    terraform show -json tfplan > plan.json
    terraview scan --plan plan.json --format sarif --output results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Installation

**Base install (graph traversal + static checks, no LLM):**
```bash
poetry install
# or: pip install -e .
```

**With Anthropic:**
```bash
poetry install --extras anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

**With OpenAI:**
```bash
poetry install --extras openai
export OPENAI_API_KEY=sk-...
export TERRAVIEW_PROVIDER=openai
export TERRAVIEW_MODEL=gpt-4o
```

**With Ollama (local, no API key):**
```bash
ollama pull llama3
export TERRAVIEW_PROVIDER=ollama
poetry install --extras openai  # uses OpenAI-compatible client
```

---

## Usage

```bash
# Scan HCL source (graph traversal + LLM)
terraview scan ./terraform

# Scan a resolved plan (recommended for CI)
terraview scan --plan plan.json

# With Checkov findings as additional context
terraview scan --plan plan.json --checkov-output checkov.json

# Skip LLM — graph and static checks only (fast, no API cost)
terraview scan ./terraform --no-llm

# SARIF output for GitHub PR annotations
terraview scan --plan plan.json --format sarif --output results.sarif

# JSON output for downstream tooling
terraview scan ./terraform --format json --output findings.json

# Custom provider and model
terraview scan ./terraform --provider anthropic --model claude-opus-4-6
```

Exit code is 1 if any CRITICAL findings are found — suitable for CI/CD gates.

---

## Installing Checkov

Checkov has Python dependency conflicts with terraview. Install it in an isolated environment:

```bash
# Option 1: pipx (recommended)
pipx install checkov

# Option 2: Homebrew
brew install checkov

# Option 3: Docker (no install needed)
docker run --rm -v $(pwd):/tf bridgecrew/checkov \
    -d /tf -o json 2>/dev/null > checkov.json
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your keys, or set environment variables directly:

```bash
ANTHROPIC_API_KEY=sk-ant-...       # Anthropic API key
OPENAI_API_KEY=sk-...              # OpenAI API key
TERRAVIEW_PROVIDER=anthropic       # anthropic | openai | ollama
TERRAVIEW_MODEL=claude-sonnet-4-6  # model name
TERRAVIEW_MAX_TOKENS=8192          # max tokens per LLM call
TERRAVIEW_BASE_URL=                # custom OpenAI-compatible base URL
```

---

## Supported providers

| Provider | Models |
|----------|--------|
| Anthropic | claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5-20251001 |
| OpenAI | gpt-4o, gpt-4o-mini |
| Ollama | any locally installed model |
| Any OpenAI-compatible endpoint | set `TERRAVIEW_BASE_URL` |

---

## Differences from existing tools

| | Checkov / tfsec / Trivy | Wiz | terraview |
|---|---|---|---|
| Cross-resource attack chains | No | Yes (runtime) | Yes (static) |
| LLM reasoning | No | No | Yes |
| Works on Terraform plan | Partial | N/A | Yes |
| Requires cloud credentials | No | Yes | No |
| Requires live environment | No | Yes | No |
| Cost | Free | $500k+/yr | API tokens only |
| CI/CD gate | Yes | No | Yes |

---

## Limitations

terraview is currently scoped to single-account AWS Terraform. See [ROADMAP.md](ROADMAP.md) for planned improvements.

- Local module references are followed. External registry modules are flagged but not analyzed.
- Terragrunt is not supported.
- Multi-cloud (GCP, Azure) resource types are not recognized by the graph builder.
- Remote state (`terraform_remote_state`) data sources are not followed across accounts.

---

## Contributing

Contributions are welcome. The most impactful areas are:

- New graph traversal checks in [src/terraview/analyzers/traversal.py](src/terraview/analyzers/traversal.py)
- New built-in static checks in [src/terraview/analyzers/static.py](src/terraview/analyzers/static.py)
- Additional Terraform examples in [examples/vulnerable/](examples/vulnerable/)
- Multi-cloud resource type support in [src/terraview/graph/builder.py](src/terraview/graph/builder.py)

Please open an issue before starting significant work.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
