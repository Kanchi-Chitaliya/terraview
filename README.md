# terraview

LLM-powered Terraform security reviewer.

Most IaC scanners flag individual misconfigurations in isolation. terraview goes further: it builds a resource graph from your Terraform code, finds cross-resource attack chains, and uses an LLM to reason about architectural risk -- things no static rule can catch.

**Example finding static scanners miss:**

> `aws_instance.web` is internet-exposed with a public IP and open SSH. It is attached to `aws_iam_instance_profile.ec2_profile`, which grants `aws_iam_role.ec2_role` -- a role with wildcard admin permissions. An attacker with SSH access can query the instance metadata service to retrieve temporary credentials and pivot to any resource in the AWS account.

That finding connects five resources into a single attack narrative. Checkov gives you five separate alerts with no context.

---

## How it works

terraview runs three analysis layers in sequence:

**1. Static analysis (optional):** Ingest findings from Checkov. terraview enriches missing severity and remediation fields via LLM so you get full context even on the free tier.

**2. Graph traversal:** Parses your Terraform into a directed resource graph and walks it to find cross-resource attack chains -- IAM privilege escalation paths, public exposure chains, and blast radius analysis.

**3. LLM reasoning:** Sends the resource graph and existing findings to an LLM to identify architectural gaps, missing controls, and risks that span multiple resources.

Every finding includes a MITRE ATT&CK technique, blast radius, and a Terraform remediation snippet.

---

## Quickstart
```bash
pip install terraview[anthropic]
export ANTHROPIC_API_KEY=sk-ant-...

terraview scan ./terraform
```

Output is a Markdown report written to `report.md` by default.

---

## Installation

**Base install (graph traversal only, no LLM):**
```bash
pip install terraview
```

**With Anthropic:**
```bash
pip install terraview[anthropic]
export ANTHROPIC_API_KEY=sk-ant-...
```

**With OpenAI:**
```bash
pip install terraview[openai]
export OPENAI_API_KEY=sk-...
export SENTINEL_PROVIDER=openai
export SENTINEL_MODEL=gpt-4o
```

**With Ollama (local, no API key):**
```bash
ollama pull llama3
export SENTINEL_PROVIDER=ollama
pip install terraview[openai]  # uses OpenAI-compatible client
```

---

## Usage
```bash
# Graph traversal + LLM only
terraview scan ./terraform

# With Checkov static analysis
checkov -d ./terraform -o json 2>/dev/null > checkov.json
terraview scan ./terraform --checkov-output checkov.json

# Skip LLM, graph traversal only (fast, no API cost)
terraview scan ./terraform --no-llm

# JSON output for CI/CD integration
terraview scan ./terraform --format json --output findings.json

# Custom model
terraview scan ./terraform --provider anthropic --model claude-opus-4-6

# Custom output file
terraview scan ./terraform --output security-report.md
```

Exit code is 1 if any CRITICAL findings are found -- useful for CI/CD gates.

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

All options can be set via environment variables or a `.env` file:
```bash
ANTHROPIC_API_KEY=sk-ant-...      # Anthropic API key
OPENAI_API_KEY=sk-...             # OpenAI API key
SENTINEL_PROVIDER=anthropic       # anthropic | openai | ollama
SENTINEL_MODEL=claude-sonnet-4-6  # any supported model
SENTINEL_MAX_TOKENS=8192          # max tokens per LLM call
SENTINEL_LOG_LEVEL=INFO           # INFO | DEBUG
```

---

## Supported providers

| Provider | Models |
|----------|--------|
| Anthropic | claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5-20251001 |
| OpenAI | gpt-4o, gpt-4o-mini |
| Ollama | any locally installed model |
| Any OpenAI-compatible endpoint | set SENTINEL_BASE_URL |

---

## Differences from existing tools

| | Checkov / tfsec / Trivy | Wiz | terraview |
|---|---|---|---|
| Cross-resource attack chains | No | Yes (runtime) | Yes (static) |
| LLM reasoning | No | No | Yes |
| Requires cloud credentials | No | Yes | No |
| Requires live environment | No | Yes | No |
| Cost | Free | $500k+/yr | API tokens only |
| Pre-commit / pre-plan | Yes | No | Yes |

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

- New graph traversal checks in `src/terraview/analyzers/traversal.py`
- Additional Terraform examples in `examples/vulnerable/`
- Multi-cloud resource type support in `src/terraview/graph/builder.py`

Please open an issue before starting significant work.

---

## License

Apache 2.0
