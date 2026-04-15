# Roadmap

Current state: single-account AWS Terraform, local module references, flat directory structure.

## Near term

**Multi-module support**
Follow local module calls across directory boundaries and build a unified graph. Most real Terraform repos use modules extensively and the current parser misses cross-module resource relationships.

**Checkov severity mapping**
Replace LLM enrichment for known check IDs with a maintained static map. LLM enrichment is a good fallback but adds latency and cost for checks we could classify deterministically.

**SARIF output**
GitHub and GitLab natively render SARIF as inline PR annotations. This makes terraview findings appear directly on the lines of code that caused them.

**Pre-commit hook**
A `.pre-commit-config.yaml` entry so engineers get feedback before they even open a PR.

## Medium term

**Terragrunt support**
Parse `terragrunt.hcl` files and resolve the account/environment structure they define. Most mature AWS shops use Terragrunt and the tool is currently invisible to their workflow.

**Remote state following**
Follow `terraform_remote_state` data source references across account boundaries. This is where the most interesting cross-account attack chains live.

**Finding deduplication**
When Checkov and the LLM both flag the same issue, merge them into one finding rather than reporting duplicates.

**Result caching**
Cache LLM responses keyed on a hash of the resource graph. Same Terraform, same findings, no redundant API calls.

## Longer term

**Multi-cloud resource graph**
Extend the graph builder to recognize GCP and Azure resource types. Cross-cloud attack paths (AWS EC2 assuming a GCP service account via Workload Identity Federation) are increasingly common and completely invisible to AWS-only tools.

**IDE integration**
A VS Code extension that runs graph traversal on save and surfaces findings inline. Static checks only, no LLM call, sub-second feedback.

**CI/CD native integrations**
GitHub App and GitLab integration that posts findings as PR comments with suggested fixes.

**Benchmark dataset**
A curated set of vulnerable Terraform configurations with known findings, for evaluating scanner coverage and LLM reasoning quality across releases.
