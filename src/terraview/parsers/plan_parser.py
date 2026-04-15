# Planned: Terraform plan JSON parser.
# Parses output of: terraform plan -out tfplan && terraform show -json tfplan
# Plan JSON has fully resolved variable values and module calls, making it
# richer input than raw HCL for graph analysis.
