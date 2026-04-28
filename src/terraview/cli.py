import click
from terraview import config
from terraview.graph.builder import build_graph, build_graph_from_plan
from terraview.analyzers.traversal import run_graph_checks
from terraview.analyzers.static import run_static_checks
from terraview.findings.models import Finding
from terraview.findings.aggregator import deduplicate


@click.group()
def cli():
    """terraview: LLM-powered Terraform security reviewer.

    Combines graph-based attack chain detection with LLM architectural
    reasoning. Optionally ingests output from Checkov for static analysis.

    Quickstart (HCL source):

        terraview scan ./terraform

    From a Terraform plan (recommended for CI):

        terraform plan -out=tfplan
        terraform show -json tfplan > plan.json
        checkov -f plan.json --framework terraform_plan -o json > checkov.json
        terraview scan --plan plan.json --checkov-output checkov.json

    Skip LLM entirely:

        terraview scan ./terraform --no-llm
    """
    pass


@cli.command()
@click.argument("path", default=".")
@click.option("--plan", default=None,
              help="Path to terraform show -json plan file (recommended for CI)")
@click.option("--provider", default=None,
              help="LLM provider: anthropic, openai, ollama")
@click.option("--model", default=None,
              help="Model name (e.g. claude-sonnet-4-6, gpt-4o)")
@click.option("--output", default="report.md",
              help="Output file path (default: report.md)")
@click.option("--no-llm", is_flag=True, default=False,
              help="Skip LLM analysis")
@click.option("--no-graph", is_flag=True, default=False,
              help="Skip graph traversal findings")
@click.option("--no-static", is_flag=True, default=False,
              help="Skip built-in static checks")
@click.option("--no-checkov", is_flag=True, default=False,
              help="Skip Checkov ingestion even when --checkov-output is provided")
@click.option("--format", "fmt", default="markdown",
              type=click.Choice(["markdown", "json", "sarif"]),
              help="Output format (default: markdown)")
@click.option("--checkov-output", default=None,
              help="Path to Checkov JSON output file")
def scan(path, plan, provider, model, output, no_llm, no_graph, no_static,
         no_checkov, fmt, checkov_output):
    """Scan a Terraform directory or plan for security issues.

    PATH is the directory containing .tf files (default: current directory).
    Use --plan to analyse a resolved terraform plan JSON instead.
    """
    provider_name = provider or config.TERRAVIEW_PROVIDER
    model_name = model or config.DEFAULT_MODEL

    click.echo(f"terraview | provider: {provider_name} | model: {model_name}")

    # Build resource graph
    if plan:
        click.echo(f"Scanning plan: {plan}")
        click.echo("")
        click.echo("  Parsing Terraform plan JSON...")
        try:
            g = build_graph_from_plan(plan)
        except (FileNotFoundError, KeyError, ValueError) as e:
            click.echo(f"  Error parsing plan: {e}", err=True)
            raise SystemExit(1)
    else:
        click.echo(f"Scanning: {path}")
        click.echo("")
        click.echo("  Parsing Terraform files...")
        try:
            g = build_graph(path)
        except FileNotFoundError as e:
            click.echo(f"  Error: {e}", err=True)
            raise SystemExit(1)

    click.echo(f"  Found {g.number_of_nodes()} resources, {g.number_of_edges()} relationships")

    # Checkov ingestion
    checkov_findings: list[Finding] = []
    if checkov_output and not no_checkov:
        click.echo(f"\n  Ingesting Checkov output from {checkov_output}...")
        try:
            from terraview.parsers.checkov_parser import parse_checkov_output
            checkov_findings = parse_checkov_output(
                checkov_output,
                enrich=not no_llm,
                provider_name=provider_name,
                model=model_name,
            )
            click.echo(f"  {len(checkov_findings)} findings from Checkov")
        except Exception as e:
            click.echo(f"  Failed to parse Checkov output: {e}", err=True)
    elif checkov_output and no_checkov:
        click.echo("\n  Skipping Checkov ingestion because --no-checkov was set.")
    else:
        click.echo("\n  No static scanner output provided.")
        click.echo("  Tip: run checkov on your plan/directory and pass --checkov-output for richer results.")

    # Built-in static checks
    static_findings: list[Finding] = []
    if not no_static:
        click.echo("\n  Running built-in static checks...")
        static_findings = run_static_checks(g)
        click.echo(f"  {len(static_findings)} static findings")
    else:
        click.echo("\n  Skipping built-in static checks because --no-static was set.")

    # Graph traversal — cross-resource attack chains
    graph_findings: list[Finding] = []
    if not no_graph:
        click.echo("\n  Running graph traversal...")
        graph_findings = run_graph_checks(g)
        click.echo(f"  {len(graph_findings)} chain findings")
    else:
        click.echo("\n  Skipping graph traversal because --no-graph was set.")

    # LLM architectural reasoning
    llm_findings: list[Finding] = []
    if not no_llm:
        click.echo("\n  Running LLM analysis...")
        try:
            from terraview.analyzers.llm import run_llm_checks
            llm_findings = run_llm_checks(
                g,
                checkov_findings + static_findings + graph_findings,
                provider_name,
                model_name,
            )
        except ImportError:
            click.echo(
                "  LLM provider not installed. Run: pip install terraview[anthropic]",
                err=True,
            )
    else:
        click.echo("\n  Skipping LLM analysis because --no-llm was set.")

    # Deduplicate across sources
    all_findings = deduplicate(checkov_findings + static_findings + graph_findings + llm_findings)

    # Summary
    click.echo(f"\n  Total findings: {len(all_findings)}")
    severity_counts: dict[str, int] = {}
    for f in all_findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            click.echo(f"    {sev}: {count}")

    # Write report
    scan_path = plan or path
    if fmt == "markdown":
        from terraview.output.markdown import generate_report
        report = generate_report(all_findings, scan_path, provider_name, model_name)
        with open(output, "w") as f:
            f.write(report)
        click.echo(f"\n  Report written to {output}")
    elif fmt == "json":
        import json
        data = [f.to_dict() for f in all_findings]
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        click.echo(f"\n  JSON report written to {output}")
    elif fmt == "sarif":
        from terraview.output.sarif import generate_sarif
        sarif_out = output if output.endswith(".sarif") else output.replace(".md", ".sarif")
        with open(sarif_out, "w") as f:
            f.write(generate_sarif(all_findings, scan_path))
        click.echo(f"\n  SARIF report written to {sarif_out}")

    # Non-zero exit on critical findings for CI/CD gates
    if severity_counts.get("CRITICAL", 0) > 0:
        raise SystemExit(1)
