import click
from terraview import config
from terraview.graph.builder import build_graph
from terraview.analyzers.traversal import run_graph_checks
from terraview.findings.models import Finding


@click.group()
def cli():
    """terraview: LLM-powered Terraform security reviewer.

    Combines graph-based attack chain detection with LLM architectural
    reasoning. Optionally ingests output from Checkov for static analysis.

    Quickstart:

        terraview scan ./terraform

    With Checkov static analysis:

        checkov -d ./terraform -o json 2>/dev/null > checkov.json
        terraview scan ./terraform --checkov-output checkov.json

    Skip LLM entirely:

        terraview scan ./terraform --no-llm
    """
    pass


@cli.command()
@click.argument("path", default=".")
@click.option("--provider", default=None,
              help="LLM provider: anthropic, openai, ollama")
@click.option("--model", default=None,
              help="Model name (e.g. claude-sonnet-4-6, gpt-4o)")
@click.option("--output", default="report.md",
              help="Output file path (default: report.md)")
@click.option("--no-llm", is_flag=True, default=False,
              help="Skip all LLM calls including Checkov enrichment")
@click.option("--format", "fmt", default="markdown",
              type=click.Choice(["markdown", "json"]),
              help="Output format (default: markdown)")
@click.option("--checkov-output", default=None,
              help="Path to Checkov JSON output file")
def scan(path, provider, model, output, no_llm, fmt, checkov_output):
    """Scan a Terraform directory for security issues.

    PATH is the directory containing .tf files (default: current directory).
    """
    provider_name = provider or config.TERRAVIEW_PROVIDER
    model_name = model or config.DEFAULT_MODEL

    click.echo(f"terraview | provider: {provider_name} | model: {model_name}")
    click.echo(f"Scanning: {path}")
    click.echo("")

    # Parse Terraform into resource graph
    click.echo("  Parsing Terraform files...")
    try:
        g = build_graph(path)
    except FileNotFoundError as e:
        click.echo(f"  Error: {e}", err=True)
        raise SystemExit(1)
    click.echo(f"  Found {g.number_of_nodes()} resources, {g.number_of_edges()} relationships")

    # Ingest Checkov findings if provided
    static: list[Finding] = []
    if checkov_output:
        click.echo(f"\n  Ingesting Checkov output from {checkov_output}...")
        try:
            from terraview.parsers.checkov_parser import parse_checkov_output
            static = parse_checkov_output(
                checkov_output,
                enrich=not no_llm,
                provider_name=provider_name,
                model=model_name,
            )
            click.echo(f"  {len(static)} findings from Checkov")
        except Exception as e:
            click.echo(f"  Failed to parse Checkov output: {e}", err=True)
    else:
        click.echo("\n  No static scanner output provided.")
        click.echo("  Tip: run checkov -d ./terraform -o json 2>/dev/null > checkov.json")
        click.echo("  then pass --checkov-output checkov.json for richer results.")

    # Graph traversal - cross-resource attack chains
    click.echo("\n  Running graph traversal...")
    graph_findings = run_graph_checks(g)
    click.echo(f"  {len(graph_findings)} chain findings")

    # LLM architectural reasoning
    llm_findings: list[Finding] = []
    if not no_llm:
        click.echo("\n  Running LLM analysis...")
        try:
            from terraview.analyzers.llm import run_llm_checks
            llm_findings = run_llm_checks(
                g, static + graph_findings, provider_name, model_name
            )
        except ImportError:
            click.echo(
                "  LLM provider not installed. Run: pip install terraview[anthropic]",
                err=True,
            )

    all_findings = static + graph_findings + llm_findings

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
    if fmt == "markdown":
        from terraview.output.markdown import generate_report
        report = generate_report(all_findings, path, provider_name, model_name)
        with open(output, "w") as f:
            f.write(report)
        click.echo(f"\n  Report written to {output}")
    elif fmt == "json":
        import json
        data = [f.to_dict() for f in all_findings]
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        click.echo(f"\n  JSON report written to {output}")

    # Non-zero exit on critical findings for CI/CD gates
    if severity_counts.get("CRITICAL", 0) > 0:
        raise SystemExit(1)
