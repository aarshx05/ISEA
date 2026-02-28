"""
ISEA Command-Line Interface

Rich-based terminal UI for the Intelligent Storage Evidence Analyzer.

Commands:
  isea analyze <image>   Full scan with live progress + findings table
  isea report  <image>   Analyze + generate JSON/Markdown report files
  isea chat    <image>   Interactive AI forensic analyst session
  isea scan    <image>   Quick entropy-only scan (sampling mode)
"""

import os
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

console = Console()

# Classification → color mapping
CLASSIFICATION_COLORS = {
    "secure_erase":      "bold red",
    "intentional_wipe":  "orange1",
    "os_clear":          "yellow",
    "natural_residual":  "green",
}

RISK_COLORS = {
    "CRITICAL": "bold red",
    "PROBABLE": "orange1",
    "POSSIBLE": "yellow",
    "MINIMAL":  "green",
}


# ------------------------------------------------------------------ #
# CLI group
# ------------------------------------------------------------------ #

@click.group()
@click.version_option("1.0.0", prog_name="ISEA")
def cli():
    """ISEA — Intelligent Storage Evidence Analyzer\n\nAI-powered forensic disk wipe detection and attacker profiling."""
    pass


# ------------------------------------------------------------------ #
# isea analyze
# ------------------------------------------------------------------ #

@cli.command()
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--cluster-size", "-c", default=4096, show_default=True,
              help="Cluster size in bytes.")
@click.option("--step", "-s", default=1, show_default=True,
              help="Sampling step (1=every cluster, 4=every 4th). Higher=faster but less precise.")
def analyze(image_path: str, cluster_size: int, step: int):
    """Perform a full forensic scan of a disk image."""
    _run_analysis(image_path, cluster_size, step, generate_report=False)


# ------------------------------------------------------------------ #
# isea report
# ------------------------------------------------------------------ #

@cli.command()
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--cluster-size", "-c", default=4096, show_default=True)
@click.option("--step", "-s", default=1, show_default=True)
@click.option("--output-dir", "-o", default="./reports", show_default=True,
              help="Directory for report output files.")
def report(image_path: str, cluster_size: int, step: int, output_dir: str):
    """Analyze disk image and generate JSON + Markdown forensic reports."""
    result = _run_analysis(image_path, cluster_size, step, generate_report=False)
    if result is None:
        return

    from agent.report_generator import ReportGenerator
    os.makedirs(output_dir, exist_ok=True)
    generator = ReportGenerator(result)

    json_path = Path(output_dir) / "isea_report.json"
    md_path = Path(output_dir) / "isea_report.md"

    json_path.write_text(generator.to_json(), encoding="utf-8")
    md_path.write_text(generator.to_markdown(), encoding="utf-8")

    console.print()
    console.print(Panel(
        f"[bold green]Reports saved[/bold green]\n\n"
        f"  JSON → [cyan]{json_path.resolve()}[/cyan]\n"
        f"  Markdown → [cyan]{md_path.resolve()}[/cyan]\n\n"
        f"  Evidence Strength: [bold]{generator.evidence_strength_rating()}[/bold]",
        title="[bold]Report Generation Complete[/bold]",
        border_style="green",
    ))


# ------------------------------------------------------------------ #
# isea scan (quick mode)
# ------------------------------------------------------------------ #

@cli.command()
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--cluster-size", "-c", default=4096, show_default=True)
@click.option("--step", "-s", default=4, show_default=True,
              help="Default step=4 for fast scan (every 4th cluster).")
def scan(image_path: str, cluster_size: int, step: int):
    """Quick entropy scan (samples every Nth cluster). Faster but approximate."""
    console.print(f"\n[bold cyan]Quick Scan Mode[/bold cyan] — sampling every {step} clusters\n")
    _run_analysis(image_path, cluster_size, step, generate_report=False)


# ------------------------------------------------------------------ #
# isea chat
# ------------------------------------------------------------------ #

@cli.command()
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--cluster-size", "-c", default=4096, show_default=True)
@click.option("--step", "-s", default=1, show_default=True)
def chat(image_path: str, cluster_size: int, step: int):
    """Interactive AI forensic analyst session. Analyze first, then ask questions."""
    from config import config
    try:
        config.validate()
    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        sys.exit(1)

    console.print()
    console.print(Panel(
        "[bold cyan]ISEA Forensic AI Agent[/bold cyan]\n\n"
        "I will analyze your disk image and answer your forensic questions.\n"
        "Type [bold]exit[/bold] or [bold]quit[/bold] to end the session.\n"
        "Type [bold]report[/bold] to generate full evidence reports.",
        title="[bold]Interactive Forensic Session[/bold]",
        border_style="cyan",
    ))

    # Run scan first
    result = _run_analysis(image_path, cluster_size, step, generate_report=False)
    if result is None:
        return

    # Initialize agent
    from agent.forensic_agent import ForensicAgent
    from core.cluster_scanner import ClusterScanner
    from groq import Groq

    scanner = ClusterScanner(image_path, cluster_size)
    groq_client = Groq(api_key=config.groq_api_key)
    agent = ForensicAgent(result, scanner, groq_client)

    console.print()
    console.print("[bold green]Analysis complete. You may now ask questions.[/bold green]\n")

    # Suggested starter questions
    suggestions = [
        "Was this wipe intentional?",
        "Which tool was most likely used?",
        "Was this a full disk wipe or selective?",
        "Which directory shows the highest destruction likelihood?",
        "Generate a complete forensic report.",
    ]
    console.print("[dim]Suggested questions:[/dim]")
    for q in suggestions:
        console.print(f"  [dim]• {q}[/dim]")
    console.print()

    # Conversation loop
    while True:
        try:
            user_input = Prompt.ask("[bold cyan]You[/bold cyan]")
        except (KeyboardInterrupt, EOFError):
            break

        if user_input.strip().lower() in ("exit", "quit", "q"):
            console.print("[dim]Session ended.[/dim]")
            break

        if user_input.strip().lower() == "report":
            user_input = "Generate a complete forensic report and save it."

        if not user_input.strip():
            continue

        console.print()
        with console.status("[bold cyan]Analyzing evidence...[/bold cyan]", spinner="dots"):
            try:
                response = agent.chat(user_input)
            except Exception as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                continue

        console.print(Panel(
            Markdown(response),
            title="[bold cyan]ISEA Analyst[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))
        console.print()


# ------------------------------------------------------------------ #
# Core analysis runner (shared by all commands)
# ------------------------------------------------------------------ #

def _run_analysis(image_path: str, cluster_size: int, step: int, generate_report: bool):
    """Run the full scan pipeline with Rich progress display."""
    from core.cluster_scanner import ClusterScanner

    image_name = Path(image_path).name
    image_size_mb = Path(image_path).stat().st_size / (1024 * 1024)

    console.print()
    console.print(Panel(
        f"[bold]Image:[/bold] {image_name}  |  "
        f"[bold]Size:[/bold] {image_size_mb:.1f} MB  |  "
        f"[bold]Cluster:[/bold] {cluster_size} B  |  "
        f"[bold]Step:[/bold] {step}",
        title="[bold cyan]ISEA — Disk Analysis Starting[/bold cyan]",
        border_style="cyan",
    ))
    console.print()

    total_clusters = Path(image_path).stat().st_size // cluster_size
    scanned = [0]

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )

    task_id = progress.add_task(
        "[cyan]Scanning clusters...", total=max(total_clusters // step, 1)
    )

    def on_progress(current, total):
        scanned[0] = current
        progress.update(task_id, completed=current // step)

    scanner = ClusterScanner(image_path, cluster_size, progress_callback=on_progress)

    with progress:
        try:
            result = scanner.run_full_scan(step=step)
        except Exception as exc:
            console.print(f"[bold red]Scan failed:[/bold red] {exc}")
            return None

    if result.error:
        console.print(f"[bold red]Scan Error:[/bold red] {result.error}")
        return None

    progress.stop()
    _display_results(result, scanner)
    return result


def _display_results(result, scanner):
    """Render the scan findings with Rich tables and panels."""
    summary = scanner.get_summary(result)
    intent = result.intent_assessment
    risk = intent.get("risk_level", "MINIMAL")
    risk_color = RISK_COLORS.get(risk, "white")

    # --- Overview Panel ---
    overview = (
        f"[bold]Evidence Score:[/bold] [bold {risk_color}]{result.evidence_score}/100[/bold {risk_color}]  "
        f"[bold]Risk Level:[/bold] [{risk_color}]{risk}[/{risk_color}]  "
        f"[bold]Wipe Regions:[/bold] {len(result.wipe_detections)}  "
        f"[bold]Scan Time:[/bold] {result.scan_duration_seconds:.1f}s"
    )
    console.print(Panel(overview, title="[bold]Overview[/bold]", border_style=risk_color))
    console.print()

    # --- Classification Breakdown ---
    by_class = result.region_stats.get("by_classification", {})
    if by_class:
        table = Table(title="Cluster Classification", box=box.ROUNDED, show_lines=False)
        table.add_column("Classification", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Fraction", justify="right")
        table.add_column("Visual")

        total = result.analyzed_clusters or 1
        for cls, count in sorted(by_class.items(), key=lambda x: -x[1]):
            pct = count / total
            color = CLASSIFICATION_COLORS.get(cls, "white")
            bar = "█" * max(1, int(pct * 30))
            table.add_row(
                Text(cls, style=color),
                f"{count:,}",
                f"{pct:.1%}",
                Text(bar, style=color),
            )
        console.print(table)
        console.print()

    # --- Wipe Detections ---
    if result.wipe_detections:
        det_table = Table(title="Wipe Region Detections", box=box.ROUNDED, show_lines=False)
        det_table.add_column("#", justify="right", width=4)
        det_table.add_column("Clusters", width=18)
        det_table.add_column("Tool Match")
        det_table.add_column("Algorithm")
        det_table.add_column("Passes", justify="center", width=7)
        det_table.add_column("Confidence", justify="right")
        det_table.add_column("Entropy", justify="right")

        for i, w in enumerate(result.wipe_detections[:20], 1):
            color = CLASSIFICATION_COLORS.get(w.classification, "white")
            conf_color = "green" if w.confidence > 0.7 else "yellow" if w.confidence > 0.4 else "red"
            det_table.add_row(
                str(i),
                Text(f"{w.start_cluster}–{w.end_cluster} ({w.cluster_count})", style="dim"),
                Text(w.tool_match, style=color),
                w.algorithm or "—",
                str(w.pass_count),
                Text(f"{w.confidence:.0%}", style=conf_color),
                f"{w.mean_entropy:.2f}",
            )

        if len(result.wipe_detections) > 20:
            det_table.add_row(
                "...", f"+{len(result.wipe_detections) - 20} more", "", "", "", "", ""
            )

        console.print(det_table)
        console.print()

    # --- Signature Match ---
    if result.signature_matches:
        sig = result.signature_matches[0]
        sig_text = (
            f"[bold]Tool:[/bold] {sig.get('tool', 'Unknown')}  "
            f"[bold]Algorithm:[/bold] {sig.get('algorithm', '?')}  "
            f"[bold]Passes:[/bold] {sig.get('pass_count', 0)}  "
            f"[bold]Confidence:[/bold] {sig.get('confidence', 0):.0%}"
        )
        if sig.get("runner_up"):
            sig_text += f"  [dim](Runner-up: {sig['runner_up']})[/dim]"
        console.print(Panel(sig_text, title="[bold]Wipe Tool Classification[/bold]", border_style="yellow"))
        console.print()

    # --- Intent Assessment ---
    hypothesis = intent.get("hypothesis", "N/A")
    intent_score = intent.get("score", 0)
    confidence_tier = intent.get("confidence", "LOW")
    intent_text = (
        f"[bold]Intent Score:[/bold] {intent_score:.0f}/100  "
        f"[bold]Confidence:[/bold] {confidence_tier}  "
        f"[bold]Scope:[/bold] {intent.get('wipe_scope', 'unknown')}\n\n"
        f"[bold]Hypothesis:[/bold] {hypothesis}"
    )
    console.print(Panel(
        intent_text,
        title=f"[bold {risk_color}]Behavioral Intent Assessment[/bold {risk_color}]",
        border_style=risk_color,
    ))
    console.print()

    # --- Evidence Points ---
    evidence_pts = intent.get("evidence_points", [])
    if evidence_pts:
        console.print("[bold]Evidence Points:[/bold]")
        for pt in evidence_pts:
            console.print(f"  [dim]•[/dim] {pt}")
        console.print()


if __name__ == "__main__":
    cli()
