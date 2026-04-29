from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.json import JSON
from rich.table import Table

from kcrash.utils.config import load_config
from kcrash.utils.token_counter import get_token_counter
from kcrash.core.pipeline import AnalysisPipeline
from kcrash.core.cache import AnalysisCache
from kcrash.core.ingestion import CrashIngestion
from kcrash.llm.client import LLMClient

console = Console()


def _create_llm_client(config_path: str | None = None) -> LLMClient:
    config = load_config(config_path)

    if not config.llm.api_key:
        console.print("[red]Error: OPENAI_API_KEY not set[/red]")
        sys.exit(1)

    return LLMClient(
        api_key=config.llm.api_key,
        model=config.llm.model,
    )


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    pass


@cli.command()
@click.option("--vmcore", required=True, help="Path to vmcore dump or mock JSON")
@click.option("--vmlinux", required=True, help="Path to vmlinux with debug symbols")
@click.option("--enable-patch", is_flag=True, default=False, help="Enable patch generation")
@click.option("--patch-type", type=click.Choice(["ebpf", "kpatch"]), default="ebpf")
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--hostname", default="unknown", help="Hostname for change correlation")
@click.option("--hours", default=72, help="Look-back window for changes in hours")
@click.option("--debate-rounds", default=2, help="Number of debate rounds")
@click.option("--min-confidence", default=0.6, help="Minimum confidence threshold")
@click.option("--output", "output_path", default=None, help="Write JSON result to file")
@click.option("--no-cache", is_flag=True, help="Disable analysis cache")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
def analyze(
    vmcore: str,
    vmlinux: str,
    enable_patch: bool,
    patch_type: str,
    config_path: str | None,
    hostname: str,
    hours: int,
    debate_rounds: int,
    min_confidence: float,
    output_path: str | None,
    no_cache: bool,
    verbose: bool,
) -> None:
    console.print("[bold cyan]kcrash-agent: Kernel Crash Analysis[/bold cyan]")
    console.print(f"  vmcore:    {vmcore}")
    console.print(f"  vmlinux:   {vmlinux}")
    console.print(f"  hostname:  {hostname}")
    console.print(f"  patch:     {patch_type if enable_patch else 'disabled'}")
    console.print()

    llm_client = _create_llm_client(config_path)
    cache = None if no_cache else AnalysisCache()

    pipeline = AnalysisPipeline(
        llm_client=llm_client,
        cache=cache,
        enable_patch=enable_patch,
        patch_type=patch_type,
        debate_rounds=debate_rounds,
        min_confidence=min_confidence,
        hostname=hostname,
        hours=hours,
    )

    with console.status("[bold green]Running analysis pipeline..."):
        report = pipeline.run(vmcore, vmlinux)

    console.print("\n" + report.summary())

    if verbose:
        console.print("\n[bold]Pipeline Stages:[/bold]")
        table = Table(show_header=True)
        table.add_column("Stage", style="cyan")
        table.add_column("Status")
        table.add_column("Duration")
        for stage in report.pipeline_stages:
            status_color = "green" if stage["status"] == "completed" else "red"
            table.add_row(
                stage["name"],
                f"[{status_color}]{stage['status']}[/{status_color}]",
                f"{stage['duration_ms']:.0f}ms",
            )
        console.print(table)

    if report.patch_code:
        console.print(f"\n[bold]Generated {report.patch_type} patch:[/bold]")
        console.print(report.patch_code)

    console.print(f"\n[bold]Token Usage:[/bold] {json.dumps(report.token_usage)}")

    result_dict = report.to_dict()
    console.print("\n[bold green]=== Full Report ===[/bold green]")
    console.print(JSON.from_data(result_dict))

    if output_path:
        with open(output_path, "w") as f:
            f.write(report.to_json())
        console.print(f"\nReport written to: {output_path}")


@cli.command()
@click.option("--watch-dir", required=True, help="Directory to watch for new vmcore files")
@click.option("--vmlinux-dir", default="/usr/lib/debug/lib/modules")
@click.option("--config", "config_path", default=None)
@click.option("--enable-patch", is_flag=True, default=False)
@click.option("--hostname", default="unknown")
@click.option("--output-dir", default="./results")
def ingest(
    watch_dir: str,
    vmlinux_dir: str,
    config_path: str | None,
    enable_patch: bool,
    hostname: str,
    output_dir: str,
) -> None:
    console.print(f"[bold cyan]Watching {watch_dir} for crash dumps...[/bold cyan]")
    console.print("Press Ctrl+C to stop.\n")

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    ingestion = CrashIngestion(watch_dir=watch_dir, vmlinux_dir=vmlinux_dir)

    for event in ingestion.watch():
        console.print(f"\n[bold yellow]New crash detected:[/bold yellow] {event.crash_id}")
        console.print(f"  vmcore: {event.vmcore_path}")

        try:
            llm_client = _create_llm_client(config_path)
            pipeline = AnalysisPipeline(
                llm_client=llm_client,
                enable_patch=enable_patch,
                hostname=hostname,
            )
            report = pipeline.run(event.vmcore_path, event.vmlinux_path)

            output_file = Path(output_dir) / f"{event.crash_id}.json"
            with open(output_file, "w") as f:
                f.write(report.to_json())

            console.print(report.summary())
            console.print(f"  Report saved to: {output_file}")

        except Exception as exc:
            console.print(f"[red]Analysis failed: {exc}[/red]")


@cli.command()
@click.option("--config", "config_path", default=None)
def stats(config_path: str | None) -> None:
    cache = AnalysisCache()
    console.print("[bold cyan]Cache Statistics:[/bold cyan]")
    console.print(f"  Entries: {cache.stats['entries']}")
    console.print(f"  Total hits: {cache.stats['total_hits']}")
    console.print(f"  TTL: {cache.stats['ttl_seconds']}s")


@cli.command()
def clear_cache() -> None:
    cache = AnalysisCache()
    cache.clear()
    console.print("[green]Cache cleared.[/green]")


if __name__ == "__main__":
    cli()
