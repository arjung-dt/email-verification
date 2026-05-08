"""CLI for email_verifier."""
from __future__ import annotations

import json
import logging
import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .providers import PROVIDERS
from .verifier import Verdict, verify


_STYLE = {
    "yes": "bold green",
    "likely": "bold yellow",
    "likely_no": "bold yellow",
    "no": "bold red",
}


def _collect_api_keys() -> dict[str, str]:
    """Pull every configured provider key from env vars."""
    keys: dict[str, str] = {}
    for provider_id, _fn, env_var, _quota, _reset in PROVIDERS:
        val = os.environ.get(env_var)
        if val:
            keys[provider_id] = val
    return keys


def check_command(
    email: str = typer.Argument(..., help="The email address to verify"),
    json_only: bool = typer.Option(False, "--json", help="Emit raw JSON only"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """Verify a single email address.

    Pipeline: syntax -> MX lookup -> disposable check -> HTTPS provider chain
    (QEV -> MyEmailVerifier -> Abstract -> Mailboxlayer -> Hunter).

    Configure providers via env vars: QEV_API_KEY, MEV_API_KEY,
    ABSTRACT_API_KEY, MAILBOXLAYER_API_KEY, HUNTER_API_KEY. Any subset works;
    missing keys are skipped silently.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

    api_keys = _collect_api_keys()
    verdict = verify(email, api_keys=api_keys)

    if json_only:
        print(json.dumps(verdict.to_dict(), indent=2, default=str))
        return

    Console().print(_render(verdict))


def _render(v: Verdict) -> Panel:
    style = _STYLE.get(v.exists, "white")

    header = Text()
    header.append(f"  {v.email}\n", style="bold")
    header.append("  exists: ", style="bold")
    header.append(v.exists.upper(), style=style)
    header.append("\n")
    header.append(f"  {v.reason}", style="dim")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Signal")
    table.add_column("Value")

    table.add_row("domain", v.domain or "—")
    table.add_row("domain_has_mx", _yn(v.domain_has_mx))
    table.add_row("mx_records", "\n".join(v.mx_records) if v.mx_records else "—")
    table.add_row("is_disposable", _yn(v.is_disposable))

    if v.provider_readings:
        for r in v.provider_readings:
            label = r.result.upper()
            if r.error:
                label = f"ERROR ({r.error[:60]})"
            table.add_row(f"provider:{r.provider}", label)
            if r.catch_all is not None:
                table.add_row(f"  {r.provider}:catch_all", _yn(r.catch_all))
            if r.score is not None:
                table.add_row(f"  {r.provider}:score", f"{r.score}")
            if r.raw_status:
                table.add_row(f"  {r.provider}:raw_status", str(r.raw_status)[:80])
    else:
        table.add_row("providers", "[dim]none configured[/dim]")

    table.add_row("decided_by", v.decided_by)

    grid = Table.grid(padding=0)
    grid.add_row(header)
    grid.add_row(table)
    return Panel(grid, border_style=style, padding=(1, 2))


def _yn(b: bool) -> str:
    return "[green]yes[/green]" if b else "[red]no[/red]"


def main() -> None:
    typer.run(check_command)
