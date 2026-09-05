from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import NEEDLER_BANNER
from .fuzzer import ФАЗЗЫ_СТРОК, ФАЗЗЫ_ТИПОВ, fuzz_server

console = Console()


def _banner() -> None:
    console.print(f"[bold magenta]{NEEDLER_BANNER}[/bold magenta]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD MCP tool fuzzer — устойчивость MCP-сервера к битому вводу."""


@main.command("payloads")
def payloads_cmd() -> None:
    console.print("[bold]строковые фаззы[/bold]")
    for p in ФАЗЗЫ_СТРОК:
        console.print("  " + json.dumps(p, ensure_ascii=False)[:70])
    console.print("[bold]подмена типа[/bold]")
    for p in ФАЗЗЫ_ТИПОВ:
        console.print("  " + json.dumps(p, ensure_ascii=False)[:70])


@main.command("fuzz")
@click.argument("url")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находки (контракт пайплайна)")
def fuzz_cmd(url: str, as_json: str | None) -> None:
    """Обнаружить MCP-сервер и профаззить все его инструменты по схеме."""
    d = asyncio.run(fuzz_server(url))
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")

    # 🔴 rc=2 «не состоялась» ≠ rc=0 «чисто»: MCP не найден — не «сервер безопасен».
    if d["verdict"] == "НЕ ПРОВЕРЕНО":
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {d.get('not_proven', '')}")
        raise SystemExit(2)

    if d["findings"]:
        table = Table(title=f"Needler: {url}  ·  инструментов профаззено: {d['tools_fuzzed']}")
        table.add_column("инструмент"); table.add_column("аргумент")
        table.add_column("класс"); table.add_column("почему")
        for f in d["findings"][:40]:
            table.add_row(f["tool"], f["arg"], f["класс"], f["почему"])
        console.print(table)
    цвет = "red" if d["verdict"] == "ПРОВАЛ" else "green"
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")

    if d["verdict"] == "ПРОВАЛ":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
