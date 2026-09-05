"""Фаззер MCP-инструментов — проверка устойчивости сервера к битому вводу.

Переписан Невис 11.08.2026 (аудит: АУДИТ_needler.md). Прежняя версия НЕ говорила на MCP:
слала голый POST `{tool, args}` вместо JSON-RPC `tools/call`, то есть на реальном MCP-сервере
не фаззила ничего. И детектор кричал «path-traversal», увидев `../` в ответе, — даже когда это
эхо посланного мной `../../../etc/passwd`.

Здесь: реальный MCP через `mcpx.probe` (discover → tools/list → tools/call), фаззинг каждого
инструмента по его схеме, и детект СЕРВЕРНОЙ внутренности (traceback/путь/SQL/500), а НЕ моего
эха. Вердикт ставит код, ноль обращений к LLM.

🔴 OPSEC: только синтетические/авторизованные цели — QA устойчивости MCP-сервера, не атака.
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from mcpx_app.probe import _extract_result, _mcp_call, discover_endpoint

# Фаззы по типам аргументов. Прицельно ломаем то, что инструмент по схеме ждёт.
ФАЗЗЫ_СТРОК = ["", "A" * 20000, "../../../etc/passwd", "'; DROP TABLE users;--",
              "<script>alert(1)</script>", "${jndi:ldap://x}", "\x00\x01\x02", "%n%n%n"]
ФАЗЗЫ_ЧИСЕЛ = [0, -1, 2**63, -(2**63), 1.5, float("inf") if False else 1e308]
ФАЗЗЫ_ТИПОВ = ["строка вместо числа", [], {}, True, None, {"nested": ["boom"]}]

# 🔴 Признаки СЕРВЕРНОЙ внутренности — то, чего в моём payload не было и что выдаёт сервер сам.
# Это и есть находка (в отличие от эха моего ввода). Каждый — с уровнем серьёзности.
УТЕЧКИ: list[tuple[str, str, str]] = [
    (r"Traceback \(most recent call last\)", "python-traceback", "стек-трейс Python в ответе"),
    (r'File "[/\\]', "server-path", "путь файловой системы сервера в ответе"),
    (r"\bat [\w.$]+\([\w.]+\.java:\d+\)", "java-stack", "Java stack trace"),
    (r"(SQL syntax|SQLSTATE|near \"|unterminated quoted)", "sql-error", "SQL-ошибка (возможна инъекция)"),
    (r"(ENOENT|EACCES|permission denied|no such file)", "os-error", "ошибка ОС в ответе"),
    (r"(panic:|goroutine \d+ \[)", "go-panic", "Go panic в ответе"),
]


def _типы_аргументов(schema: dict[str, Any]) -> dict[str, str]:
    props = (schema or {}).get("properties") or {}
    return {имя: (поле.get("type", "string") if isinstance(поле, dict) else "string")
            for имя, поле in props.items()} if isinstance(props, dict) else {}


def _фаззы_для(тип: str) -> list[Any]:
    if тип in ("integer", "number"):
        return ФАЗЗЫ_ЧИСЕЛ + ФАЗЗЫ_ТИПОВ
    if тип in ("array", "object", "boolean"):
        return ФАЗЗЫ_ТИПОВ
    return ФАЗЗЫ_СТРОК + ФАЗЗЫ_ТИПОВ


def _классифицировать(status: int, тело: str, payload: Any) -> tuple[str, str]:
    """→ (класс, объяснение). Ищем СЕРВЕРНУЮ внутренность, не эхо payload'а."""
    # эхо: если весь «подозрительный» ответ — это буквально мой payload, уязвимости нет
    for шаблон, класс, объяснение in УТЕЧКИ:
        m = re.search(шаблон, тело, re.I)
        if m:
            кусок = m.group(0)
            # признак утечки, которого не было в моём payload → это сервер, а не эхо
            if str(payload) is None or кусок.lower() not in str(payload).lower():
                return класс, объяснение
    if status >= 500:
        return "crash-5xx", f"сервер вернул {status} на битом вводе — не валидирует и падает"
    return "ok", ""


async def fuzz_tool(client: httpx.AsyncClient, endpoint, tool: dict[str, Any],
                    request_id: int = 100) -> list[dict[str, Any]]:
    """Профаззить один MCP-инструмент по его схеме через реальный tools/call."""
    имя = tool.get("name", "")
    схема = tool.get("inputSchema") or tool.get("input_schema") or {}
    типы = _типы_аргументов(схема)
    находки = []
    # если у инструмента нет аргументов по схеме — всё равно пробуем сломать одним полем
    поля = типы or {"input": "string"}
    for арг, тип in поля.items():
        for payload in _фаззы_для(тип):
            try:
                obj = await _mcp_call(client, endpoint, "tools/call",
                                      {"name": имя, "arguments": {арг: payload}},
                                      request_id=request_id)
                request_id += 1
            except httpx.HTTPError as e:
                находки.append({"tool": имя, "arg": арг, "payload": repr(payload)[:60],
                                "класс": "transport-error", "почему": str(e)[:100], "status": 0})
                continue
            status = obj.get("status_code", 200 if obj.get("ok") else 0)
            тело = obj.get("error") or ""
            if obj.get("ok"):
                res = _extract_result(obj)
                тело = str(res)
            класс, почему = _классифицировать(status, тело, payload)
            if класс != "ok":
                находки.append({"tool": имя, "arg": арг, "payload": repr(payload)[:60],
                                "класс": класс, "почему": почему, "status": status})
    return находки


async def fuzz_server(url: str) -> dict[str, Any]:
    """Обнаружить MCP-сервер, профаззить все его инструменты. Контракт находок."""
    итог: dict[str, Any] = {"инструмент": {"имя": "needler", "цель": url}, "url": url}
    endpoint = await discover_endpoint(url)
    if endpoint is None:
        итог.update({"verdict": "НЕ ПРОВЕРЕНО", "not_proven": "MCP-сервер не обнаружен",
                     "tools_fuzzed": 0, "findings": []})
        return итог
    async with httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
        await _mcp_call(client, endpoint, "initialize",
                        {"protocolVersion": "2024-11-05",
                         "clientInfo": {"name": "needler", "version": "0.2.0"}, "capabilities": {}})
        tools_obj = await _mcp_call(client, endpoint, "tools/list", request_id=2)
        tools = _extract_result(tools_obj).get("tools", []) if tools_obj.get("ok") else []
        if not tools:
            итог.update({"verdict": "НЕ ПРОВЕРЕНО",
                         "not_proven": "инструменты не перечислены — фаззить нечего",
                         "tools_fuzzed": 0, "findings": []})
            return итог
        все_находки = []
        for i, tool in enumerate(tools):
            все_находки += await fuzz_tool(client, endpoint, tool, request_id=100 + i * 100)
    крашей = sum(1 for f in все_находки if f["класс"] in ("crash-5xx", "transport-error"))
    утечек = sum(1 for f in все_находки if f["класс"] not in ("crash-5xx", "transport-error", "ok"))
    итог.update({
        "verdict": "ПРОВАЛ" if все_находки else "ПРОШЁЛ",
        "tools_fuzzed": len(tools), "findings": все_находки,
        "crash_count": крашей, "leak_count": утечек,
        "почему": (f"инструмент(ы) не держат битый ввод: крашей {крашей}, утечек внутренностей {утечек}"
                   if все_находки else "все инструменты выдержали фаззинг — падений и утечек нет"),
    })
    return итог
