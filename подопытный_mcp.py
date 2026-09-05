#!/usr/bin/env python3
"""Синтетические MCP-серверы с tools/call — для проверки самого needler.

🔴 OPSEC: свои серверы на localhost, не реальные цели.

  уязвимый — на битом вводе НЕ валидирует: кидает исключение и возвращает СВОЙ traceback с путём
             файловой системы. needler обязан дать ПРОВАЛ (утечка внутренностей + краш).
  чистый   — валидирует тип аргумента, на битом вводе возвращает вежливый isError без внутренностей.
             ПРОШЁЛ.

Отвечает по MCP JSON-RPC: initialize · tools/list · tools/call.
Запуск: python3 подопытный_mcp.py уязвимый 8499  |  чистый 8498
"""
import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = [
    {"name": "get_order", "description": "Fetch an order by numeric id.",
     "inputSchema": {"type": "object", "properties": {"order_id": {"type": "integer"}}}},
    {"name": "search", "description": "Search catalog by keyword.",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string", "maxLength": 64}}}},
]


def обработчик(режим: str):
    class Ручка(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj, code=200):
            тело = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(тело)))
            self.end_headers()
            self.wfile.write(тело)

        def do_GET(self):
            # discovery: отдаём JSON, чтобы discover_endpoint нас нашёл
            self._send({"mcp": "ready"})

        def do_POST(self):
            сырое = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            try:
                req = json.loads(сырое)
            except Exception:
                self._send({}, 400); return
            метод, rid = req.get("method"), req.get("id", 1)
            params = req.get("params", {})

            if метод == "initialize":
                return self._send({"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": f"mcp-{режим}", "version": "0.1.0"},
                    "capabilities": {"tools": {}}}})
            if метод == "tools/list":
                return self._send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
            if метод == "tools/call":
                имя = params.get("name")
                args = params.get("arguments", {})
                try:
                    if режим == "уязвимый":
                        # НЕ валидирует: get_order ждёт int, делает арифметику → падает на строке/списке
                        if имя == "get_order":
                            val = args.get("order_id")
                            result = f"order #{val + 1000}"          # TypeError на не-int
                        else:
                            result = args["q"].upper()               # AttributeError на не-строке
                        return self._send({"jsonrpc": "2.0", "id": rid,
                                           "result": {"content": [{"type": "text", "text": result}]}})
                    else:  # чистый — валидирует
                        if имя == "get_order":
                            if not isinstance(args.get("order_id"), int) or isinstance(args.get("order_id"), bool):
                                raise ValueError("order_id must be an integer")
                            return self._send({"jsonrpc": "2.0", "id": rid, "result": {
                                "content": [{"type": "text", "text": f"order #{args['order_id']}"}]}})
                        q = args.get("q")
                        if not isinstance(q, str) or len(q) > 64:
                            raise ValueError("q must be a string up to 64 chars")
                        return self._send({"jsonrpc": "2.0", "id": rid, "result": {
                            "content": [{"type": "text", "text": f"results for {q}"}]}})
                except ValueError as e:
                    # чистый: вежливый isError, БЕЗ внутренностей
                    return self._send({"jsonrpc": "2.0", "id": rid, "result": {
                        "isError": True, "content": [{"type": "text", "text": f"invalid argument: {e}"}]}})
                except Exception:
                    # уязвимый: отдаёт СВОЙ traceback с путём файловой системы
                    return self._send({"jsonrpc": "2.0", "id": rid,
                                       "error": {"code": -32603, "message": traceback.format_exc()}}, 500)
            self._send({"jsonrpc": "2.0", "id": rid, "result": {}})

    return Ручка


if __name__ == "__main__":
    режим = sys.argv[1] if len(sys.argv) > 1 else "чистый"
    порт = int(sys.argv[2]) if len(sys.argv) > 2 else 8498
    HTTPServer(("127.0.0.1", порт), обработчик(режим)).serve_forever()
