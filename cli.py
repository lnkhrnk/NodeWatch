"""Командный интерфейс администратора NodeWatch (CLI).

Подключается к серверу по TCP (порт управления 9998) с той же взаимной
аутентификацией, что и агенты, и выполняет команды:

  python cli.py agents
  python cli.py report [NODE]
  python cli.py incidents [--node N] [--rule R] [--status open|acknowledged]
  python cli.py incident INC-0001
  python cli.py ack INC-0001
  python cli.py agent NODE pause|resume|snapshot|ping
  python cli.py agent NODE interval 1.5
  python cli.py agent NODE groups lab,office      (NODE: имя, @группа или *)
  python cli.py thresholds [key=value ...] [--reset]
  python cli.py test_incident NODE [RULE]
  python cli.py forget NODE
  python cli.py shell                              (интерактивный режим)
"""
import argparse
import json
import shlex
import sys
import time

from common import connect_admin, fix_console, load_config, require_secret


def fmt_bytes(v):
    if v is None:
        return "-"
    for unit in ("Б/с", "КБ/с", "МБ/с", "ГБ/с"):
        if abs(v) < 1024:
            return "%.1f %s" % (v, unit)
        v /= 1024.0
    return "%.1f ТБ/с" % v


def fmt_time(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-"


def table(rows, headers):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-" * len(line))
    for row in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))


STATUS_RU = {"online": "онлайн", "silent": "молчит", "offline": "офлайн", "paused": "пауза"}


class Client:
    def __init__(self, host, port, secret):
        self.conn = connect_admin(host, port, secret)
        self.n = 0

    def call(self, cmd, **kwargs):
        self.n += 1
        msg = {"type": "cmd", "id": self.n, "cmd": cmd}
        msg.update(kwargs)
        self.conn.send(msg)
        resp = self.conn.recv()
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error"))
        return resp.get("data")


def show(client, argv):
    """Разбирает одну команду и печатает результат."""
    ap = argparse.ArgumentParser(prog="cli.py", add_help=True)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("agents")
    p = sub.add_parser("report"); p.add_argument("node", nargs="?")
    p = sub.add_parser("incidents")
    p.add_argument("--node"); p.add_argument("--rule"); p.add_argument("--status"); p.add_argument("--limit", type=int, default=30)
    p = sub.add_parser("incident"); p.add_argument("id")
    p = sub.add_parser("ack"); p.add_argument("id")
    p = sub.add_parser("agent"); p.add_argument("node"); p.add_argument("action"); p.add_argument("value", nargs="?")
    p = sub.add_parser("thresholds"); p.add_argument("pairs", nargs="*"); p.add_argument("--reset", action="store_true")
    p = sub.add_parser("test_incident"); p.add_argument("node"); p.add_argument("rule", nargs="?", default="TEST")
    p = sub.add_parser("forget"); p.add_argument("node")
    sub.add_parser("info")
    a = ap.parse_args(argv)

    if a.cmd == "agents":
        rows = []
        for ag in client.call("agents"):
            rows.append([ag["node"], STATUS_RU.get(ag["status"], ag["status"]), ag["ip"] or "-",
                         "%ss" % ag["age_s"] if ag["age_s"] is not None else "-", ag["packets"],
                         "%d (%.1f%%)" % (ag["lost"], ag["loss_pct"]), ag["replay"],
                         "%d/%d" % (ag["buffer"], ag["buffer_cap"]), ag["incidents"],
                         "%s/%ss" % (ag["profile"], ag["interval"]), ",".join(ag["groups"])])
        table(rows, ["узел", "статус", "IP", "last_seen", "пакеты", "потери", "replay", "буфер",
                     "инц.", "профиль/инт.", "группы"])
    elif a.cmd == "report":
        data = client.call("report", node=a.node) if a.node else client.call("report")
        nodes = [data] if a.node else data["nodes"]
        for item in nodes:
            print("\n== %s ==" % item["node"])
            rows = []
            for key, st in item["summary"].items():
                conv = fmt_bytes if key.startswith(("net_", "disk_read", "disk_write", "disk_total")) else (lambda v: "%.2f" % v)
                rows.append([key, conv(st["mean"]), conv(st["p95"]), conv(st["max"]), conv(st["last"])])
            table(rows, ["метрика", "mean", "p95", "max", "last"])
    elif a.cmd == "incidents":
        items = client.call("incidents", node=a.node, rule=a.rule, status=a.status, limit=a.limit)
        table([[i["id"], fmt_time(i["ts"]), i["node"], i["rule"], i["severity"], i["status"]] for i in items],
              ["id", "время", "узел", "правило", "важность", "статус"])
    elif a.cmd == "incident":
        inc = client.call("incident", id=a.id)
        print("%s  %s  [%s]  %s" % (inc["id"], inc["rule"], inc["severity"], inc["title"]))
        print("узел: %s (%s)   время: %s   статус: %s" % (inc["node"], inc["ip"],
              time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc["ts"])), inc["status"]))
        print("доказательства:")
        print(json.dumps(inc["evidence"], ensure_ascii=False, indent=2))
        snap = inc.get("snapshot")
        if snap:
            print("топ процессов по CPU:")
            table([[p["pid"], p["name"], p["cpu"], p["rss_mb"]] for p in snap["top_cpu"][:5]],
                  ["pid", "имя", "cpu%", "RSS МБ"])
        else:
            print("снимок: %s" % inc.get("snapshot_status"))
    elif a.cmd == "ack":
        print(client.call("ack", id=a.id))
    elif a.cmd == "agent":
        value = a.value
        if a.action == "interval":
            value = float(value)
        res = client.call("agent", node=a.node, action=a.action, value=value)
        for node, r in res.items():
            if r["ok"] and a.action == "snapshot":
                snap = r["data"]
                print("== %s: процессов %d, соединений %s" % (node, snap["process_count"], snap["conn_summary"].get("total")))
                table([[p["pid"], p["name"], p["cpu"], p["rss_mb"]] for p in snap["top_cpu"]], ["pid", "имя", "cpu%", "RSS МБ"])
            else:
                print(node, "OK" if r["ok"] else "ОШИБКА", r.get("data") if r["ok"] else r.get("error"))
    elif a.cmd == "thresholds":
        changes = {}
        for pair in a.pairs:
            key, _, value = pair.partition("=")
            changes[key] = value
        data = client.call("thresholds", set=changes or None, reset=a.reset)
        table([[i["group"], i["key"], i["value"], "*" if i["changed"] else ""] for i in data["items"]],
              ["группа", "параметр", "значение", "изм."])
    elif a.cmd == "test_incident":
        print(client.call("test_incident", node=a.node, rule=a.rule))
    elif a.cmd == "forget":
        print(client.call("forget", node=a.node))
    elif a.cmd == "info":
        print(json.dumps(client.call("info"), ensure_ascii=False, indent=2))
    else:
        ap.print_help()


def main():
    fix_console()
    cfg = load_config()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--server", default=cfg["agent"]["host"], help="IP сервера")
    ap.add_argument("--port", type=int, default=cfg["server"]["tcp_port"])
    ap.add_argument("--secret")
    known, rest = ap.parse_known_args()
    if known.secret:
        cfg["secret"] = known.secret
    secret = require_secret(cfg)
    try:
        client = Client(known.server, known.port, secret)
    except PermissionError as exc:
        sys.exit("Аутентификация не пройдена: %s (проверьте MON_SECRET)" % exc)
    except OSError as exc:
        sys.exit("Нет связи с сервером %s:%s — %s" % (known.server, known.port, exc))

    if not rest or rest[0] == "shell":
        print("NodeWatch CLI. Команды: agents, report, incidents, incident, ack, agent, thresholds, "
              "test_incident, forget, info, exit")
        while True:
            try:
                line = input("nodewatch> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line in ("exit", "quit"):
                break
            if not line:
                continue
            try:
                show(client, shlex.split(line))
            except SystemExit:
                pass
            except Exception as exc:
                print("Ошибка:", exc)
        return
    try:
        show(client, rest)
    except RuntimeError as exc:
        sys.exit("Ошибка: %s" % exc)


if __name__ == "__main__":
    main()
