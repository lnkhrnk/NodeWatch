"""Агент NodeWatch — запускается на каждом контролируемом узле.

* раз в interval секунд собирает метрики (psutil + /proc/stat на Linux)
  и отправляет их на сервер по UDP (подпись HMAC-SHA256, сжатие zlib,
  номер пакета seq и идентификатор запуска boot);
* сам открывает TCP-соединение к серверу (работает через NAT и файрвол),
  проходит взаимную аутентификацию и выполняет команды управления:
  pause / resume / interval / groups / snapshot / ping.

Запуск:  python agent.py --host 192.168.1.10
"""
import argparse
import logging
import os
import platform
import queue
import secrets
import socket
import sys
import threading
import time

import psutil

from common import (VERSION, JsonLineConn, client_handshake, encode_packet,
                    fix_console, load_config, require_secret)

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
MB = 1024.0 * 1024.0
log = logging.getLogger("agent")


# ====================================================================== метрики
class Collector:
    """Собирает метрики. Скорости считаются как разность счётчиков / время."""

    def __init__(self, include_loopback=False):
        self.include_loopback = include_loopback
        self.prev = None
        psutil.cpu_percent(percpu=True)        # первый вызов только «запоминает» отсчёт
        psutil.cpu_times_percent()
        self.prev = self._counters()

    # ---- сырые счётчики
    def _net(self):
        total_in = total_out = 0
        for name, c in psutil.net_io_counters(pernic=True).items():
            low = name.lower()
            if not self.include_loopback and (low == "lo" or low.startswith("loopback") or low.startswith("lo0")):
                continue
            total_in += c.bytes_recv
            total_out += c.bytes_sent
        return total_in, total_out

    @staticmethod
    def _forks():
        """Linux: счётчик fork/clone с момента загрузки. Учитывает и процессы,
        которые успели завершиться между двумя замерами."""
        if not IS_LINUX:
            return None
        try:
            with open("/proc/stat", "r") as fh:
                for line in fh:
                    if line.startswith("processes "):
                        return int(line.split()[1])
        except OSError:
            return None
        return None

    @staticmethod
    def _processes():
        attrs = ["pid", "num_threads"] + (["num_handles"] if IS_WINDOWS else [])
        threads, handles = {}, 0
        for p in psutil.process_iter(attrs, ad_value=None):
            info = p.info
            threads[info["pid"]] = info.get("num_threads") or 0
            handles += info.get("num_handles") or 0
        return threads, handles

    def _counters(self):
        disk = psutil.disk_io_counters()
        threads, handles = self._processes()
        vm = psutil.virtual_memory()
        return {
            "t": time.monotonic(),
            "disk": disk,
            "net": self._net(),
            "forks": self._forks(),
            "threads": threads,
            "handles": handles,
            "mem_used": (vm.total - vm.available) / MB,
        }

    # ---- одна точка
    def sample(self):
        cur = self._counters()
        prev = self.prev
        self.prev = cur
        dt = max(cur["t"] - prev["t"], 1e-3)

        cores = psutil.cpu_percent(percpu=True)
        times = psutil.cpu_times_percent()
        cpu_user = times.user + getattr(times, "nice", 0.0)
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        m = {
            "cpu_total": round(sum(cores) / max(len(cores), 1), 2),
            "cpu_user": round(cpu_user, 2),
            "cpu_cores": [round(c, 1) for c in cores],
            "cpu_max_core": max(cores) if cores else 0.0,
        }
        # диск: байты/с и операции/с (IOPS)
        d0, d1 = prev["disk"], cur["disk"]
        if d0 is not None and d1 is not None:
            m["disk_read"] = max(0, d1.read_bytes - d0.read_bytes) / dt
            m["disk_write"] = max(0, d1.write_bytes - d0.write_bytes) / dt
            m["disk_riops"] = max(0, d1.read_count - d0.read_count) / dt
            m["disk_wiops"] = max(0, d1.write_count - d0.write_count) / dt
        else:
            m["disk_read"] = m["disk_write"] = m["disk_riops"] = m["disk_wiops"] = 0.0
        m["disk_total"] = m["disk_read"] + m["disk_write"]
        m["disk_iops"] = m["disk_riops"] + m["disk_wiops"]
        # сеть
        m["net_in"] = max(0, cur["net"][0] - prev["net"][0]) / dt
        m["net_out"] = max(0, cur["net"][1] - prev["net"][1]) / dt
        m["net_total"] = m["net_in"] + m["net_out"]
        # процессы и потоки
        new_pids = [pid for pid in cur["threads"] if pid not in prev["threads"]]
        if cur["forks"] is not None and prev["forks"] is not None:
            m["proc_new_ps"] = max(0, cur["forks"] - prev["forks"]) / dt
            m["proc_source"] = "proc_stat"
        else:
            m["proc_new_ps"] = len(new_pids) / dt
            m["proc_source"] = "pid_diff"
        new_threads = 0
        for pid, n in cur["threads"].items():
            new_threads += max(0, n - prev["threads"].get(pid, 0))
        m["thr_new_ps"] = new_threads / dt
        m["proc_count"] = len(cur["threads"])
        m["thr_count"] = sum(cur["threads"].values())
        if IS_WINDOWS:
            m["handles"] = cur["handles"]
        # память
        m["mem_total"] = round(vm.total / MB, 1)
        m["mem_used"] = round(cur["mem_used"], 1)
        m["mem_pct"] = vm.percent
        m["mem_delta"] = round(cur["mem_used"] - prev["mem_used"], 1)
        m["mem_delta_pct"] = round(100.0 * m["mem_delta"] / max(m["mem_total"], 1), 3)
        m["swap_pct"] = swap.percent
        for key in ("disk_read", "disk_write", "disk_total", "net_in", "net_out", "net_total"):
            m[key] = round(m[key], 1)
        for key in ("disk_riops", "disk_wiops", "disk_iops", "proc_new_ps", "thr_new_ps"):
            m[key] = round(m[key], 2)
        return m


# ====================================================================== снимок
def _proc_row(p, ncpu, cpu=None):
    info = p.info
    mem = info.get("memory_info")
    return {
        "pid": info.get("pid"), "name": info.get("name") or "?",
        "user": (info.get("username") or "").split("\\")[-1],
        "cpu": round((cpu or 0.0) / ncpu, 1),
        "rss_mb": round(mem.rss / MB, 1) if mem else 0.0,
        "started": round(info.get("create_time") or 0, 1),
    }


def take_snapshot(limit=8):
    """Снимок состояния узла для карточки инцидента."""
    ncpu = psutil.cpu_count() or 1
    procs = list(psutil.process_iter(["pid", "name", "username", "create_time", "memory_info"], ad_value=None))
    for p in procs:
        try:
            p.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(0.5)
    rows = []
    for p in procs:
        try:
            cpu = p.cpu_percent(None)
        except psutil.Error:
            cpu = 0.0
        rows.append(_proc_row(p, ncpu, cpu))
    by_pid = {r["pid"]: r["name"] for r in rows}

    newest = sorted(rows, key=lambda r: r["started"], reverse=True)[:limit]
    for row in newest:
        try:
            cmd = psutil.Process(row["pid"]).cmdline()
            row["cmdline"] = " ".join(cmd)[:160]
        except psutil.Error:
            row["cmdline"] = ""

    conns, summary = [], {"total": 0}
    try:
        for c in psutil.net_connections(kind="inet"):
            summary["total"] += 1
            summary[c.status] = summary.get(c.status, 0) + 1
            if c.raddr:
                conns.append({
                    "laddr": "%s:%s" % (c.laddr.ip, c.laddr.port) if c.laddr else "",
                    "raddr": "%s:%s" % (c.raddr.ip, c.raddr.port),
                    "status": c.status, "pid": c.pid, "name": by_pid.get(c.pid, ""),
                })
    except (psutil.Error, OSError) as exc:
        summary["error"] = str(exc)
    conns.sort(key=lambda c: c["status"] != "ESTABLISHED")

    users = []
    try:
        for u in psutil.users():
            users.append({"name": u.name, "terminal": u.terminal or "", "host": u.host or "",
                          "started": round(u.started, 0)})
    except Exception:
        pass

    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    return {
        "ts": time.time(),
        "host": socket.gethostname(),
        "top_cpu": sorted(rows, key=lambda r: r["cpu"], reverse=True)[:limit],
        "top_mem": sorted(rows, key=lambda r: r["rss_mb"], reverse=True)[:limit],
        "newest": newest,
        "connections": conns[:25],
        "conn_summary": summary,
        "users": users,
        "memory": {"total_mb": round(vm.total / MB), "used_mb": round((vm.total - vm.available) / MB),
                   "percent": vm.percent},
        "swap": {"total_mb": round(sw.total / MB), "used_mb": round(sw.used / MB), "percent": sw.percent},
        "process_count": len(rows),
    }


# ====================================================================== агент
class Agent:
    HEARTBEAT_S = 10

    def __init__(self, cfg, args):
        acfg = cfg["agent"]
        self.secret = require_secret(cfg)
        self.host = args.host or acfg["host"]
        self.udp_port = int(args.udp_port or acfg["udp_port"])
        self.tcp_port = int(args.tcp_port or acfg["tcp_port"])
        self.node = (args.node or acfg.get("node") or socket.gethostname()).strip()
        self.interval = float(args.interval or acfg["interval"])
        groups = args.groups.split(",") if args.groups else acfg.get("groups", [])
        self.groups = [g.strip() for g in groups if g.strip()]
        self.boot = secrets.token_hex(4)          # новый идентификатор на каждый запуск
        self.seq = 0
        self.paused = False
        self.sent = 0
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.collector = Collector(bool(acfg.get("include_loopback")))
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.conn = None
        self.commands = queue.Queue()             # команды выполняет один постоянный поток

    def info(self):
        return {
            "version": VERSION, "os": platform.system(), "os_release": platform.release(),
            "hostname": socket.gethostname(), "cpu_count": psutil.cpu_count(),
            "interval": self.interval, "paused": self.paused, "groups": self.groups,
            "boot": self.boot, "sent": self.sent, "python": platform.python_version(),
        }

    # ---- UDP: метрики
    def metrics_loop(self):
        addr = (self.host, self.udp_port)
        next_tick = time.monotonic() + self.interval   # первая точка — через полный интервал
        self.stop.wait(self.interval)
        while not self.stop.is_set():
            try:
                metrics = self.collector.sample()      # сбор идёт и на паузе (mem_delta не «копится»)
                if not self.paused:
                    self.seq += 1
                    packet = encode_packet(self.secret, {
                        "node": self.node, "boot": self.boot, "seq": self.seq,
                        "ts": round(time.time(), 3), "iv": self.interval, "m": metrics})
                    self.udp.sendto(packet, addr)
                    self.sent += 1
            except OSError as exc:
                log.warning("UDP: %s", exc)
            except Exception:
                log.exception("ошибка сбора метрик")
            next_tick += self.interval
            delay = next_tick - time.monotonic()
            if delay < 0:
                next_tick = time.monotonic()
                delay = 0
            self.wake.wait(delay)
            if self.wake.is_set():
                self.wake.clear()
                next_tick = time.monotonic()

    # ---- TCP: управление
    def handle(self, msg):
        cmd = msg.get("cmd")
        if cmd == "ping":
            return {"pong": time.time()}
        if cmd == "pause":
            self.paused = True
            log.info("пауза по команде сервера")
            return {"paused": True}
        if cmd == "resume":
            self.paused = False
            log.info("возобновление отправки")
            return {"paused": False}
        if cmd == "interval":
            value = float(msg.get("value"))
            if not 0.5 <= value <= 60:
                raise ValueError("интервал должен быть от 0.5 до 60 с")
            self.interval = value
            self.wake.set()
            log.info("новый интервал %.1f с", value)
            return {"interval": value}
        if cmd == "groups":
            value = msg.get("value") or []
            if isinstance(value, str):
                value = value.split(",")
            self.groups = [g.strip() for g in value if str(g).strip()]
            return {"groups": self.groups}
        if cmd == "snapshot":
            return take_snapshot()
        if cmd == "status":
            return self.info()
        raise ValueError("неизвестная команда: %s" % cmd)

    def _heartbeat(self, conn):
        while not self.stop.is_set() and self.conn is conn:
            time.sleep(self.HEARTBEAT_S)
            try:
                conn.send({"type": "status", "info": self.info()})
            except OSError:
                return

    def command_worker(self):
        """Постоянный поток для команд: снимок занимает ~0.5 с и не должен
        блокировать чтение сокета; новые потоки на каждую команду не создаются
        (иначе агент сам искажал бы метрику thr_new_ps / proc_new_ps)."""
        while not self.stop.is_set():
            try:
                conn, msg = self.commands.get(timeout=1.0)
            except queue.Empty:
                continue
            self._serve_command(conn, msg)

    def _serve_command(self, conn, msg):
        try:
            data = self.handle(msg)
            reply = {"type": "resp", "id": msg.get("id"), "ok": True, "data": data}
        except Exception as exc:
            reply = {"type": "resp", "id": msg.get("id"), "ok": False, "error": str(exc)}
        try:
            conn.send(reply)
        except OSError:
            pass

    def control_loop(self):
        backoff = 1
        while not self.stop.is_set():
            conn = None
            try:
                sock = socket.create_connection((self.host, self.tcp_port), timeout=10)
                conn = JsonLineConn(sock)
                client_handshake(conn, self.secret, "agent", self.node, self.info())
                sock.settimeout(None)
                self.conn = conn
                backoff = 1
                log.info("TCP-управление: подключено к %s:%s", self.host, self.tcp_port)
                threading.Thread(target=self._heartbeat, args=(conn,), daemon=True).start()
                while not self.stop.is_set():
                    msg = conn.recv()
                    if msg.get("type") == "cmd":
                        self.commands.put((conn, msg))
            except PermissionError as exc:
                log.error("TCP: аутентификация не пройдена (%s). Проверьте MON_SECRET.", exc)
                backoff = 10
            except (OSError, ConnectionError, ValueError) as exc:
                log.warning("TCP: нет связи с сервером (%s), повтор через %d с", exc, backoff)
            finally:
                self.conn = None
                if conn:
                    conn.close()
            self.stop.wait(backoff)
            backoff = min(backoff * 2, 10)

    def run(self):
        log.info("агент %s (boot %s) -> сервер %s, UDP %d, TCP %d, интервал %.1f с, группы %s",
                 self.node, self.boot, self.host, self.udp_port, self.tcp_port, self.interval,
                 ",".join(self.groups) or "-")
        threading.Thread(target=self.control_loop, name="control", daemon=True).start()
        threading.Thread(target=self.command_worker, name="commands", daemon=True).start()
        try:
            self.metrics_loop()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            log.info("агент остановлен, отправлено пакетов: %d", self.sent)


def main():
    fix_console()
    ap = argparse.ArgumentParser(description="Агент мониторинга NodeWatch")
    ap.add_argument("--host", help="IP-адрес сервера (по умолчанию из config.json)")
    ap.add_argument("--node", help="имя узла (по умолчанию имя компьютера)")
    ap.add_argument("--interval", type=float, help="период отправки метрик, с")
    ap.add_argument("--groups", help="группы через запятую, например lab,office")
    ap.add_argument("--udp-port", type=int)
    ap.add_argument("--tcp-port", type=int)
    ap.add_argument("--config", help="путь к config.json")
    ap.add_argument("--secret", help="общий секрет (лучше через MON_SECRET)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")
    cfg = load_config(args.config)
    if args.secret:
        cfg["secret"] = args.secret
    Agent(cfg, args).run()


if __name__ == "__main__":
    main()
