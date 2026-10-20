"""Центральный аналитический сервер NodeWatch.

Потоки сервера:
  udp-recv      — принимает UDP-датаграммы и кладёт их в очередь;
  worker-1..N   — проверяют подпись, распаковывают, учитывают потери/повторы,
                  пишут точку в кольцевой буфер узла и запускают анализ;
  watchdog      — раз в секунду проверяет «молчащих» агентов (AGENT_SILENT);
  tcp-accept    — принимает TCP-подключения агентов и CLI (по потоку на клиента);
  http          — веб-панель и REST API (ThreadingHTTPServer).

Запуск:  python server.py      (порты: HTTP 8080, UDP 9999, TCP 9998)
"""
import argparse
import hmac
import json
import logging
import logging.handlers
import os
import queue
import smtplib
import socket
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from analyzer import (CHART_KEYS, RULES, Analyzer, NodeState, RingBuffer,
                      Thresholds, summarize)
from common import (VERSION, JsonLineConn, PacketError, SeqWindow, auth_mac,
                    decode_packet, fix_console, load_config, local_ipv4,
                    new_nonce, panel_token, require_secret)

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "web")
log = logging.getLogger("server")

SUMMARY_KEYS = ["cpu_total", "cpu_user", "cpu_max_core", "disk_read", "disk_write", "disk_total",
                "disk_iops", "net_in", "net_out", "net_total", "proc_new_ps", "thr_new_ps",
                "proc_count", "thr_count", "handles", "mem_used", "mem_pct", "mem_delta", "swap_pct"]
TAIL_KEYS = ["cpu_user", "net_total", "disk_total", "mem_used", "mem_delta", "proc_new_ps", "thr_new_ps"]


class CommandError(Exception):
    pass


# ====================================================================== агенты
class AgentLink:
    """TCP-канал управления к одному агенту: команды с ожиданием ответа по id."""

    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.pending = {}
        self.next_id = 0
        self.lock = threading.Lock()

    def call(self, cmd, timeout=6.0, **kwargs):
        with self.lock:
            self.next_id += 1
            msg_id = self.next_id
            slot = {"event": threading.Event(), "resp": None}
            self.pending[msg_id] = slot
        try:
            msg = {"type": "cmd", "id": msg_id, "cmd": cmd}
            msg.update(kwargs)
            self.conn.send(msg)
            if not slot["event"].wait(timeout):
                raise CommandError("агент не ответил за %.0f с" % timeout)
        except OSError as exc:
            raise CommandError("ошибка связи с агентом: %s" % exc)
        finally:
            with self.lock:
                self.pending.pop(msg_id, None)
        resp = slot["resp"]
        if not resp.get("ok"):
            raise CommandError(resp.get("error") or "ошибка агента")
        return resp.get("data")

    def resolve(self, msg):
        with self.lock:
            slot = self.pending.get(msg.get("id"))
        if slot:
            slot["resp"] = msg
            slot["event"].set()

    def close(self):
        self.conn.close()


class AgentRecord:
    """Всё, что сервер знает об одном узле."""

    def __init__(self, node, buffer_size):
        self.node = node
        self.ip = ""
        self.info = {}
        self.groups = []
        self.interval = None
        self.paused = False
        self.first_seen = time.time()
        self.last_seen = None        # время последнего принятого UDP-пакета
        self.resumed_at = None       # когда сняли паузу (или агент отключился, будучи на паузе)
        self.last_tcp = None
        self.packets = 0
        self.window = SeqWindow()
        self.buffer = RingBuffer(buffer_size)
        self.state = NodeState()
        self.incidents = 0
        self.link = None
        self.lock = threading.Lock()

    @property
    def os_name(self):
        return self.info.get("os", "")

    def silence_ref(self):
        """Момент, от которого считается молчание: последний UDP-пакет или снятие паузы.

        Пока агент стоял на паузе, пакеты не шли, поэтому сразу после «Продолжить»
        старое время last_seen не должно приводить к ложному AGENT_SILENT.
        """
        times = [t for t in (self.last_seen, self.resumed_at) if t is not None]
        return max(times) if times else None

    def set_paused(self, paused):
        if self.paused and not paused:
            self.resumed_at = time.time()
        self.paused = paused


# ====================================================================== инциденты
class IncidentStore:
    """Хранилище инцидентов: память + JSON-файлы + alerts.log + лента событий."""

    def __init__(self, data_dir, notifier=None):
        self.dir = os.path.join(data_dir, "incidents")
        os.makedirs(self.dir, exist_ok=True)
        self.alerts_path = os.path.join(data_dir, "alerts.log")
        self.items = {}
        self.lock = threading.Lock()
        self.counter = 0
        self.events = []
        self.event_seq = 0
        self.notifier = notifier
        self._load()

    def _load(self):
        for name in sorted(os.listdir(self.dir)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), "r", encoding="utf-8") as fh:
                    inc = json.load(fh)
                self.items[inc["id"]] = inc
                self.counter = max(self.counter, int(inc["id"].split("-")[1]))
            except Exception:
                log.warning("не удалось прочитать %s", name)
        if self.items:
            log.info("загружено инцидентов: %d", len(self.items))

    def _save(self, inc):
        path = os.path.join(self.dir, inc["id"] + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(inc, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    def add(self, inc):
        with self.lock:
            self.counter += 1
            inc["id"] = "INC-%04d" % self.counter
            self.items[inc["id"]] = inc
            self._save(inc)
            self.event_seq += 1
            self.events.append({"n": self.event_seq, "type": "incident", "id": inc["id"],
                                "node": inc["node"], "rule": inc["rule"], "severity": inc["severity"],
                                "title": inc["title"], "ts": inc["ts"]})
            self.events = self.events[-200:]
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc["ts"]))
        line = "%s [%s] %s node=%s rule=%s %s evidence=%s" % (
            stamp, inc["severity"], inc["id"], inc["node"], inc["rule"], inc["title"],
            json.dumps(inc["evidence"], ensure_ascii=False))
        with open(self.alerts_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        log.warning("ИНЦИДЕНТ %s: %s на %s — %s", inc["id"], inc["rule"], inc["node"], inc["title"])
        if self.notifier:
            self.notifier.send(inc)
        return inc

    def update(self, inc_id, **fields):
        with self.lock:
            inc = self.items.get(inc_id)
            if inc is None:
                return None
            inc.update(fields)
            self._save(inc)
            return inc

    def get(self, inc_id):
        with self.lock:
            inc = self.items.get(inc_id)
            return json.loads(json.dumps(inc)) if inc else None

    def query(self, node=None, rule=None, status=None, limit=200):
        with self.lock:
            items = sorted(self.items.values(), key=lambda i: i["ts"], reverse=True)
        out = []
        for inc in items:
            if node and inc["node"] != node:
                continue
            if rule and inc["rule"] != rule:
                continue
            if status and inc["status"] != status:
                continue
            out.append({k: inc.get(k) for k in ("id", "ts", "node", "rule", "severity", "title",
                                                 "status", "ack_by", "ack_ts", "source")})
            if len(out) >= limit:
                break
        return out

    def count_open(self, node=None):
        with self.lock:
            return sum(1 for i in self.items.values()
                       if i["status"] == "open" and (node is None or i["node"] == node))

    def events_since(self, since):
        with self.lock:
            return self.event_seq, [e for e in self.events if e["n"] > since]


class Notifier:
    """Необязательная отправка инцидентов по e-mail (SMTP) в фоновом потоке."""

    def __init__(self, smtp_cfg):
        self.cfg = smtp_cfg

    def send(self, inc):
        if self.cfg.get("enabled"):
            threading.Thread(target=self._send, args=(inc,), daemon=True).start()

    def _send(self, inc):
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = "[NodeWatch] %s %s на %s" % (inc["severity"].upper(), inc["rule"], inc["node"])
        msg["From"] = c["from"]
        msg["To"] = ", ".join(c["to"])
        msg.set_content("%s\n\n%s\n\nЗафиксировано: %s\n\nДоказательства:\n%s" % (
            inc["title"], inc["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc["ts"])),
            json.dumps(inc["evidence"], ensure_ascii=False, indent=2)))
        try:
            with smtplib.SMTP(c["host"], int(c["port"]), timeout=15) as smtp:
                if c.get("starttls"):
                    smtp.starttls()
                if c.get("user"):
                    smtp.login(c["user"], c["password"])
                smtp.send_message(msg)
            log.info("письмо по %s отправлено", inc["id"])
        except Exception as exc:
            log.warning("SMTP: не удалось отправить письмо (%s)", exc)


# ====================================================================== сервер
class MonitorServer:
    def __init__(self, cfg):
        self.cfg = cfg
        scfg = cfg["server"]
        self.scfg = scfg
        self.secret = require_secret(cfg)
        self.token = panel_token(self.secret, scfg.get("web_token", ""))
        self.data_dir = os.path.join(HERE, scfg["data_dir"]) if not os.path.isabs(scfg["data_dir"]) else scfg["data_dir"]
        os.makedirs(self.data_dir, exist_ok=True)
        self.thresholds = Thresholds(os.path.join(self.data_dir, "thresholds.json"), cfg.get("thresholds"))
        self.analyzer = Analyzer(self.thresholds)
        self.store = IncidentStore(self.data_dir, Notifier(scfg.get("smtp", {})))
        self.agents = {}
        self.agents_lock = threading.Lock()
        self.queue = queue.Queue(maxsize=int(scfg["queue_size"]))
        self.started = time.time()
        self.stats = {"udp_received": 0, "processed": 0, "queue_drops": 0, "bad_hmac": 0,
                      "bad_format": 0, "replay": 0, "stale": 0, "auth_failed": 0}
        self.stats_lock = threading.Lock()
        self.stop = threading.Event()
        self.snapshots = queue.Queue()      # запросы снимков к агентам (2 постоянных потока)

    def _count(self, key, n=1):
        with self.stats_lock:
            self.stats[key] += n

    def _record(self, node, create=True):
        with self.agents_lock:
            rec = self.agents.get(node)
            if rec is None and create:
                rec = AgentRecord(node, self.scfg["buffer_size"])
                self.agents[node] = rec
                log.info("новый узел: %s", node)
            return rec

    # ------------------------------------------------------------ запуск
    def start(self):
        bind = self.scfg["bind"]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        self.udp.bind((bind, int(self.scfg["udp_port"])))
        self.udp.settimeout(1.0)

        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((bind, int(self.scfg["tcp_port"])))
        self.tcp.listen(64)
        self.tcp.settimeout(1.0)

        handler = type("BoundHandler", (PanelHandler,), {"server_ref": self})
        self.http = ThreadingHTTPServer((bind, int(self.scfg["http_port"])), handler)
        self.http.daemon_threads = True

        threads = [threading.Thread(target=self._udp_loop, name="udp-recv")]
        for i in range(int(self.scfg["workers"])):
            threads.append(threading.Thread(target=self._worker, name="worker-%d" % (i + 1)))
        threads.append(threading.Thread(target=self._watchdog, name="watchdog"))
        for i in range(2):
            threads.append(threading.Thread(target=self._snapshot_worker, name="snapshot-%d" % (i + 1)))
        threads.append(threading.Thread(target=self._tcp_loop, name="tcp-accept"))
        threads.append(threading.Thread(target=self.http.serve_forever, name="http"))
        for t in threads:
            t.daemon = True
            t.start()
        self.threads = threads
        self._banner()

    def _banner(self):
        s = self.scfg
        lines = ["NodeWatch server %s" % VERSION,
                 "  UDP метрики    : %s:%s" % (s["bind"], s["udp_port"]),
                 "  TCP управление : %s:%s" % (s["bind"], s["tcp_port"]),
                 "  Потоков-обработчиков: %s, буфер на узел: %s точек" % (s["workers"], s["buffer_size"]),
                 "  Веб-панель (откройте с ПК, ноутбука или телефона в той же сети):"]
        ips = local_ipv4() if s["bind"] in ("0.0.0.0", "") else [s["bind"]]
        for ip in ips + ["127.0.0.1"]:
            lines.append("    http://%s:%s/#token=%s" % (ip, s["http_port"], self.token))
        for line in lines:
            log.info(line)

    def shutdown(self):
        self.stop.set()
        try:
            self.http.shutdown()
        except Exception:
            pass
        for sock in (self.udp, self.tcp):
            try:
                sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------ UDP
    def _udp_loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                continue   # Windows: ICMP «порт недоступен» приходит как ошибка recv
            self._count("udp_received")
            try:
                self.queue.put_nowait((data, addr, time.time()))
            except queue.Full:
                self._count("queue_drops")

    def _worker(self):
        while not self.stop.is_set():
            try:
                data, addr, received = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._process(data, addr, received)
            except Exception:
                log.exception("ошибка обработки пакета от %s", addr)
            finally:
                self.queue.task_done()

    def _process(self, data, addr, received):
        try:
            p = decode_packet(self.secret, data)
        except PacketError as exc:
            self._count("bad_hmac" if str(exc) in ("hmac", "magic") else "bad_format")
            return
        if abs(float(p["ts"]) - received) > float(self.scfg["max_clock_skew_s"]):
            self._count("stale")
            return
        node = str(p["node"])[:64]
        rec = self._record(node)
        with rec.lock:
            if not rec.window.check(str(p["boot"]), int(p["seq"])):
                self._count("replay")
                return
            rec.ip = addr[0]
            rec.last_seen = received
            rec.packets += 1
            rec.interval = p.get("iv")
            history = rec.buffer.snapshot()
            sample = {"ts": received, "ats": p["ts"], "seq": p["seq"], "iv": p.get("iv"), "m": p["m"]}
            rec.buffer.append(sample)
            findings = self.analyzer.evaluate(history, sample, rec.state, rec.os_name)
        self._count("processed")
        for f in findings:
            self.raise_incident(rec, f)

    # ------------------------------------------------------------ сторож
    def _watchdog(self):
        while not self.stop.wait(1.0):
            now = time.time()
            with self.agents_lock:
                records = list(self.agents.values())
            for rec in records:
                with rec.lock:
                    f = self.analyzer.check_silent(rec.silence_ref(), rec.paused, now, rec.state, rec.os_name)
                if f:
                    self.raise_incident(rec, f)

    def agent_status(self, rec, now):
        silent_limit = self.analyzer.silent_limit(rec.os_name)
        ref = rec.silence_ref()
        fresh = (rec.last_seen is not None and now - rec.last_seen <= silent_limit) or \
                (rec.link is not None and rec.resumed_at is not None and now - rec.resumed_at <= silent_limit)
        if rec.paused and rec.link is not None:
            return "paused"
        if fresh:
            return "online"
        recently = ref is not None and now - ref < float(self.scfg["offline_after_s"])
        if rec.link is not None or recently:
            return "silent"
        return "offline"

    # ------------------------------------------------------------ инциденты
    def raise_incident(self, rec, finding, source="analyzer"):
        tail = []
        for s in rec.buffer.snapshot(last=20):
            row = {"t": round(s["ts"], 1)}
            for key in TAIL_KEYS:
                row[key] = s["m"].get(key)
            tail.append(row)
        inc = {
            "ts": time.time(), "node": rec.node, "ip": rec.ip, "os": rec.os_name,
            "rule": finding["rule"], "severity": finding["severity"], "title": finding["title"],
            "evidence": finding["evidence"], "tail": tail, "snapshot": None,
            "snapshot_status": "pending" if rec.link else "агент не подключён по TCP",
            "status": "open", "ack_by": None, "ack_ts": None, "source": source,
        }
        self.store.add(inc)
        rec.incidents += 1
        if rec.link:
            self.snapshots.put((rec, inc["id"]))
        return inc

    def _snapshot_worker(self):
        """Запрашивает у агента снимок и дописывает его в карточку инцидента."""
        while not self.stop.is_set():
            try:
                rec, inc_id = self.snapshots.get(timeout=1.0)
            except queue.Empty:
                continue
            link = rec.link
            if link is None:
                self.store.update(inc_id, snapshot_status="агент отключился")
                continue
            try:
                snap = link.call("snapshot", timeout=8.0)
                self.store.update(inc_id, snapshot=snap, snapshot_status="ok")
            except Exception as exc:
                self.store.update(inc_id, snapshot_status="ошибка: %s" % exc)

    # ------------------------------------------------------------ TCP
    def _tcp_loop(self):
        while not self.stop.is_set():
            try:
                sock, addr = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._tcp_client, args=(sock, addr), daemon=True,
                             name="tcp-%s" % addr[0]).start()

    def _tcp_client(self, sock, addr):
        sock.settimeout(15)
        conn = JsonLineConn(sock)
        rec = None
        link = None
        try:
            n1 = new_nonce()
            conn.send({"type": "challenge", "nonce": n1, "server": "nodewatch", "v": VERSION})
            hello = conn.recv()
            role, name = hello.get("role"), str(hello.get("node", ""))[:64]
            expected = auth_mac(self.secret, role, n1, name, hello.get("cnonce", ""))
            if hello.get("type") != "hello" or role not in ("agent", "admin") or not name \
                    or not hmac.compare_digest(str(hello.get("mac", "")), expected):
                self._count("auth_failed")
                log.warning("TCP %s: аутентификация не пройдена (role=%s, node=%s)", addr[0], role, name)
                conn.send({"type": "error", "error": "auth failed"})
                return
            conn.send({"type": "welcome", "mac": auth_mac(self.secret, "server", hello["cnonce"], n1)})

            if role == "admin":
                sock.settimeout(900)
                log.info("CLI подключён: %s (%s)", name, addr[0])
                while True:
                    msg = conn.recv()
                    try:
                        data = self.execute(msg, source="cli:" + name)
                        conn.send({"type": "resp", "id": msg.get("id"), "ok": True, "data": data})
                    except (CommandError, ValueError, KeyError) as exc:
                        conn.send({"type": "resp", "id": msg.get("id"), "ok": False, "error": str(exc)})

            # role == agent
            rec = self._record(name)
            link = AgentLink(conn, addr)
            with rec.lock:
                old = rec.link
                rec.link = link
                rec.ip = rec.ip or addr[0]
                rec.last_tcp = time.time()
                self._apply_info(rec, hello.get("info") or {})
            if old:
                old.close()
            log.info("агент %s подключился по TCP с %s", name, addr[0])
            sock.settimeout(45)        # агент шлёт status каждые 10 с
            while True:
                msg = conn.recv()
                rec.last_tcp = time.time()
                if msg.get("type") == "resp":
                    link.resolve(msg)
                elif msg.get("type") == "status":
                    with rec.lock:
                        self._apply_info(rec, msg.get("info") or {})
        except (OSError, ConnectionError, ValueError) as exc:
            if rec is not None:
                log.info("агент %s: TCP закрыт (%s)", rec.node, exc)
        finally:
            if rec is not None and rec.link is link:
                with rec.lock:
                    rec.link = None
                    # агент отключился: его пауза больше не действует (новый запуск начнёт без паузы),
                    # молчание отсчитывается от момента отключения
                    rec.set_paused(False)
            conn.close()

    @staticmethod
    def _apply_info(rec, info):
        rec.info.update(info)
        rec.groups = list(info.get("groups", rec.groups))
        rec.set_paused(bool(info.get("paused", rec.paused)))
        if info.get("interval"):
            rec.interval = info["interval"]

    # ------------------------------------------------------------ команды
    def _targets(self, target):
        with self.agents_lock:
            records = list(self.agents.values())
        if target in ("*", "all"):
            return records
        if target.startswith("@"):
            group = target[1:]
            found = [r for r in records if group in r.groups]
        else:
            found = [r for r in records if r.node == target]
        if not found:
            raise CommandError("узел или группа не найдены: %s" % target)
        return found

    def agent_dict(self, rec, now):
        w = rec.window
        total = w.received + w.lost
        last = rec.buffer.snapshot(last=1)
        m = last[0]["m"] if last else {}
        return {
            "node": rec.node, "status": self.agent_status(rec, now), "ip": rec.ip,
            "os": rec.os_name, "os_release": rec.info.get("os_release", ""),
            "groups": rec.groups, "interval": rec.interval, "paused": rec.paused,
            "tcp": rec.link is not None, "last_seen": rec.last_seen,
            "age_s": round(now - rec.last_seen, 1) if rec.last_seen else None,
            "packets": rec.packets, "lost": w.lost, "replay": w.replay, "restarts": w.restarts,
            "loss_pct": round(100.0 * w.lost / total, 2) if total else 0.0,
            "buffer": len(rec.buffer), "buffer_cap": rec.buffer.capacity,
            "incidents": rec.incidents, "open_incidents": self.store.count_open(rec.node),
            "profile": self.thresholds.profile_for(rec.os_name),
            "version": rec.info.get("version", ""), "boot": w.boot,
            "last": {k: m.get(k) for k in ("cpu_total", "cpu_user", "net_total", "disk_total", "mem_pct",
                                           "proc_new_ps")},
        }

    def execute(self, msg, source="api"):
        """Единая точка выполнения команд для веб-панели, REST API и CLI."""
        cmd = msg.get("cmd")
        now = time.time()

        if cmd == "info":
            with self.stats_lock:
                stats = dict(self.stats)
            stats["queue"] = self.queue.qsize()
            return {"version": VERSION, "uptime_s": round(now - self.started), "stats": stats,
                    "ports": {k: self.scfg[k] for k in ("udp_port", "tcp_port", "http_port")},
                    "workers": self.scfg["workers"], "buffer_size": self.scfg["buffer_size"],
                    "rules": {k: {"severity": v[0], "title": v[1]} for k, v in RULES.items()}}

        if cmd == "agents":
            with self.agents_lock:
                records = sorted(self.agents.values(), key=lambda r: r.node)
            return [self.agent_dict(r, now) for r in records]

        if cmd == "report":
            node = msg.get("node")
            n = int(msg.get("n") or 300)
            if not node:
                with self.agents_lock:
                    records = sorted(self.agents.values(), key=lambda r: r.node)
                return {"nodes": [{"node": r.node, "status": self.agent_status(r, now),
                                   "summary": summarize(r.buffer.snapshot(), SUMMARY_KEYS)} for r in records]}
            rec = self._targets(node)[0]
            samples = rec.buffer.snapshot(last=n)
            series = {"t": [round(s["ts"], 2) for s in samples]}
            for key in CHART_KEYS:
                series[key] = [s["m"].get(key) for s in samples]
            return {"node": rec.node, "agent": self.agent_dict(rec, now),
                    "summary": summarize(samples, SUMMARY_KEYS), "series": series,
                    "cores": samples[-1]["m"].get("cpu_cores", []) if samples else []}

        if cmd == "incidents":
            return self.store.query(msg.get("node") or None, msg.get("rule") or None,
                                    msg.get("status") or None, int(msg.get("limit") or 200))

        if cmd == "incident":
            inc = self.store.get(str(msg.get("id")))
            if not inc:
                raise CommandError("инцидент не найден: %s" % msg.get("id"))
            return inc

        if cmd == "ack":
            inc = self.store.update(str(msg.get("id")), status="acknowledged",
                                    ack_by=msg.get("by") or source, ack_ts=now)
            if not inc:
                raise CommandError("инцидент не найден: %s" % msg.get("id"))
            log.info("инцидент %s подтверждён (%s)", inc["id"], inc["ack_by"])
            return {"id": inc["id"], "status": inc["status"]}

        if cmd == "agent":
            action = msg.get("action")
            if action not in ("pause", "resume", "interval", "snapshot", "groups", "ping", "status"):
                raise CommandError("неизвестное действие: %s" % action)
            results = {}
            for rec in self._targets(str(msg.get("node", ""))):
                link = rec.link
                if link is None:
                    results[rec.node] = {"ok": False, "error": "агент не подключён по TCP"}
                    continue
                kwargs = {}
                if action in ("interval", "groups"):
                    kwargs["value"] = msg.get("value")
                try:
                    data = link.call(action, timeout=10.0 if action == "snapshot" else 6.0, **kwargs)
                    with rec.lock:
                        if action == "pause":
                            rec.set_paused(True)
                        elif action == "resume":
                            rec.set_paused(False)
                        elif action == "interval":
                            rec.interval = data["interval"]
                        elif action == "groups":
                            rec.groups = data["groups"]
                    results[rec.node] = {"ok": True, "data": data}
                    log.info("команда %s -> %s выполнена (%s)", action, rec.node, source)
                except CommandError as exc:
                    results[rec.node] = {"ok": False, "error": str(exc)}
            return results

        if cmd == "thresholds":
            if msg.get("reset"):
                self.thresholds.reset()
                log.info("пороги сброшены к значениям по умолчанию (%s)", source)
            if msg.get("set"):
                changed = self.thresholds.update(msg["set"])
                log.info("пороги изменены (%s): %s", source, changed)
            return {"items": self.thresholds.describe(), "user": dict(self.thresholds.user)}

        if cmd == "test_incident":
            rule = msg.get("rule") or "TEST"
            if rule not in RULES:
                raise CommandError("неизвестное правило: %s" % rule)
            out = []
            for rec in self._targets(str(msg.get("node", ""))):
                sev, title = RULES[rule]
                inc = self.raise_incident(rec, {
                    "rule": rule, "severity": sev,
                    "title": title if rule == "TEST" else title + " (тест)",
                    "evidence": {"manual": True, "requested_by": source,
                                 "note": "Тестовый инцидент, создан вручную для проверки уведомлений"}},
                    source="test")
                out.append(inc["id"])
            return {"created": out}

        if cmd == "forget":
            node = str(msg.get("node", ""))
            with self.agents_lock:
                rec = self.agents.pop(node, None)
            if not rec:
                raise CommandError("узел не найден: %s" % node)
            if rec.link:
                rec.link.close()
            log.info("узел %s удалён из списка (%s)", node, source)
            return {"forgotten": node}

        if cmd == "events":
            last, events = self.store.events_since(int(msg.get("since") or 0))
            with self.agents_lock:
                records = list(self.agents.values())
            online = sum(1 for r in records if self.agent_status(r, now) == "online")
            return {"last": last, "events": events, "open": self.store.count_open(),
                    "agents_online": online, "agents_total": len(records)}

        raise CommandError("неизвестная команда: %s" % cmd)


# ====================================================================== HTTP
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
                 ".ico": "image/x-icon", ".json": "application/json"}


READ_ONLY = {"info", "agents", "report", "incidents", "incident", "thresholds", "events"}


class PanelHandler(BaseHTTPRequestHandler):
    """Статика веб-панели + JSON API. Все /api/* требуют токен."""
    server_ref = None
    server_version = "NodeWatch/" + VERSION

    def log_message(self, fmt, *args):
        log.debug("http %s " + fmt, self.client_address[0], *args)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self, query):
        token = self.headers.get("X-Token") or (query.get("token") or [""])[0]
        return hmac.compare_digest(token.encode(), self.server_ref.token.encode())

    def _api(self, msg, query):
        if not self._authorized(query):
            self._json(401, {"ok": False, "error": "unauthorized: нужен токен из лога сервера"})
            return
        try:
            data = self.server_ref.execute(msg, source="web:" + self.client_address[0])
            self._json(200, {"ok": True, "data": data})
        except (CommandError, ValueError, KeyError, TypeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})
        except Exception as exc:
            log.exception("ошибка API")
            self._json(500, {"ok": False, "error": str(exc)})

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path.startswith("/api/"):
            msg = {k: v[0] for k, v in query.items() if k not in ("token", "set", "reset")}
            msg["cmd"] = url.path[5:].strip("/")
            if msg["cmd"] not in READ_ONLY:       # действия — только через POST /api/cmd
                return self._json(405, {"ok": False, "error": "use POST /api/cmd"})
            return self._api(msg, query)
        self._static(url.path)

    def do_POST(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if not url.path.startswith("/api/"):
            return self._json(404, {"ok": False, "error": "not found"})
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 1 << 20)
            msg = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except ValueError:
            return self._json(400, {"ok": False, "error": "bad json"})
        name = url.path[5:].strip("/")
        if name and name != "cmd":
            msg["cmd"] = name
        self._api(msg, query)

    def _static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
        if not full.startswith(WEB_DIR) or not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ====================================================================== main
def setup_logging(data_dir, verbose=False):
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)-10s %(message)s", "%H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)
    os.makedirs(data_dir, exist_ok=True)
    fileh = logging.handlers.RotatingFileHandler(os.path.join(data_dir, "server.log"), maxBytes=2 << 20,
                                                 backupCount=3, encoding="utf-8")
    fileh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)-10s %(message)s"))
    root.addHandler(fileh)


def main():
    fix_console()
    ap = argparse.ArgumentParser(description="Сервер мониторинга NodeWatch")
    ap.add_argument("--config", help="путь к config.json")
    ap.add_argument("--bind", help="адрес прослушивания (по умолчанию 0.0.0.0)")
    ap.add_argument("--http-port", type=int)
    ap.add_argument("--udp-port", type=int)
    ap.add_argument("--tcp-port", type=int)
    ap.add_argument("--workers", type=int)
    ap.add_argument("--secret", help="общий секрет (лучше через MON_SECRET)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    cfg = load_config(args.config)
    if args.secret:
        cfg["secret"] = args.secret
    for key in ("bind", "http_port", "udp_port", "tcp_port", "workers"):
        if getattr(args, key) is not None:
            cfg["server"][key] = getattr(args, key)
    data_dir = cfg["server"]["data_dir"]
    setup_logging(data_dir if os.path.isabs(data_dir) else os.path.join(HERE, data_dir), args.verbose)
    srv = MonitorServer(cfg)
    try:
        srv.start()
    except OSError as exc:
        log.error("не удалось открыть порт: %s (порт занят или нет прав)", exc)
        return 1
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("остановка сервера…")
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
