"""Общие компоненты системы мониторинга NodeWatch.

Здесь собрано всё, что нужно и агенту, и серверу, и CLI:
  * загрузка конфигурации (файл config.json + переменная окружения MON_SECRET);
  * формат UDP-пакета с метриками: HMAC-SHA256 + сжатие zlib;
  * протокол TCP-управления: JSON-строки (одна строка = одно сообщение);
  * взаимная аутентификация «запрос-ответ» (challenge-response) по общему секрету.
Секрет никогда не передаётся по сети: стороны обмениваются только случайными
числами (nonce) и HMAC от них.
"""
import copy
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import sys
import threading
import time
import zlib

VERSION = "1.0"

MAGIC = b"NWM1"              # сигнатура UDP-пакета
HEADER = struct.Struct("!4s32s")  # сигнатура + HMAC-SHA256
MAX_DATAGRAM = 60000

DEFAULT_CONFIG = {
    "secret": "",
    "server": {
        "bind": "0.0.0.0",
        "udp_port": 9999,
        "tcp_port": 9998,
        "http_port": 8080,
        "workers": 4,
        "queue_size": 10000,
        "buffer_size": 900,
        "data_dir": "data",
        "offline_after_s": 60,
        "max_clock_skew_s": 600,
        "web_token": "",
        "smtp": {
            "enabled": False,
            "host": "smtp.example.com",
            "port": 587,
            "starttls": True,
            "user": "",
            "password": "",
            "from": "monitor@example.com",
            "to": ["admin@example.com"],
        },
    },
    "agent": {
        "host": "127.0.0.1",
        "udp_port": 9999,
        "tcp_port": 9998,
        "node": "",
        "interval": 2.0,
        "groups": ["default"],
        "include_loopback": False,
    },
    "thresholds": {},
}


# ---------------------------------------------------------------- конфигурация
def _merge(dst, src):
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _merge(dst[key], value)
        else:
            dst[key] = value
    return dst


def load_config(path=None):
    """Читает config.json (если есть) поверх значений по умолчанию.

    Секрет берётся в порядке приоритета: переменная окружения MON_SECRET,
    поле "secret" файла конфигурации.
    """
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "config.json")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            _merge(cfg, json.load(fh))
    env_secret = os.environ.get("MON_SECRET", "").strip()
    if env_secret:
        cfg["secret"] = env_secret
    return cfg


def require_secret(cfg):
    secret = (cfg.get("secret") or "").strip()
    if len(secret) < 8:
        sys.exit("Ошибка: не задан общий секрет (MON_SECRET или \"secret\" в "
                 "config.json), минимум 8 символов.")
    return secret.encode("utf-8")


def panel_token(secret, override=""):
    """Токен веб-панели. Выводится из секрета, поэтому одинаков после перезапуска."""
    if override:
        return override
    return hmac.new(secret, b"nodewatch-web-panel", hashlib.sha256).hexdigest()[:32]


def fix_console():
    """Чтобы русский текст не ломал вывод в старой консоли Windows."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


# ---------------------------------------------------------------- UDP-пакеты
class PacketError(ValueError):
    pass


def encode_packet(secret, payload):
    """dict -> bytes: MAGIC | HMAC(secret, MAGIC+body) | zlib(json)."""
    body = zlib.compress(json.dumps(payload, separators=(",", ":")).encode("utf-8"), 6)
    mac = hmac.new(secret, MAGIC + body, hashlib.sha256).digest()
    return HEADER.pack(MAGIC, mac) + body


def decode_packet(secret, data):
    """bytes -> dict. Бросает PacketError, если пакет чужой или изменён."""
    if len(data) <= HEADER.size:
        raise PacketError("short")
    magic, mac = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise PacketError("magic")
    body = data[HEADER.size:]
    expected = hmac.new(secret, MAGIC + body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise PacketError("hmac")
    try:
        payload = json.loads(zlib.decompress(body).decode("utf-8"))
    except Exception:
        raise PacketError("format")
    for key in ("node", "boot", "seq", "ts", "m"):
        if key not in payload:
            raise PacketError("format")
    return payload


class SeqWindow:
    """Учёт потерь и защита от повтора (replay) по номеру пакета.

    Окно из последних 64 номеров (как в IPsec): номер, который уже был,
    или слишком старый номер считается повтором. Пропуски считаются
    потерями; если «потерянный» пакет пришёл позже — потеря снимается.
    """
    SIZE = 64

    def __init__(self):
        self.boot = None
        self.old_boots = []
        self.max_seq = -1
        self.mask = 0
        self.received = 0
        self.lost = 0
        self.replay = 0
        self.restarts = 0

    def check(self, boot, seq):
        """Возвращает True, если пакет новый и его нужно принять."""
        if boot != self.boot:
            if boot in self.old_boots:          # пакет от прошлого запуска агента
                self.replay += 1
                return False
            if self.boot is not None:
                self.old_boots = (self.old_boots + [self.boot])[-8:]
                self.restarts += 1
            self.boot, self.max_seq, self.mask = boot, -1, 0
        if seq > self.max_seq:
            gap = seq - self.max_seq - 1 if self.max_seq >= 0 else 0
            self.lost += gap
            shift = seq - self.max_seq
            self.mask = ((self.mask << shift) | 1) & ((1 << self.SIZE) - 1) if shift < self.SIZE else 1
            self.max_seq = seq
            self.received += 1
            return True
        offset = self.max_seq - seq
        if offset >= self.SIZE or self.mask & (1 << offset):
            self.replay += 1
            return False
        self.mask |= 1 << offset                 # опоздавший, но не повторный пакет
        self.lost = max(0, self.lost - 1)
        self.received += 1
        return True


# ---------------------------------------------------------------- TCP JSON-lines
class JsonLineConn:
    """Обёртка над TCP-сокетом: отправка/приём словарей построчно."""

    def __init__(self, sock):
        self.sock = sock
        self.file = sock.makefile("rb")
        self._send_lock = threading.Lock()

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._send_lock:
            self.sock.sendall(data)

    def recv(self):
        line = self.file.readline(1 << 20)
        if not line:
            raise ConnectionError("connection closed")
        return json.loads(line.decode("utf-8"))

    def close(self):
        for obj in (self.file, self.sock):
            try:
                obj.close()
            except Exception:
                pass


def new_nonce():
    return secrets.token_hex(16)


def auth_mac(secret, *parts):
    msg = "|".join(str(p) for p in parts).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def client_handshake(conn, secret, role, name, info=None):
    """Клиентская сторона рукопожатия (агент или CLI).

    1) сервер присылает challenge с nonce N1;
    2) клиент отвечает HMAC(role|N1|name|N2) и своим nonce N2;
    3) сервер доказывает знание секрета: HMAC(server|N2|N1).
    """
    msg = conn.recv()
    if msg.get("type") != "challenge":
        raise ConnectionError("protocol: expected challenge")
    n1 = msg["nonce"]
    n2 = new_nonce()
    conn.send({"type": "hello", "role": role, "node": name, "cnonce": n2,
               "mac": auth_mac(secret, role, n1, name, n2), "info": info or {}})
    reply = conn.recv()
    if reply.get("type") != "welcome":
        raise PermissionError(reply.get("error", "auth failed"))
    if not hmac.compare_digest(reply.get("mac", ""), auth_mac(secret, "server", n2, n1)):
        raise PermissionError("server failed to prove the secret")
    return reply


def connect_admin(host, port, secret, timeout=10.0):
    sock = socket.create_connection((host, port), timeout=timeout)
    conn = JsonLineConn(sock)
    try:
        client_handshake(conn, secret, "admin", "cli@" + socket.gethostname())
    except Exception:
        conn.close()
        raise
    sock.settimeout(None)
    return conn


def local_ipv4():
    """Список IPv4-адресов машины (для подсказки адреса панели)."""
    result = []
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                    result.append(a.address)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))     # пакет не отправляется, только выбор маршрута
        primary = s.getsockname()[0]
        s.close()
        if primary in result:
            result.remove(primary)
        result.insert(0, primary)
    except Exception:
        pass
    return result or ["127.0.0.1"]


def now():
    return time.time()
