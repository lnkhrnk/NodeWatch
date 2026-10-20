"""Демонстрационная нагрузка для защиты: провоцирует правила анализатора.

Запускать на узле, где работает агент (без прав администратора):
  python scripts/demo_load.py mem              скачок памяти            -> MEM_JUMP
  python scripts/demo_load.py proc             всплеск процессов        -> PROC_BURST
  python scripts/demo_load.py threads          всплеск потоков          -> PROC_BURST
  python scripts/demo_load.py net --host IP    долгий трафик, CPU низкий -> NET_LOW_CPU
  python scripts/demo_load.py combo --host IP  диск + сеть одновременно -> DISK_NET_COMBO

Для net/combo укажите IP ДРУГОГО компьютера (сервера): трафик на свой же
адрес идёт через loopback, а агент loopback не учитывает.
Перед демонстрацией дайте агенту поработать ~1 минуту, чтобы накопилась норма.
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time


def mem(args):
    try:
        import psutil
        total_mb = psutil.virtual_memory().total / 2 ** 20
    except ImportError:
        total_mb = 8192
    size = int(args.mb or min(max(total_mb * 0.12, 600), 3072))
    print("занимаю %d МБ памяти на %d с…" % (size, args.seconds))
    blocks = [bytearray(os.urandom(1) * (64 << 20)) for _ in range(size // 64)]
    for b in blocks:                       # реально касаемся страниц памяти
        for i in range(0, len(b), 4096):
            b[i] = 1
    time.sleep(args.seconds)
    del blocks
    print("память освобождена")


def proc(args):
    rate = args.rate or 20
    print("запускаю ~%d процессов в секунду в течение %d с…" % (rate, args.seconds))
    children = []
    end = time.time() + args.seconds
    while time.time() < end:
        t0 = time.time()
        children.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"]))
        time.sleep(max(0.0, 1.0 / rate - (time.time() - t0)))
    for c in children:
        c.wait()
    print("готово, запущено процессов: %d" % len(children))


def threads(args):
    n = int(args.rate or 400)
    print("создаю %d потоков…" % n)
    pool = [threading.Thread(target=time.sleep, args=(args.seconds,)) for _ in range(n)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    print("готово")


def net(args, stop=None):
    if not args.host:
        sys.exit("укажите --host IP другого компьютера")
    rate_kb = args.rate or 2048
    print("отправляю ~%d КБ/с на %s:%d в течение %d с (CPU почти не нагружается)…"
          % (rate_kb, args.host, args.port, args.seconds))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = os.urandom(1200)
    per_tick = max(1, int(rate_kb * 1024 / len(payload) / 50))   # 50 «тиков» в секунду
    end = time.time() + args.seconds
    while time.time() < end and not (stop and stop.is_set()):
        for _ in range(per_tick):
            try:
                sock.sendto(payload, (args.host, args.port))
            except OSError:
                pass
        time.sleep(0.02)
    print("трафик остановлен")


def disk(args):
    path = os.path.join(tempfile.gettempdir(), "nodewatch_demo.bin")
    chunk = os.urandom(4 << 20)
    end = time.time() + args.seconds
    written = 0
    while time.time() < end:
        with open(path, "wb") as fh:
            for _ in range(8):
                fh.write(chunk)
                written += len(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        time.sleep(0.05)
    os.remove(path)
    print("записано на диск: %d МБ" % (written >> 20))


def combo(args):
    t = threading.Thread(target=net, args=(args,))
    t.start()
    disk(args)
    t.join()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["mem", "proc", "threads", "net", "disk", "combo"])
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--host", help="IP другого компьютера (для net/combo)")
    ap.add_argument("--port", type=int, default=9, help="UDP-порт получателя (по умолчанию 9 — discard)")
    ap.add_argument("--rate", type=float, help="КБ/с для net, процессов/с для proc, число потоков для threads")
    ap.add_argument("--mb", type=int, help="сколько МБ занять в режиме mem")
    args = ap.parse_args()
    {"mem": mem, "proc": proc, "threads": threads, "net": net, "disk": disk, "combo": combo}[args.mode](args)


if __name__ == "__main__":
    main()
