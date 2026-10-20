"""Нагрузочный тест сервера: эмулирует много узлов и шлёт подписанные пакеты с заданной частотой.

Запускает отдельный экземпляр сервера на свободных портах (не мешает рабочему),
отправляет пакеты от NODES виртуальных узлов и затем читает статистику командой info.

  python scripts/load_test.py                    (500 узлов, 500/2000/5000 пакетов/с, 1 и 4 потока)
  python scripts/load_test.py --nodes 200 --rates 1000 --workers 4
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import common  # noqa: E402

SECRET = b"load-test-secret-123"
METRICS = {"cpu_user": 5.0, "cpu_total": 7.0, "cpu_cores": [5.0] * 8, "net_total": 20000.0, "disk_total": 5e4,
           "proc_new_ps": 1.0, "thr_new_ps": 4.0, "mem_used": 4000.0, "mem_total": 16000.0, "mem_delta": 0.0}


def run_case(workers, rate, nodes, seconds, port):
    tmp = tempfile.mkdtemp()
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as fh:
        json.dump({"server": {"data_dir": tmp}}, fh)
    env = dict(os.environ, MON_SECRET=SECRET.decode())
    srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--config", cfg_path, "--bind", "127.0.0.1",
                            "--udp-port", str(port), "--tcp-port", str(port + 1), "--http-port", str(port + 2),
                            "--workers", str(workers)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent, seq, t0 = 0, 0, time.time()
    while time.time() - t0 < seconds:
        seq += 1
        round_start = time.time()
        for n in range(nodes):
            pkt = common.encode_packet(SECRET, {"node": "v%04d" % n, "boot": "b", "seq": seq, "ts": time.time(),
                                                "iv": 2, "m": METRICS})
            sock.sendto(pkt, ("127.0.0.1", port))
            sent += 1
        wait = nodes / rate - (time.time() - round_start)   # держим заданную частоту
        if wait > 0:
            time.sleep(wait)
    elapsed = time.time() - t0
    time.sleep(1.5)
    conn = common.connect_admin("127.0.0.1", port + 1, SECRET)
    conn.send({"type": "cmd", "id": 1, "cmd": "info"})
    stats = conn.recv()["data"]["stats"]
    conn.close()
    srv.terminate()
    srv.wait()
    return {"workers": workers, "rate": round(sent / elapsed), "sent": sent, "processed": stats["processed"],
            "loss_pct": round(100.0 * (sent - stats["processed"]) / sent, 2), "queue_drops": stats["queue_drops"]}


def main():
    common.fix_console()
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=500)
    ap.add_argument("--rates", default="500,2000,5000", help="пакетов в секунду через запятую")
    ap.add_argument("--workers", default="1,4", help="числа потоков-обработчиков через запятую")
    ap.add_argument("--seconds", type=int, default=6)
    args = ap.parse_args()
    port = 31000
    print("потоки  пакетов/с  отправлено  обработано  потери,%  переполнения очереди")
    for w in [int(x) for x in args.workers.split(",")]:
        for r in [int(x) for x in args.rates.split(",")]:
            res = run_case(w, r, args.nodes, args.seconds, port)
            port += 10
            print("%6d  %9d  %10d  %10d  %8.2f  %d" % (res["workers"], res["rate"], res["sent"], res["processed"],
                                                       res["loss_pct"], res["queue_drops"]))


if __name__ == "__main__":
    main()
