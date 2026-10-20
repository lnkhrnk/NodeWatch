"""Модульные и интеграционные тесты NodeWatch (только стандартный unittest).

Запуск:  python -m unittest discover -s tests -v
"""
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyzer  # noqa: E402
import common    # noqa: E402

SECRET = b"unit-test-secret"


def sample(ts, **m):
    base = {"cpu_user": 5.0, "net_total": 20_000.0, "disk_total": 50_000.0, "proc_new_ps": 1.0,
            "thr_new_ps": 5.0, "mem_used": 4000.0, "mem_total": 16000.0, "mem_delta": 0.0}
    base.update(m)
    return {"ts": ts, "iv": 2.0, "m": base}


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class PacketTests(unittest.TestCase):
    def test_roundtrip(self):
        payload = {"node": "n1", "boot": "ab", "seq": 1, "ts": 1.0, "m": {"cpu_user": 3.5}}
        self.assertEqual(common.decode_packet(SECRET, common.encode_packet(SECRET, payload)), payload)

    def test_wrong_secret_rejected(self):
        data = common.encode_packet(SECRET, {"node": "n", "boot": "b", "seq": 1, "ts": 1, "m": {}})
        with self.assertRaises(common.PacketError):
            common.decode_packet(b"another-secret", data)

    def test_tampered_packet_rejected(self):
        data = bytearray(common.encode_packet(SECRET, {"node": "n", "boot": "b", "seq": 1, "ts": 1, "m": {}}))
        data[-1] ^= 0xFF
        with self.assertRaises(common.PacketError):
            common.decode_packet(SECRET, bytes(data))

    def test_packet_is_compressed(self):
        payload = {"node": "n", "boot": "b", "seq": 1, "ts": 1, "m": {"cpu_cores": [12.5] * 64}}
        self.assertLess(len(common.encode_packet(SECRET, payload)), len(json.dumps(payload)))


class SeqWindowTests(unittest.TestCase):
    def test_loss_and_replay(self):
        w = common.SeqWindow()
        for seq in (1, 2, 3, 6):
            self.assertTrue(w.check("boot1", seq))
        self.assertEqual(w.lost, 2)              # потеряны 4 и 5
        self.assertFalse(w.check("boot1", 3))    # повтор
        self.assertEqual(w.replay, 1)
        self.assertTrue(w.check("boot1", 5))     # опоздавший пакет снимает потерю
        self.assertEqual(w.lost, 1)

    def test_agent_restart_and_old_boot(self):
        w = common.SeqWindow()
        w.check("old", 10)
        self.assertTrue(w.check("new", 1))       # перезапуск агента: seq снова с 1
        self.assertEqual(w.restarts, 1)
        self.assertFalse(w.check("old", 11))     # пакет прошлого запуска — replay


class StatsTests(unittest.TestCase):
    def test_median_mad(self):
        vals = [1, 2, 3, 4, 100]
        self.assertEqual(analyzer.median(vals), 3)
        self.assertEqual(analyzer.mad(vals), 1)

    def test_robust_z_ignores_outlier(self):
        vals = [10.0] * 50 + [1000.0] * 3       # выбросы почти не сдвигают медиану
        med = analyzer.median(vals)
        self.assertEqual(med, 10.0)
        self.assertGreater(analyzer.robust_z(50, med, analyzer.mad(vals, med), 1.0), 20)

    def test_ring_buffer_bounded(self):
        buf = analyzer.RingBuffer(10)
        for i in range(25):
            buf.append(i)
        self.assertEqual(len(buf), 10)
        self.assertEqual(buf.snapshot()[0], 15)

    def test_baseline_excludes_last_points(self):
        th = analyzer.Thresholds().effective()
        hist = [sample(i) for i in range(40)] + [sample(40 + i, net_total=9e6) for i in range(5)]
        base = analyzer.Baseline(hist, th)
        self.assertTrue(all(s["m"]["net_total"] < 1e6 for s in base.samples))


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.th = analyzer.Thresholds()
        self.an = analyzer.Analyzer(self.th)
        self.state = analyzer.NodeState()
        self.hist = [sample(i * 2.0, net_total=20_000 + (i % 5) * 1000, proc_new_ps=1 + (i % 3) * 0.3)
                     for i in range(60)]

    def run_points(self, points):
        found = []
        for p in points:
            found += self.an.evaluate(self.hist, p, self.state)
            self.hist.append(p)
        return [f["rule"] for f in found]

    def test_quiet_node_has_no_incidents(self):
        self.assertEqual(self.run_points([sample(200 + i, net_total=21_000) for i in range(10)]), [])

    def test_net_low_cpu_needs_duration(self):
        short = self.run_points([sample(200 + i, net_total=3e6, cpu_user=3) for i in range(3)])
        self.assertEqual(short, [])
        longer = self.run_points([sample(210 + i, net_total=3e6, cpu_user=3) for i in range(3)])
        self.assertIn("NET_LOW_CPU", longer)

    def test_net_with_high_cpu_is_not_suspicious(self):
        self.assertNotIn("NET_LOW_CPU", self.run_points([sample(200 + i, net_total=3e6, cpu_user=80) for i in range(8)]))

    def test_proc_burst(self):
        self.assertIn("PROC_BURST", self.run_points([sample(200, proc_new_ps=12)]))

    def test_disk_net_combo(self):
        rules = self.run_points([sample(200 + i, net_total=2e6, disk_total=40e6, cpu_user=60) for i in range(4)])
        self.assertIn("DISK_NET_COMBO", rules)

    def test_mem_jump(self):
        self.assertIn("MEM_JUMP", self.run_points([sample(200, mem_used=5200, mem_delta=1200)]))

    def test_cooldown(self):
        rules = self.run_points([sample(200 + i, proc_new_ps=40) for i in range(5)])
        self.assertEqual(rules.count("PROC_BURST"), 1)

    def test_thresholds_on_the_fly(self):
        self.th.update({"burst_enabled": False})
        self.assertEqual(self.run_points([sample(200, proc_new_ps=40)]), [])
        with self.assertRaises(ValueError):
            self.th.update({"no_such_key": 1})

    def test_windows_profile(self):
        self.assertEqual(self.th.profile_for("Windows"), "windows")
        self.assertEqual(self.th.effective("Windows")["burst_hard_proc_ps"], 15.0)
        self.assertEqual(self.th.effective("Linux")["burst_hard_proc_ps"], 25.0)

    def test_agent_silent_respects_pause(self):
        st = analyzer.NodeState()
        self.assertIsNone(self.an.check_silent(100.0, True, 200.0, st))
        f = self.an.check_silent(100.0, False, 200.0, st)
        self.assertEqual(f["rule"], "AGENT_SILENT")
        self.assertIsNone(self.an.check_silent(100.0, False, 201.0, st))   # один раз на эпизод


class ServerIntegrationTests(unittest.TestCase):
    """Поднимает настоящий сервер на свободных портах и общается с ним по UDP/TCP/HTTP."""

    @classmethod
    def setUpClass(cls):
        import server
        cls.tmp = tempfile.mkdtemp()
        cfg = common.load_config(os.path.join(cls.tmp, "none.json"))
        cfg["secret"] = SECRET.decode()
        cfg["server"].update({"bind": "127.0.0.1", "udp_port": free_port(socket.SOCK_DGRAM),
                              "tcp_port": free_port(), "http_port": free_port(), "data_dir": cls.tmp})
        cls.cfg = cfg
        cls.srv = server.MonitorServer(cfg)
        cls.srv.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def send(self, seq, node="itest", secret=SECRET, **m):
        pkt = common.encode_packet(secret, {"node": node, "boot": "b1", "seq": seq, "ts": time.time(),
                                            "iv": 1.0, "m": sample(0, **m)["m"]})
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(pkt, ("127.0.0.1", self.cfg["server"]["udp_port"]))
        s.close()

    def wait_for(self, cond, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_udp_metrics_and_admin_tcp(self):
        for seq in (1, 2, 4):
            self.send(seq)
        self.send(2)                                    # повтор
        self.send(5, secret=b"bad-secret-123")          # чужой пакет
        self.assertTrue(self.wait_for(lambda: "itest" in self.srv.agents and self.srv.agents["itest"].packets == 3))
        conn = common.connect_admin("127.0.0.1", self.cfg["server"]["tcp_port"], SECRET)
        conn.send({"type": "cmd", "id": 1, "cmd": "agents"})
        agents = {a["node"]: a for a in conn.recv()["data"]}
        conn.close()
        self.assertEqual(agents["itest"]["lost"], 1)
        self.assertEqual(agents["itest"]["replay"], 1)
        self.assertTrue(self.wait_for(lambda: self.srv.stats["bad_hmac"] >= 1))

    def test_resume_after_long_pause_is_not_silent(self):
        import server
        rec = server.AgentRecord("paused-node", 50)
        rec.last_seen = time.time() - 600          # пакеты не шли 10 минут — агент был на паузе
        rec.paused = True
        rec.link = object()                        # TCP-канал управления активен
        rec.set_paused(False)                      # команда «Продолжить»
        st = analyzer.NodeState()
        self.assertIsNone(self.srv.analyzer.check_silent(rec.silence_ref(), rec.paused, time.time(), st))
        self.assertEqual(self.srv.agent_status(rec, time.time()), "online")

    def test_admin_with_wrong_secret_fails(self):
        with self.assertRaises(PermissionError):
            common.connect_admin("127.0.0.1", self.cfg["server"]["tcp_port"], b"wrong-secret-000")

    def test_http_requires_token_and_ack(self):
        base = "http://127.0.0.1:%d/api/" % self.cfg["server"]["http_port"]
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(base + "agents")
        self.assertEqual(ctx.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as ctx:      # действия через GET запрещены
            urllib.request.urlopen(urllib.request.Request(base + "forget?node=x", headers={"X-Token": self.srv.token}))
        self.assertEqual(ctx.exception.code, 405)
        self.send(1, node="web-node")
        self.assertTrue(self.wait_for(lambda: "web-node" in self.srv.agents))

        def call(body):
            req = urllib.request.Request(base + "cmd", data=json.dumps(body).encode(),
                                         headers={"X-Token": self.srv.token, "Content-Type": "application/json"})
            return json.loads(urllib.request.urlopen(req).read())["data"]

        inc_id = call({"cmd": "test_incident", "node": "web-node"})["created"][0]
        self.assertEqual(call({"cmd": "incident", "id": inc_id})["status"], "open")
        call({"cmd": "ack", "id": inc_id})
        self.assertEqual(call({"cmd": "incidents", "status": "acknowledged"})[0]["id"], inc_id)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "incidents", inc_id + ".json")))
        with open(os.path.join(self.tmp, "alerts.log"), encoding="utf-8") as fh:
            self.assertIn(inc_id, fh.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
