"""Потоковый статистический анализ метрик узлов.

Основа — робастная статистика: медиана и MAD (медиана абсолютных
отклонений). В отличие от среднего и СКО они почти не меняются, если в
данных есть выбросы, поэтому сама атака не «портит» представление о норме.
Дополнительно база (baseline) строится без последних N точек: свежие
аномальные значения не попадают в оценку нормы, с которой их сравнивают.

robust_z = 0.6745 * (x - median) / MAD
(коэффициент 0.6745 приводит MAD к шкале СКО нормального распределения).
"""
import json
import math
import os
import threading
from collections import deque

# ------------------------------------------------------------------ пороги
# (ключ, значение по умолчанию, тип, группа, подпись)
THRESHOLD_SPEC = [
    ("profile", "auto", "choice", "Общие", "Профиль порогов (auto — по ОС агента)"),
    ("adaptive", False, "bool", "Общие", "Адаптивный режим: поднимать абсолютные пороги до p95 нормы узла × k"),
    ("adaptive_k", 1.5, "float", "Общие", "Множитель k адаптивного режима"),
    ("warmup_points", 15, "int", "Общие", "Точек в базе до включения z-оценок"),
    ("baseline_window", 300, "int", "Общие", "Размер базы (точек)"),
    ("exclude_last", 5, "int", "Общие", "Не включать в базу последние N точек"),
    ("cooldown_s", 30, "int", "Общие", "Пауза между одинаковыми инцидентами узла, с"),

    ("net_enabled", True, "bool", "NET_LOW_CPU", "Правило включено"),
    ("net_z", 4.0, "float", "NET_LOW_CPU", "Порог z-score сетевого трафика"),
    ("net_min_kbps", 256.0, "float", "NET_LOW_CPU", "Минимальный трафик, КБ/с"),
    ("low_cpu_user", 25.0, "float", "NET_LOW_CPU", "user CPU не выше, %"),
    ("net_sustain", 5, "int", "NET_LOW_CPU", "Сколько точек подряд (длительность)"),

    ("burst_enabled", True, "bool", "PROC_BURST", "Правило включено"),
    ("burst_z", 5.0, "float", "PROC_BURST", "Порог z-score частоты процессов/потоков"),
    ("burst_min_proc_ps", 5.0, "float", "PROC_BURST", "Минимум новых процессов в секунду"),
    ("burst_min_thr_ps", 40.0, "float", "PROC_BURST", "Минимум новых потоков в секунду"),
    ("burst_hard_proc_ps", 25.0, "float", "PROC_BURST", "Жёсткий порог процессов/с (без z)"),

    ("combo_enabled", True, "bool", "DISK_NET_COMBO", "Правило включено"),
    ("combo_z", 3.5, "float", "DISK_NET_COMBO", "Порог z-score диска и сети"),
    ("combo_disk_min_kbps", 4096.0, "float", "DISK_NET_COMBO", "Минимум дисковой активности, КБ/с"),
    ("combo_net_min_kbps", 256.0, "float", "DISK_NET_COMBO", "Минимум сетевой активности, КБ/с"),
    ("combo_sustain", 3, "int", "DISK_NET_COMBO", "Сколько точек подряд"),

    ("mem_enabled", True, "bool", "MEM_JUMP", "Правило включено"),
    ("mem_jump_pct", 5.0, "float", "MEM_JUMP", "Скачок занятой RAM, % от объёма"),
    ("mem_window", 3, "int", "MEM_JUMP", "Окно скачка (точек)"),
    ("mem_z", 6.0, "float", "MEM_JUMP", "Порог z-score mem_delta"),
    ("mem_jump_min_mb", 400.0, "float", "MEM_JUMP", "Минимальный mem_delta для z-проверки, МБ"),

    ("silent_enabled", True, "bool", "AGENT_SILENT", "Правило включено"),
    ("silent_min_s", 15.0, "float", "AGENT_SILENT", "Нет UDP-метрик дольше, с"),
    ("silent_ignore_paused", True, "bool", "AGENT_SILENT", "Не считать молчанием паузу по команде"),
]
CHOICES = {"profile": ["auto", "default", "windows"]}

# На Windows новые процессы считаются по разнице списков PID (короткоживущие
# процессы между замерами не видны), а фоновая активность служб выше.
PROFILES = {
    "default": {},
    "windows": {
        "burst_min_proc_ps": 3.0,
        "burst_hard_proc_ps": 15.0,
        "burst_min_thr_ps": 80.0,
        "net_min_kbps": 384.0,
        "low_cpu_user": 30.0,
    },
}

RULES = {
    "NET_LOW_CPU": ("high", "Длительный высокий сетевой трафик при низкой пользовательской нагрузке"),
    "PROC_BURST": ("medium", "Всплеск создания процессов/потоков"),
    "DISK_NET_COMBO": ("high", "Одновременно высокая дисковая и сетевая активность"),
    "MEM_JUMP": ("medium", "Резкий скачок потребления памяти"),
    "AGENT_SILENT": ("medium", "Агент перестал присылать метрики"),
    "TEST": ("low", "Тестовый инцидент"),
}

# Нижняя граница MAD: при «ровном» ряде MAD = 0 и любое изменение дало бы z = ∞.
MAD_FLOOR = {
    "net_total": 4096.0, "disk_total": 65536.0, "cpu_user": 2.0,
    "proc_new_ps": 0.5, "thr_new_ps": 3.0, "mem_delta": 16.0,
}

CHART_KEYS = ["cpu_user", "cpu_total", "net_total", "net_in", "net_out", "disk_total",
              "disk_iops", "mem_used", "mem_delta", "proc_new_ps", "thr_new_ps"]


class Thresholds:
    """Пороги: значения по умолчанию ⊕ профиль ⊕ правки администратора."""

    def __init__(self, path=None, initial=None):
        self.path = path
        self.spec = {k: (d, t, g, label) for k, d, t, g, label in THRESHOLD_SPEC}
        self.user = {}
        self.lock = threading.Lock()
        if initial:                      # пороги из config.json
            self.user.update(self._validate(initial))
        if path and os.path.exists(path):  # правки из панели важнее
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self.user.update(self._validate(json.load(fh)))
            except Exception:
                pass

    def _validate(self, changes):
        clean = {}
        for key, value in changes.items():
            if key not in self.spec:
                raise ValueError("неизвестный параметр: %s" % key)
            kind = self.spec[key][1]
            if kind == "bool":
                if isinstance(value, str):
                    value = value.strip().lower() in ("1", "true", "yes", "on", "да")
                value = bool(value)
            elif kind == "int":
                value = int(float(value))
                if value < 0:
                    raise ValueError("%s: значение должно быть ≥ 0" % key)
            elif kind == "float":
                value = float(value)
                if value < 0 or math.isnan(value):
                    raise ValueError("%s: значение должно быть ≥ 0" % key)
            elif kind == "choice":
                value = str(value)
                if value not in CHOICES[key]:
                    raise ValueError("%s: допустимо %s" % (key, ", ".join(CHOICES[key])))
            clean[key] = value
        return clean

    def update(self, changes):
        clean = self._validate(changes)
        with self.lock:
            self.user.update(clean)
            self._save()
        return clean

    def reset(self):
        with self.lock:
            self.user = {}
            self._save()

    def _save(self):
        if self.path:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.user, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    def profile_for(self, os_name):
        chosen = self.user.get("profile", "auto")
        if chosen != "auto":
            return chosen
        return "windows" if str(os_name).lower().startswith("win") else "default"

    def effective(self, os_name=""):
        with self.lock:
            result = {k: v[0] for k, v in self.spec.items()}
            result.update(PROFILES.get(self.profile_for(os_name), {}))
            result.update(self.user)
        return result

    def describe(self):
        with self.lock:
            items = []
            for key, default, kind, group, label in THRESHOLD_SPEC:
                items.append({
                    "key": key, "type": kind, "group": group, "label": label,
                    "default": default, "value": self.user.get(key, default),
                    "changed": key in self.user, "choices": CHOICES.get(key),
                    "profiles": {p: o[key] for p, o in PROFILES.items() if key in o},
                })
            return items


# ------------------------------------------------------------------ буфер
class RingBuffer:
    """Кольцевой буфер фиксированного размера (старые точки вытесняются)."""

    def __init__(self, size):
        self.data = deque(maxlen=max(10, int(size)))
        self.lock = threading.Lock()

    def append(self, item):
        with self.lock:
            self.data.append(item)

    def snapshot(self, last=None):
        with self.lock:
            items = list(self.data)
        return items[-last:] if last else items

    def __len__(self):
        return len(self.data)

    @property
    def capacity(self):
        return self.data.maxlen


# ------------------------------------------------------------------ статистика
def median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return float(s[mid]) if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def mad(values, med=None):
    if not values:
        return 0.0
    if med is None:
        med = median(values)
    return median([abs(v - med) for v in values])


def percentile(values, q):
    if not values:
        return 0.0
    s = sorted(values)
    pos = (len(s) - 1) * q / 100.0
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def robust_z(x, med, mad_value, floor=1e-9):
    return 0.6745 * (x - med) / max(mad_value, floor)


def summarize(samples, keys):
    """Сводка mean / p95 / max / last по каждой метрике."""
    out = {}
    for key in keys:
        vals = [s["m"].get(key) for s in samples if isinstance(s["m"].get(key), (int, float))]
        if not vals:
            continue
        out[key] = {"mean": sum(vals) / len(vals), "p95": percentile(vals, 95),
                    "max": max(vals), "min": min(vals), "last": vals[-1], "n": len(vals)}
    return out


class Baseline:
    """Оценка нормы по истории без последних N точек; статистика считается лениво."""

    def __init__(self, history, th):
        cut = len(history) - int(th["exclude_last"])
        base = history[max(0, cut - int(th["baseline_window"])):max(0, cut)]
        self.samples = base
        self.ready = len(base) >= int(th["warmup_points"])
        self._cache = {}

    def stats(self, key):
        if key not in self._cache:
            vals = [s["m"].get(key, 0.0) or 0.0 for s in self.samples]
            med = median(vals)
            self._cache[key] = (med, mad(vals, med), percentile(vals, 95))
        return self._cache[key]

    def z(self, key, x):
        if not self.ready:
            return None
        med, m, _ = self.stats(key)
        return robust_z(x, med, m, MAD_FLOOR.get(key, 1e-6))


class NodeState:
    """Состояние анализа одного узла: счётчики «подряд» и время последних сработок."""

    def __init__(self):
        self.streak = {}
        self.last_fire = {}
        self.silent_reported = False


def _r(x, nd=2):
    return None if x is None else round(float(x), nd)


class Analyzer:
    def __init__(self, thresholds):
        self.thresholds = thresholds

    # -- вспомогательное
    @staticmethod
    def _floor(th, base, key, value):
        """Абсолютный порог; в адаптивном режиме не ниже p95 нормы узла × k."""
        if th["adaptive"] and base.ready:
            return max(value, base.stats(key)[2] * float(th["adaptive_k"]))
        return value

    @staticmethod
    def _streak(state, rule, cond):
        state.streak[rule] = state.streak.get(rule, 0) + 1 if cond else 0
        return state.streak[rule]

    def _cooled(self, state, rule, ts, th):
        last = state.last_fire.get(rule)
        if last is not None and ts - last < float(th["cooldown_s"]):
            return False
        state.last_fire[rule] = ts
        return True

    @staticmethod
    def _baseline_info(base, key):
        if not base.ready:
            return {"ready": False, "points": len(base.samples)}
        med, m, p95 = base.stats(key)
        return {"ready": True, "points": len(base.samples), "median": _r(med), "mad": _r(m), "p95": _r(p95)}

    # -- главный метод
    def evaluate(self, history, sample, state, os_name=""):
        """history — точки буфера ДО текущей; sample — новая точка.

        Возвращает список находок: dict(rule, severity, title, evidence).
        """
        th = self.thresholds.effective(os_name)
        base = Baseline(history, th)
        m = sample["m"]
        ts = sample["ts"]
        iv = float(sample.get("iv") or 2.0)
        found = []

        def fire(rule, evidence, severity=None):
            if self._cooled(state, rule, ts, th):
                sev, title = RULES[rule]
                evidence["profile"] = self.thresholds.profile_for(os_name)
                found.append({"rule": rule, "severity": severity or sev, "title": title,
                              "evidence": evidence})

        # NET_LOW_CPU — долгая высокая сеть при низком user CPU
        net = float(m.get("net_total", 0.0))
        cpu_user = float(m.get("cpu_user", 0.0))
        if th["net_enabled"]:
            floor = self._floor(th, base, "net_total", float(th["net_min_kbps"]) * 1024)
            z = base.z("net_total", net)
            high = net >= floor and (z >= float(th["net_z"]) if z is not None else net >= 4 * floor)
            n = self._streak(state, "NET_LOW_CPU", high and cpu_user <= float(th["low_cpu_user"]))
            if n >= int(th["net_sustain"]):
                fire("NET_LOW_CPU", {
                    "net_total_kBps": _r(net / 1024), "cpu_user_pct": _r(cpu_user),
                    "points_in_row": n, "duration_s": _r(n * iv, 1), "z": _r(z),
                    "threshold_z": th["net_z"], "floor_kBps": _r(floor / 1024),
                    "low_cpu_user_pct": th["low_cpu_user"],
                    "baseline": self._baseline_info(base, "net_total")})

        # PROC_BURST — всплеск создания процессов / потоков
        if th["burst_enabled"]:
            p = float(m.get("proc_new_ps", 0.0))
            t = float(m.get("thr_new_ps", 0.0))
            zp = base.z("proc_new_ps", p)
            zt = base.z("thr_new_ps", t)
            hard = p >= float(th["burst_hard_proc_ps"])
            by_p = zp is not None and p >= float(th["burst_min_proc_ps"]) and zp >= float(th["burst_z"])
            by_t = zt is not None and t >= float(th["burst_min_thr_ps"]) and zt >= float(th["burst_z"])
            if hard or by_p or by_t:
                fire("PROC_BURST", {
                    "proc_new_ps": _r(p), "thr_new_ps": _r(t), "z_proc": _r(zp), "z_thr": _r(zt),
                    "threshold_z": th["burst_z"], "hard_limit_ps": th["burst_hard_proc_ps"],
                    "trigger": "hard" if hard else ("proc+thr" if by_p and by_t else ("proc" if by_p else "thr")),
                    "baseline_proc": self._baseline_info(base, "proc_new_ps"),
                    "baseline_thr": self._baseline_info(base, "thr_new_ps")},
                    severity="high" if hard or (by_p and by_t) else None)

        # DISK_NET_COMBO — высокие диск и сеть одновременно
        if th["combo_enabled"]:
            disk = float(m.get("disk_total", 0.0))
            fd = self._floor(th, base, "disk_total", float(th["combo_disk_min_kbps"]) * 1024)
            fn = self._floor(th, base, "net_total", float(th["combo_net_min_kbps"]) * 1024)
            zd = base.z("disk_total", disk)
            zn = base.z("net_total", net)
            if base.ready:
                cond = disk >= fd and net >= fn and zd >= float(th["combo_z"]) and zn >= float(th["combo_z"])
            else:
                cond = disk >= 4 * fd and net >= 4 * fn
            n = self._streak(state, "DISK_NET_COMBO", cond)
            if n >= int(th["combo_sustain"]):
                fire("DISK_NET_COMBO", {
                    "disk_total_kBps": _r(disk / 1024), "net_total_kBps": _r(net / 1024),
                    "disk_iops": _r(m.get("disk_iops", 0)), "z_disk": _r(zd), "z_net": _r(zn),
                    "threshold_z": th["combo_z"], "points_in_row": n,
                    "baseline_disk": self._baseline_info(base, "disk_total"),
                    "baseline_net": self._baseline_info(base, "net_total")})

        # MEM_JUMP — резкий скачок занятой памяти
        if th["mem_enabled"]:
            total = float(m.get("mem_total", 0.0)) or 1.0
            used = float(m.get("mem_used", 0.0))
            delta = float(m.get("mem_delta", 0.0))
            window = [h["m"].get("mem_used", used) for h in history[-max(1, int(th["mem_window"])):]]
            jump = used - min(window) if window else delta
            jump_pct = 100.0 * jump / total
            zm = base.z("mem_delta", delta)
            by_pct = jump_pct >= float(th["mem_jump_pct"])
            by_z = zm is not None and delta >= float(th["mem_jump_min_mb"]) and zm >= float(th["mem_z"])
            if by_pct or by_z:
                fire("MEM_JUMP", {
                    "mem_used_mb": _r(used, 0), "mem_total_mb": _r(total, 0),
                    "jump_mb": _r(jump, 0), "jump_pct": _r(jump_pct), "window_points": len(window),
                    "mem_delta_mb": _r(delta, 0), "z": _r(zm), "threshold_pct": th["mem_jump_pct"],
                    "trigger": "pct" if by_pct else "z",
                    "baseline": self._baseline_info(base, "mem_delta")},
                    severity="high" if jump_pct >= 2 * float(th["mem_jump_pct"]) else None)
        return found

    def check_silent(self, last_seen, paused, now, state, os_name=""):
        """AGENT_SILENT: смотрит на время последнего UDP-пакета (или снятия паузы), а не на TCP."""
        th = self.thresholds.effective(os_name)
        if not th["silent_enabled"] or last_seen is None:
            return None
        if paused and th["silent_ignore_paused"]:
            return None
        gap = now - last_seen
        if gap < float(th["silent_min_s"]):
            state.silent_reported = False
            return None
        if state.silent_reported:
            return None
        state.silent_reported = True
        sev, title = RULES["AGENT_SILENT"]
        return {"rule": "AGENT_SILENT", "severity": sev, "title": title,
                "evidence": {"silent_s": _r(gap, 1), "threshold_s": th["silent_min_s"],
                             "paused": bool(paused), "profile": self.thresholds.profile_for(os_name)}}

    def silent_limit(self, os_name=""):
        return float(self.thresholds.effective(os_name)["silent_min_s"])
