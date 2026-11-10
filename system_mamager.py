#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Mamager - a root-only Linux terminal system manager.

Only Python standard-library modules are used.  Data is collected from /proc,
/sys and standard Linux administration commands already present on the host.
"""

from __future__ import annotations

import curses
import grp
import os
import platform
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

APP_NAME = "SYSTEM MAMAGER"
APP_VERSION = "1.1"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    command: list[str]
    code: int = 0
    output: str = ""
    error: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        if self.output and self.error:
            return self.output.rstrip() + "\n" + self.error.rstrip()
        return (self.output or self.error).rstrip()


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    uid: int
    user: str
    state: str
    state_label: str
    cpu: float
    mem_pct: float
    rss_kb: int
    threads: int
    elapsed: float
    comm: str
    args: str
    daemon: bool


@dataclass
class ServiceInfo:
    unit: str
    load: str
    active: str
    sub: str
    description: str


@dataclass
class NetRow:
    netid: str
    state: str
    local: str
    peer: str
    process: str
    raw: str


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return default


def run_cmd(args: Iterable[str], timeout: float = 6.0) -> CommandResult:
    command = [str(a) for a in args]
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            command=command,
            code=proc.returncode,
            output=proc.stdout or "",
            error=proc.stderr or "",
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(command=command, code=124, output=out, error=err, timed_out=True)
    except FileNotFoundError:
        return CommandResult(command=command, code=127, error=f"command not found: {command[0]}")
    except OSError as exc:
        return CommandResult(command=command, code=1, error=str(exc))


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def human_bytes(value: float) -> str:
    value = float(max(0, value))
    units = ("B", "K", "M", "G", "T", "P")
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)}B"
    return f"{value:.1f}{units[idx]}"


def fmt_float(value: Optional[float], suffix: str = "", digits: int = 1) -> str:
    if value is None:
        return "—"
    return f"{value:.{digits}f}{suffix}"


def clean_line(line: str) -> str:
    line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
    return line.replace("\t", "    ").rstrip()


def display_width(text: str) -> int:
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def clip_display(text: str, max_width: int) -> str:
    if max_width <= 0:
        return ""
    out: list[str] = []
    used = 0
    for char in str(text):
        char_width = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in ("W", "F") else 1)
        if used + char_width > max_width:
            break
        out.append(char)
        used += char_width
    return "".join(out)


def pad_display(text: str, width: int, align: str = "left") -> str:
    text = clip_display(str(text), width)
    gap = max(0, width - display_width(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def wrap_display(text: str, width: int) -> list[str]:
    if width <= 0:
        return [""]
    lines: list[str] = []
    current: list[str] = []
    used = 0
    for char in str(text):
        if char == "\n":
            lines.append("".join(current))
            current = []
            used = 0
            continue
        char_width = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in ("W", "F") else 1)
        if used + char_width > width and current:
            lines.append("".join(current))
            current = []
            used = 0
        current.append(char)
        used += char_width
    lines.append("".join(current))
    return lines


def section(title: str, body: str) -> str:
    body = body.strip() if body else "(无输出)"
    return f"===== {title} =====\n{body}"


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

class Collector:
    STATE_LABELS = {
        "R": "running",
        "S": "sleeping",
        "D": "disk-wait",
        "Z": "zombie",
        "T": "stopped",
        "t": "tracing-stop",
        "I": "idle",
        "X": "dead",
        "x": "dead",
        "K": "wakekill",
        "W": "waking",
        "P": "parked",
    }

    def __init__(self) -> None:
        self.clk_tck = os.sysconf("SC_CLK_TCK")
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self._prev_proc: dict[int, tuple[int, float]] = {}
        self._prev_cpu: Optional[tuple[int, int, float]] = None
        self._user_cache: dict[int, str] = {}
        self._group_cache: dict[int, str] = {}
        self._boot_time = self._read_boot_time()

    @staticmethod
    def _read_boot_time() -> float:
        try:
            with open("/proc/stat", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("btime "):
                        return float(line.split()[1])
        except OSError:
            pass
        return time.time() - Collector.uptime_seconds()

    @staticmethod
    def uptime_seconds() -> float:
        try:
            return float(read_text("/proc/uptime", "0 0").split()[0])
        except (ValueError, IndexError):
            return 0.0

    def user_name(self, uid: int) -> str:
        if uid not in self._user_cache:
            try:
                self._user_cache[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self._user_cache[uid] = str(uid)
        return self._user_cache[uid]

    def group_name(self, gid: int) -> str:
        if gid not in self._group_cache:
            try:
                self._group_cache[gid] = grp.getgrgid(gid).gr_name
            except KeyError:
                self._group_cache[gid] = str(gid)
        return self._group_cache[gid]

    def cpu_usage(self) -> Optional[float]:
        try:
            parts = read_text("/proc/stat").splitlines()[0].split()[1:]
            values = [int(x) for x in parts]
        except (OSError, ValueError, IndexError):
            return None
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        now = time.monotonic()
        if self._prev_cpu is None:
            self._prev_cpu = (total, idle, now)
            return None
        prev_total, prev_idle, prev_time = self._prev_cpu
        self._prev_cpu = (total, idle, now)
        elapsed = now - prev_time
        total_delta = total - prev_total
        idle_delta = idle - prev_idle
        if elapsed <= 0 or total_delta <= 0:
            return None
        usage = 100.0 * (total_delta - idle_delta) / total_delta
        return max(0.0, min(100.0, usage))

    def memory_info(self) -> dict[str, int]:
        data: dict[str, int] = {}
        for line in read_text("/proc/meminfo").splitlines():
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            parts = rest.strip().split()
            if not parts:
                continue
            try:
                value = int(parts[0])
            except ValueError:
                continue
            if len(parts) > 1 and parts[1].lower() == "kb":
                value *= 1024
            data[key] = value
        return data

    def loadavg(self) -> tuple[float, float, float]:
        try:
            values = [float(x) for x in read_text("/proc/loadavg").split()[:3]]
            return values[0], values[1], values[2]
        except (ValueError, IndexError):
            return 0.0, 0.0, 0.0

    def _read_stat(self, pid: int) -> Optional[tuple[str, int, int, int, int, int, int]]:
        raw = read_text(f"/proc/{pid}/stat")
        if not raw:
            return None
        try:
            _, tail = raw.rsplit(")", 1)
            fields = tail.split()
            state = fields[0]
            ppid = int(fields[1])
            utime = int(fields[11])
            stime = int(fields[12])
            threads = int(fields[17])
            starttime = int(fields[19])
            rss_pages = int(fields[21])
            return state, ppid, utime + stime, threads, starttime, rss_pages, int(fields[13]) + int(fields[14])
        except (ValueError, IndexError):
            return None

    def _read_uid_gid(self, pid: int) -> tuple[int, int]:
        uid = gid = 0
        for line in read_text(f"/proc/{pid}/status").splitlines():
            if line.startswith("Uid:"):
                try:
                    uid = int(line.split()[1])
                except (ValueError, IndexError):
                    pass
            elif line.startswith("Gid:"):
                try:
                    gid = int(line.split()[1])
                except (ValueError, IndexError):
                    pass
        return uid, gid

    def list_processes(self) -> list[ProcessInfo]:
        now = time.monotonic()
        uptime = self.uptime_seconds()
        mem = self.memory_info()
        total_mem_kb = max(1, mem.get("MemTotal", 0) // 1024)
        current: dict[int, tuple[int, float]] = {}
        result: list[ProcessInfo] = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            stat = self._read_stat(pid)
            if stat is None:
                continue
            state, ppid, ticks, threads, starttime, rss_pages, _ctime = stat
            uid, _gid = self._read_uid_gid(pid)
            comm = read_text(f"/proc/{pid}/comm").strip() or f"pid-{pid}"
            raw_args = read_text(f"/proc/{pid}/cmdline", "")
            args = raw_args.replace("\x00", " ").strip() if raw_args else comm
            cpu = 0.0
            prev = self._prev_proc.get(pid)
            if prev is not None:
                prev_ticks, prev_time = prev
                elapsed = now - prev_time
                if elapsed > 0 and ticks >= prev_ticks:
                    cpu = (ticks - prev_ticks) / self.clk_tck / elapsed * 100.0
                    cpu = max(0.0, cpu)
            current[pid] = (ticks, now)
            rss_kb = max(0, rss_pages * self.page_size // 1024)
            elapsed_seconds = max(0.0, uptime - (starttime / self.clk_tck))
            result.append(
                ProcessInfo(
                    pid=pid,
                    ppid=ppid,
                    uid=uid,
                    user=self.user_name(uid),
                    state=state,
                    state_label=self.STATE_LABELS.get(state, state),
                    cpu=cpu,
                    mem_pct=100.0 * rss_kb / total_mem_kb,
                    rss_kb=rss_kb,
                    threads=threads,
                    elapsed=elapsed_seconds,
                    comm=comm,
                    args=args,
                    daemon=(ppid == 1 and state != "Z"),
                )
            )
        self._prev_proc = current
        result.sort(key=lambda p: (-p.cpu, -p.rss_kb, p.pid))
        return result

    def process_detail(self, pid: int) -> list[str]:
        stat = self._read_stat(pid)
        if stat is None:
            return [f"PID {pid} 已不存在或无法读取。"]
        state, ppid, ticks, threads, starttime, rss_pages, _ = stat
        uid, gid = self._read_uid_gid(pid)
        status = read_text(f"/proc/{pid}/status").strip()
        raw_args = read_text(f"/proc/{pid}/cmdline", "")
        args = raw_args.replace("\x00", " ").strip() or read_text(f"/proc/{pid}/comm").strip()
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = "(不可读取)"
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            cwd = "(不可读取)"
        try:
            fd_count = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            fd_count = -1
        try:
            cgroup = read_text(f"/proc/{pid}/cgroup").strip()
        except OSError:
            cgroup = "(不可读取)"
        cpu = 0.0
        prev = self._prev_proc.get(pid)
        if prev is not None:
            elapsed = max(1e-9, time.monotonic() - prev[1])
            cpu = max(0.0, (ticks - prev[0]) / self.clk_tck / elapsed * 100.0)
        rss_kb = rss_pages * self.page_size // 1024
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._boot_time + starttime / self.clk_tck))
        lines = [
            f"PID:           {pid}",
            f"PPID:          {ppid}",
            f"用户 / UID:    {self.user_name(uid)} / {uid}",
            f"组 / GID:      {self.group_name(gid)} / {gid}",
            f"状态:          {state} ({self.STATE_LABELS.get(state, state)})",
            f"线程:          {threads}",
            f"CPU:           {cpu:.1f}%",
            f"RSS 内存:      {human_bytes(rss_kb * 1024)}",
            f"启动时间:      {started}",
            f"运行时长:      {human_duration(self.uptime_seconds() - starttime / self.clk_tck)}",
            f"打开的文件描述符: {fd_count if fd_count >= 0 else '未知'}",
            f"可执行文件:    {exe}",
            f"工作目录:      {cwd}",
            f"命令:          {args}",
            f"CGroup:        {cgroup or '(空)'}",
            "",
            section("/proc/PID/status", status),
        ]
        return lines

    def list_services(self) -> list[ServiceInfo]:
        result = run_cmd(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"],
            timeout=8,
        )
        services: list[ServiceInfo] = []
        for raw in result.output.splitlines():
            line = clean_line(raw).strip()
            if not line:
                continue
            line = line.lstrip("●* ").strip()
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            unit, load, active = parts[:3]
            sub = parts[3].split(None, 1)[0] if len(parts) > 3 else ""
            desc = parts[3].split(None, 1)[1] if len(parts) > 3 and len(parts[3].split(None, 1)) > 1 else ""
            if not unit.endswith(".service"):
                continue
            services.append(ServiceInfo(unit, load, active, sub, desc))
        priority = {"failed": 0, "active": 1, "activating": 2, "deactivating": 3, "inactive": 4}
        services.sort(key=lambda s: (priority.get(s.active, 5), s.unit))
        return services

    def service_detail(self, unit: str) -> list[str]:
        props = (
            "Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,"
            "MainPID,ExecMainPID,MemoryCurrent,TasksCurrent,CPUUsageNSec,NRestarts,"
            "ActiveEnterTimestamp,InactiveEnterTimestamp"
        )
        show = run_cmd(["systemctl", "show", unit, "--no-pager", f"--property={props}"], timeout=8)
        status = run_cmd(["systemctl", "status", unit, "--no-pager", "--full", "-l"], timeout=8)
        logs = run_cmd(
            ["journalctl", "-u", unit, "-n", "35", "--no-pager", "-o", "short-iso"],
            timeout=8,
        )
        lines: list[str] = []
        if show.ok:
            for line in show.output.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    if value:
                        lines.append(f"{key}: {value}")
        lines.append("")
        lines.append(section("systemctl status", status.combined))
        lines.append("")
        lines.append(section("最近 35 条服务日志", logs.combined if logs.ok else logs.combined))
        return lines

    def service_action(self, unit: str, action: str) -> CommandResult:
        commands = {
            "start": ["systemctl", "start", unit],
            "stop": ["systemctl", "stop", unit],
            "restart": ["systemctl", "restart", unit],
            "enable": ["systemctl", "enable", unit],
            "disable": ["systemctl", "disable", unit],
        }
        return run_cmd(commands[action], timeout=20)

    def list_interfaces(self) -> list[str]:
        result = run_cmd(["ip", "-brief", "address"], timeout=5)
        return [clean_line(x) for x in result.output.splitlines() if clean_line(x).strip()]

    def list_connections(self) -> list[NetRow]:
        result = run_cmd(["ss", "-H", "-tunap"], timeout=6)
        rows: list[NetRow] = []
        for raw in result.output.splitlines():
            line = clean_line(raw).strip()
            if not line:
                continue
            parts = line.split(None, 6)
            if len(parts) < 5:
                continue
            netid = parts[0]
            state = parts[1] if len(parts) > 1 else ""
            local = parts[4] if len(parts) > 4 else ""
            peer = parts[5] if len(parts) > 5 else ""
            process = parts[6] if len(parts) > 6 else ""
            rows.append(NetRow(netid, state, local, peer, process, line))
        return rows

    def network_summary(self) -> tuple[int, int]:
        return len(self.list_interfaces()), len(self.list_connections())

    def _active_state(self, service: str) -> str:
        result = run_cmd(["systemctl", "is-active", service], timeout=4)
        value = (result.output or result.error).strip().splitlines()
        return value[0] if value else "unknown"

    def firewall_text(self) -> list[str]:
        lines: list[str] = ["防火墙服务状态"]
        for service in ("ufw", "firewalld", "nftables", "iptables"):
            lines.append(f"{service:12s}: {self._active_state(service)}")
        lines.append("")

        if shutil.which("ufw"):
            result = run_cmd(["ufw", "status", "verbose"], timeout=8)
            lines.append(section("UFW", result.combined))
            lines.append("")
        if shutil.which("firewall-cmd"):
            state = run_cmd(["firewall-cmd", "--state"], timeout=6)
            lines.append(section("firewalld 状态", state.combined))
            if "running" in state.combined.lower():
                result = run_cmd(["firewall-cmd", "--list-all"], timeout=8)
                lines.append(section("firewalld 规则", result.combined))
            lines.append("")
        if shutil.which("nft"):
            result = run_cmd(["nft", "list", "ruleset"], timeout=10)
            body = result.combined
            body_lines = body.splitlines()
            if len(body_lines) > 180:
                body = "\n".join(body_lines[:180]) + f"\n... 已截断，共 {len(body_lines)} 行"
            lines.append(section("nftables ruleset", body))
            lines.append("")
        if shutil.which("iptables"):
            result = run_cmd(["iptables", "-S"], timeout=8)
            body = result.combined
            body_lines = body.splitlines()
            if len(body_lines) > 120:
                body = "\n".join(body_lines[:120]) + f"\n... 已截断，共 {len(body_lines)} 行"
            lines.append(section("iptables -S", body))
        return lines

    def _sudo_user(self) -> tuple[str, int, str]:
        username = os.environ.get("SUDO_USER") or ""
        if username and username != "root":
            try:
                entry = pwd.getpwnam(username)
                return entry.pw_name, entry.pw_uid, entry.pw_dir
            except KeyError:
                pass
        try:
            entry = pwd.getpwuid(1000)
            return entry.pw_name, entry.pw_uid, entry.pw_dir
        except KeyError:
            return "root", 0, "/root"

    def _proxy_env_from_processes(self, uid: int) -> list[str]:
        names = {
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        }
        found: set[str] = set()
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return []
        for pid in pids:
            status = read_text(f"/proc/{pid}/status")
            match = re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE)
            if not match or int(match.group(1)) != uid:
                continue
            try:
                with open(f"/proc/{pid}/environ", "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            for item in raw.split(b"\0"):
                if b"=" not in item:
                    continue
                key, value = item.split(b"=", 1)
                key_text = key.decode("utf-8", "replace")
                if key_text in names:
                    found.add(f"{key_text}={value.decode('utf-8', 'replace')}")
        return sorted(found)

    def proxy_text(self) -> list[str]:
        username, uid, home = self._sudo_user()
        lines: list[str] = []
        current = [
            f"{key}={value}" for key, value in os.environ.items()
            if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy") and value
        ]
        lines.append(section("当前管理器环境", "\n".join(sorted(current)) or "(未设置代理环境变量)"))

        proc_env = self._proxy_env_from_processes(uid)
        lines.append(section(f"用户 {username} 运行进程中的代理变量", "\n".join(proc_env) or "(未发现代理环境变量)"))

        systemd_env = run_cmd(["systemctl", "show-environment"], timeout=5)
        proxy_systemd = [
            clean_line(x) for x in systemd_env.output.splitlines()
            if any(k in x.lower() for k in ("proxy", "http_proxy", "https_proxy"))
        ]
        lines.append(section("systemd 系统环境", "\n".join(proxy_systemd) or "(未发现代理变量)"))

        config_hits: list[str] = []
        try:
            result = run_cmd(
                ["grep", "-RInEi", "(https?_proxy|all_proxy|no_proxy)", "/etc/environment", "/etc/profile.d", f"{home}/.config/environment.d", f"{home}/.bashrc", f"{home}/.profile"],
                timeout=6,
            )
            if result.output.strip():
                config_hits.extend(clean_line(x) for x in result.output.splitlines()[:80])
        except Exception:
            pass
        lines.append(section("环境/配置文件中发现", "\n".join(config_hits) or "(未发现代理配置)"))

        if shutil.which("gsettings"):
            dbus = f"unix:path=/run/user/{uid}/bus"
            keys = [
                ("mode", "org.gnome.system.proxy", "mode"),
                ("http host", "org.gnome.system.proxy.http", "host"),
                ("http port", "org.gnome.system.proxy.http", "port"),
                ("https host", "org.gnome.system.proxy.https", "host"),
                ("https port", "org.gnome.system.proxy.https", "port"),
                ("socks host", "org.gnome.system.proxy.socks", "host"),
                ("socks port", "org.gnome.system.proxy.socks", "port"),
                ("ignore-hosts", "org.gnome.system.proxy", "ignore-hosts"),
            ]
            gnome_lines: list[str] = []
            for label, schema, key in keys:
                result = run_cmd(
                    ["runuser", "-u", username, "--", "env", f"DBUS_SESSION_BUS_ADDRESS={dbus}", "gsettings", "get", schema, key],
                    timeout=5,
                )
                if result.ok:
                    gnome_lines.append(f"{label}: {result.output.strip()}")
            lines.append(section("GNOME 系统代理", "\n".join(gnome_lines) or "(无法读取 GNOME 代理设置)"))

        kde_paths = [f"{home}/.config/kioslaverc", f"{home}/.config/kded5rc", f"{home}/.config/kdedefaults/kioslaverc"]
        kde_lines: list[str] = []
        for path in kde_paths:
            if not os.path.isfile(path):
                continue
            for raw in read_text(path).splitlines():
                if any(word in raw.lower() for word in ("proxy", "proxytype", "proxyserver")):
                    kde_lines.append(f"{path}: {raw.strip()}")
        lines.append(section("KDE 代理配置", "\n".join(kde_lines) or "(未发现 KDE 代理配置)"))
        return lines

    def _firewall_summary(self) -> str:
        states: list[str] = []
        if self._active_state("ufw") == "active" and shutil.which("ufw"):
            result = run_cmd(["ufw", "status"], timeout=6)
            if "status: active" in result.combined.lower():
                states.append("UFW 已启用")
            else:
                states.append("UFW 规则未启用")
        if self._active_state("firewalld") == "active":
            result = run_cmd(["firewall-cmd", "--state"], timeout=5) if shutil.which("firewall-cmd") else None
            if result and "running" in result.combined.lower():
                states.append("firewalld 正在运行")
            else:
                states.append("firewalld 服务活跃")
        if self._active_state("nftables") == "active":
            states.append("nftables 服务活跃")
        if self._active_state("iptables") == "active":
            states.append("iptables 服务活跃")
        if states:
            return "；".join(states)
        if shutil.which("nft") and run_cmd(["nft", "list", "ruleset"], timeout=8).output.strip():
            return "nftables 规则已加载（无可管理服务）"
        return "未检测到已启用防火墙规则"

    def security_overview_text(self) -> list[str]:
        interfaces = self.list_interfaces()
        connections = self.list_connections()
        listeners = [
            row for row in connections
            if row.state in ("LISTEN", "UNCONN") or ":*" in row.local or row.local.endswith(":*")
        ]
        exposed = [
            row for row in listeners
            if row.local.startswith("0.0.0.0:") or row.local.startswith("[::]:") or row.local.startswith("*:")
        ]
        established = [row for row in connections if row.state == "ESTAB"]
        tunnel_prefixes = ("tun", "tap", "wg", "tailscale", "zt", "ppp", "vpn")
        tunnels = [line for line in interfaces if line.split(None, 1)[0].startswith(tunnel_prefixes)]
        route = run_cmd(["ip", "route", "show", "default"], timeout=5)
        lines = [
            f"网络接口: {len(interfaces)}  当前套接字: {len(connections)}",
            f"监听套接字: {len(listeners)}  对外监听: {len(exposed)}  已建立连接: {len(established)}",
            f"防火墙: {self._firewall_summary()}",
            f"VPN/隧道接口: {len(tunnels)}" + (f" ({', '.join(x.split()[0] for x in tunnels)})" if tunnels else ""),
            f"默认路由: {route.combined or '(无默认路由)'}",
            "",
            "对外监听地址（重点检查）:",
        ]
        if exposed:
            lines.extend("  " + row.raw for row in exposed[:40])
            if len(exposed) > 40:
                lines.append(f"  ... 另有 {len(exposed) - 40} 条")
        else:
            lines.append("  (未发现 0.0.0.0 / [::] 通配监听)")
        lines.extend([
            "",
            "重要提示:",
            "  - 防火墙与代理详情见对应标签页。",
            "  - 对外监听不等于有风险，请结合服务用途和防火墙规则判断。",
            "  - 如果使用 Docker/libvirt，它们可能自行写入 nftables/iptables 规则。",
        ])
        return lines

    def network_tab(self, tab: int) -> tuple[list[str], list[str]]:
        if tab == 0:
            lines = self.list_interfaces()
            return ["接口状态", "名称 / 状态 / 地址"], lines
        if tab == 1:
            rows = self.list_connections()
            raw = [r.raw for r in rows]
            return ["当前套接字连接", "协议 / 状态 / 本地地址 / 对端地址 / 进程"], raw
        if tab == 2:
            result = run_cmd(["ip", "route", "show"], timeout=5)
            return ["路由表", "ip route show"], [clean_line(x) for x in result.output.splitlines() if x.strip()]
        if tab == 3:
            resolv = read_text("/etc/resolv.conf", "(/etc/resolv.conf 不可读)")
            parts = [section("/etc/resolv.conf", resolv)]
            if shutil.which("resolvectl"):
                resolved = run_cmd(["resolvectl", "status"], timeout=5)
                parts.append(section("resolvectl status", resolved.combined))
            return ["DNS / 域名解析", "/etc/resolv.conf 与 systemd-resolved"], "\n".join(parts).splitlines()
        if tab == 4:
            return ["防火墙状态", "UFW / firewalld / nftables / iptables"], self.firewall_text()
        if tab == 5:
            return ["代理配置", "环境变量 / GNOME / KDE / systemd"], self.proxy_text()
        if tab == 6:
            return ["网络安全概览", "监听地址 / 防火墙 / VPN / 默认路由"], self.security_overview_text()
        return [], []

    def system_topic_content(self, topic_id: str) -> list[str]:
        if topic_id == "host":
            parts = [
                section("hostnamectl", run_cmd(["hostnamectl"], timeout=5).combined),
                section("uname", run_cmd(["uname", "-a"], timeout=4).combined),
                section("os-release", read_text("/etc/os-release").strip()),
            ]
        elif topic_id == "cpu":
            parts = [
                section("lscpu", run_cmd(["lscpu"], timeout=6).combined),
                section("CPU 频率策略", self._cpu_policy_text()),
            ]
        elif topic_id == "memory":
            parts = [
                section("free -h", run_cmd(["free", "-h"], timeout=4).combined),
                section("/proc/meminfo", read_text("/proc/meminfo").strip()),
            ]
        elif topic_id == "kernel":
            parts = [
                section("kernel", run_cmd(["uname", "-a"], timeout=4).combined),
                section("/proc/cmdline", read_text("/proc/cmdline").strip()),
                section("modules", run_cmd(["lsmod"], timeout=5).combined),
            ]
        elif topic_id == "users":
            parts = [
                section("who", run_cmd(["who", "-a"], timeout=4).combined),
                section("w", run_cmd(["w"], timeout=4).combined),
            ]
        elif topic_id == "platform":
            detect = run_cmd(["systemd-detect-virt"], timeout=4)
            parts = [
                section("virtualization", detect.combined if detect.ok else detect.combined),
                section("platform_profile", read_text("/sys/firmware/acpi/platform_profile", "(未暴露)").strip()),
                section("DMI", self._dmi_text()),
            ]
        else:
            parts = ["未知系统信息主题。"]
        return "\n".join(parts).splitlines()

    def _cpu_policy_text(self) -> str:
        lines: list[str] = []
        for cpu in ("cpu0", "cpu1", "cpu2", "cpu3", "cpu4", "cpu5", "cpu6", "cpu7"):
            base = f"/sys/devices/system/cpu/{cpu}/cpufreq"
            if not os.path.isdir(base):
                continue
            governor = read_text(f"{base}/scaling_governor", "?").strip()
            driver = read_text(f"{base}/scaling_driver", "?").strip()
            epp = read_text(f"{base}/energy_performance_preference", "").strip()
            lines.append(f"{cpu}: governor={governor} driver={driver}" + (f" epp={epp}" if epp else ""))
        return "\n".join(lines) or "(未发现 cpufreq 策略接口)"

    def _dmi_text(self) -> str:
        names = ("sys_vendor", "product_name", "product_version", "bios_version", "bios_date", "board_name")
        lines = []
        for name in names:
            value = read_text(f"/sys/devices/virtual/dmi/id/{name}", "").strip()
            if value:
                lines.append(f"{name}: {value}")
        return "\n".join(lines) or "(DMI 信息不可读)"

    def sensor_text(self) -> str:
        sensors = run_cmd(["sensors"], timeout=6)
        parts: list[str] = []
        if sensors.combined:
            parts.append(section("sensors", sensors.combined))
        hwmon_lines = []
        for hwmon in sorted(glob_hwmon()):
            name = read_text(os.path.join(hwmon, "name"), "hwmon").strip()
            for fname in sorted(os.listdir(hwmon)) if os.path.isdir(hwmon) else []:
                path = os.path.join(hwmon, fname)
                if re.match(r"temp\d+_input$", fname):
                    try:
                        value = float(read_text(path).strip()) / 1000.0
                        hwmon_lines.append(f"{name} {fname}: {value:.1f}°C")
                    except ValueError:
                        pass
                elif re.match(r"fan\d+_input$", fname):
                    try:
                        value = int(read_text(path).strip())
                        hwmon_lines.append(f"{name} {fname}: {value} RPM")
                    except ValueError:
                        pass
        parts.append(section("hwmon", "\n".join(hwmon_lines) or "(未暴露风扇/温度传感器)"))
        if not any(" RPM" in line for line in hwmon_lines):
            parts.append("提示：当前 BIOS/EC 没有向 Linux 暴露风扇转速；风扇通常由固件自动控制。")
        return "\n\n".join(parts)

    def temperature_summary(self) -> tuple[Optional[float], Optional[int]]:
        temps: list[float] = []
        fans: list[int] = []
        for hwmon in glob_hwmon():
            if not os.path.isdir(hwmon):
                continue
            for fname in os.listdir(hwmon):
                path = os.path.join(hwmon, fname)
                if re.match(r"temp\d+_input$", fname):
                    try:
                        temps.append(float(read_text(path).strip()) / 1000.0)
                    except ValueError:
                        pass
                elif re.match(r"fan\d+_input$", fname):
                    try:
                        fans.append(int(read_text(path).strip()))
                    except ValueError:
                        pass
        return (max(temps) if temps else None, max(fans) if fans else None)

    def disk_topic_content(self, topic_id: str) -> list[str]:
        if topic_id == "filesystems":
            body = run_cmd(["df", "-hT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "efivarfs"], timeout=6).combined
        elif topic_id == "block":
            body = run_cmd(
                ["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,ROTA,MODEL"],
                timeout=6,
            ).combined
        elif topic_id == "sensors":
            body = self.sensor_text()
        elif topic_id == "pci":
            body = run_cmd(["lspci", "-nnk"], timeout=6).combined
        else:
            body = "未知主题。"
        return body.splitlines()

    def recent_logs(self) -> list[str]:
        result = run_cmd(
            ["journalctl", "-b", "-p", "warning", "-n", "160", "--no-pager", "-o", "short-iso"],
            timeout=10,
        )
        if result.ok and result.output.strip():
            return [clean_line(x) for x in result.output.splitlines() if x.strip()]
        fallback = run_cmd(["dmesg", "-T"], timeout=6)
        if fallback.ok and fallback.output.strip():
            return [clean_line(x) for x in fallback.output.splitlines() if x.strip()][-160:]
        if result.timed_out:
            return ["[journalctl 超时] 请稍后按 r 重试，或直接运行：journalctl -b -p warning -n 100"]
        return [result.combined or "(当前启动没有 warning 及以上日志)"]

    def identity(self) -> dict[str, str]:
        return {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "os": self._os_pretty_name(),
            "cpu": self._cpu_model(),
            "arch": platform.machine(),
        }

    def _os_pretty_name(self) -> str:
        for line in read_text("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return platform.platform()

    def _cpu_model(self) -> str:
        for line in read_text("/proc/cpuinfo").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
        return platform.processor() or "CPU"


def glob_hwmon() -> list[str]:
    base = "/sys/class/hwmon"
    try:
        return [os.path.join(base, name) for name in os.listdir(base)]
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Terminal UI
# ---------------------------------------------------------------------------

SYSTEM_TOPICS = [
    ("host", "主机与系统", "主机名、发行版、内核、架构"),
    ("cpu", "CPU 信息", "型号、核心、频率策略"),
    ("memory", "内存与交换", "内存、缓存、Swap 详细数据"),
    ("kernel", "内核与启动", "内核、启动参数、已加载模块"),
    ("users", "用户与登录", "当前登录用户、会话、负载"),
    ("platform", "虚拟化与平台", "虚拟机检测、DMI、平台性能模式"),
]

HARDWARE_TOPICS = [
    ("filesystems", "文件系统", "挂载点、类型、容量和使用率"),
    ("block", "块设备", "磁盘、分区、文件系统、旋转介质"),
    ("sensors", "温度与风扇", "传感器读数、风扇转速（若固件暴露）"),
    ("pci", "PCI / GPU", "显卡、网卡、驱动绑定情况"),
]

PROCESS_TABS = [
    ("全部", "all"),
    ("运行中", "running"),
    ("守护进程", "daemon"),
    ("僵尸", "zombie"),
    ("睡眠", "sleeping"),
]

NETWORK_TABS = ["接口", "连接", "路由", "DNS", "防火墙", "代理", "安全概览"]


class App:
    def __init__(self, stdscr: "curses.window") -> None:
        self.stdscr = stdscr
        self.collector = Collector()
        self.stack: list[dict] = [{"screen": "overview", "sel": 0, "scroll": 0, "tab": 0, "filter": ""}]
        self.processes: list[ProcessInfo] = []
        self.services: list[ServiceInfo] = []
        self.interface_count = 0
        self.connection_count = 0
        self.cpu_usage: Optional[float] = None
        self.memory: dict[str, int] = {}
        self.loads = (0.0, 0.0, 0.0)
        self.max_temp: Optional[float] = None
        self.fan_rpm: Optional[int] = None
        self.identity = self.collector.identity()
        self.logs: list[str] = []
        self.message = ""
        self.message_until = 0.0
        self.last_process_refresh = 0.0
        self.last_service_refresh = 0.0
        self.last_network_refresh = 0.0
        self.network_cache: dict[int, tuple[float, list[str]]] = {}
        self.auto_refresh_interval = 2.0
        self.quit_requested = False
        self._init_curses()

    # ------------------------------------------------------------------
    # Curses / drawing helpers
    # ------------------------------------------------------------------
    def _init_curses(self) -> None:
        self.stdscr.keypad(True)
        curses.noecho()
        curses.cbreak()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        self.stdscr.timeout(250)
        self.has_color = False
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
            self.has_color = True
        except curses.error:
            pass

    def color(self, pair: int) -> int:
        return curses.color_pair(pair) if self.has_color else 0

    def add(self, y: int, x: int, text: object, width: int, attr: int = 0) -> None:
        if width <= 0:
            return
        try:
            self.stdscr.addstr(y, x, clip_display(str(text), width), attr)
        except curses.error:
            pass

    def current(self) -> dict:
        return self.stack[-1]

    def push(self, screen: str, context: Optional[dict] = None, tab: int = 0, filter_text: str = "") -> None:
        self.stack.append(
            {
                "screen": screen,
                "sel": 0,
                "scroll": 0,
                "tab": tab,
                "filter": filter_text,
                "context": context or {},
            }
        )

    def replace_screen(self, screen: str, context: Optional[dict] = None) -> None:
        if len(self.stack) == 1:
            self.stack[0] = {"screen": screen, "sel": 0, "scroll": 0, "tab": 0, "filter": "", "context": context or {}}
        else:
            self.stack[-1] = {"screen": screen, "sel": 0, "scroll": 0, "tab": 0, "filter": "", "context": context or {}}

    def pop(self) -> bool:
        if len(self.stack) > 1:
            self.stack.pop()
            return True
        return False

    def set_message(self, text: str, seconds: float = 6.0) -> None:
        self.message = text
        self.message_until = time.monotonic() + seconds

    # ------------------------------------------------------------------
    # Data refresh
    # ------------------------------------------------------------------
    def refresh_data(self, force: bool = False) -> None:
        now = time.monotonic()
        if force:
            self.network_cache.clear()
        if force or now - self.last_process_refresh >= self.auto_refresh_interval:
            self.processes = self.collector.list_processes()
            self.last_process_refresh = now
        if force or now - self.last_service_refresh >= 8.0:
            self.services = self.collector.list_services()
            self.last_service_refresh = now
        if force or now - self.last_network_refresh >= 5.0:
            try:
                self.interface_count = len(self.collector.list_interfaces())
                self.connection_count = len(self.collector.list_connections())
            except Exception:
                self.interface_count = 0
                self.connection_count = 0
            self.last_network_refresh = now
        self.cpu_usage = self.collector.cpu_usage()
        self.memory = self.collector.memory_info()
        self.loads = self.collector.loadavg()
        self.max_temp, self.fan_rpm = self.collector.temperature_summary()

    def process_counts(self) -> dict[str, int]:
        counts = {"total": len(self.processes), "running": 0, "daemon": 0, "zombie": 0, "sleeping": 0}
        for proc in self.processes:
            if proc.state == "R":
                counts["running"] += 1
            if proc.daemon:
                counts["daemon"] += 1
            if proc.state == "Z":
                counts["zombie"] += 1
            if proc.state == "S":
                counts["sleeping"] += 1
        return counts

    def service_counts(self) -> tuple[int, int, int]:
        active = sum(1 for s in self.services if s.active == "active")
        failed = sum(1 for s in self.services if s.active == "failed")
        return len(self.services), active, failed

    def mem_summary(self) -> tuple[int, int, int, int]:
        total = self.memory.get("MemTotal", 0)
        available = self.memory.get("MemAvailable", self.memory.get("MemFree", 0))
        used = max(0, total - available)
        swap_total = self.memory.get("SwapTotal", 0)
        swap_free = self.memory.get("SwapFree", 0)
        return total, used, swap_total, max(0, swap_total - swap_free)

    def root_disk(self) -> tuple[int, int, int]:
        try:
            usage = shutil.disk_usage("/")
            return usage.total, usage.used, usage.free
        except OSError:
            return 0, 0, 0

    def overview_items(self) -> list[dict]:
        pc = self.process_counts()
        total_svc, active_svc, failed_svc = self.service_counts()
        total_mem, used_mem, _, _ = self.mem_summary()
        disk_total, disk_used, _ = self.root_disk()
        disk_pct = (100.0 * disk_used / disk_total) if disk_total else 0.0
        return [
            {
                "screen": "system_info",
                "title": "系统概览",
                "summary": f"{self.identity['hostname']} | {self.identity['os']}",
            },
            {
                "screen": "processes",
                "title": "进程管理",
                "summary": f"{pc['total']} 进程 | 运行 {pc['running']} | 守护 {pc['daemon']} | 僵尸 {pc['zombie']}",
            },
            {
                "screen": "network",
                "title": "网络状态",
                "summary": f"{self.interface_count} 接口 | {self.connection_count} 套接字连接",
            },
            {
                "screen": "services",
                "title": "服务管理",
                "summary": f"{total_svc} 服务 | 活跃 {active_svc} | 失败 {failed_svc}",
            },
            {
                "screen": "system_info",
                "title": "系统信息",
                "summary": f"{self.identity['kernel']} | {self.identity['cpu']}",
            },
            {
                "screen": "hardware",
                "title": "磁盘与硬件",
                "summary": f"/ 使用 {disk_pct:.1f}% | 温度 {fmt_float(self.max_temp, '°C')} | 风扇 {self.fan_rpm if self.fan_rpm is not None else 'N/A'}",
            },
            {
                "screen": "logs",
                "title": "日志与告警",
                "summary": "查看本次启动 warning/error 级别日志",
            },
        ]

    # ------------------------------------------------------------------
    # Main loop / input
    # ------------------------------------------------------------------
    def run(self) -> None:
        self.draw_loading()
        self.refresh_data(force=True)
        while not self.quit_requested:
            self.refresh_data(force=False)
            self.draw()
            try:
                key = self.stdscr.getch()
            except curses.error:
                key = -1
            if key == -1:
                continue
            self.handle_key(key)

    def draw_loading(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        text = "正在采集系统信息，请稍候..."
        self.add(h // 2, max(0, (w - display_width(text)) // 2), text, w, curses.A_BOLD)
        self.stdscr.refresh()

    def handle_key(self, key: int) -> None:
        if key == curses.KEY_RESIZE:
            return
        if self.message and time.monotonic() > self.message_until:
            self.message = ""
        screen = self.current()["screen"]
        cur = self.current()

        if key in (27,):
            if not self.pop():
                self.quit_requested = True
            return
        if key in (ord("q"), ord("Q")):
            if not self.pop():
                self.quit_requested = True
            return
        if key in (ord("?"),):
            self.show_help()
            return
        if key in (ord("r"),) and screen not in ("overview", "process_detail", "service_detail"):
            self.refresh_data(force=True)
            if screen == "logs":
                self.logs = self.collector.recent_logs()
            self.set_message("已刷新")
            return

        if screen == "overview":
            items = self.overview_items()
            if key in (curses.KEY_UP, ord("k")):
                cur["sel"] = (cur["sel"] - 1) % len(items)
            elif key in (curses.KEY_DOWN, ord("j")):
                cur["sel"] = (cur["sel"] + 1) % len(items)
            elif key in (10, 13, curses.KEY_ENTER):
                item = items[cur["sel"]]
                self.open_overview_item(item)
        elif screen == "processes":
            self.handle_processes_key(key)
        elif screen == "process_detail":
            self.handle_process_detail_key(key)
        elif screen == "network":
            self.handle_network_key(key)
        elif screen == "services":
            self.handle_services_key(key)
        elif screen == "service_detail":
            self.handle_service_detail_key(key)
        elif screen == "system_info":
            self.handle_topic_key(key, SYSTEM_TOPICS)
        elif screen == "hardware":
            self.handle_topic_key(key, HARDWARE_TOPICS)
        elif screen == "logs":
            self.handle_logs_key(key)
        elif screen == "detail":
            self.handle_detail_key(key)

    def open_overview_item(self, item: dict) -> None:
        screen = item["screen"]
        if screen == "logs":
            self.draw_loading()
            self.logs = self.collector.recent_logs()
            self.push("logs")
            return
        if screen == "system_info" and item["title"] == "系统概览":
            lines = self.overview_text()
            self.push("detail", {"kind": "text", "title": "系统概览", "lines": lines, "source": ("overview", None)})
            return
        self.push(screen)

    def overview_text(self) -> list[str]:
        total_mem, used_mem, swap_total, swap_used = self.mem_summary()
        disk_total, disk_used, disk_free = self.root_disk()
        pc = self.process_counts()
        total_svc, active_svc, failed_svc = self.service_counts()
        boot_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.collector._boot_time))
        lines = [
            f"主机名:       {self.identity['hostname']}",
            f"操作系统:     {self.identity['os']}",
            f"内核:         {self.identity['kernel']}",
            f"架构:         {self.identity['arch']}",
            f"CPU:          {self.identity['cpu']}",
            f"启动时间:     {boot_time}",
            f"运行时长:     {human_duration(self.collector.uptime_seconds())}",
            f"负载:         {self.loads[0]:.2f} / {self.loads[1]:.2f} / {self.loads[2]:.2f}",
            f"CPU 总占用:   {fmt_float(self.cpu_usage, '%')}",
            f"内存:         {human_bytes(used_mem)} / {human_bytes(total_mem)}",
            f"Swap:         {human_bytes(swap_used)} / {human_bytes(swap_total)}",
            f"根文件系统:   {human_bytes(disk_used)} / {human_bytes(disk_total)} ({100 * disk_used / disk_total if disk_total else 0:.1f}%)",
            f"进程:         总 {pc['total']} / 运行 {pc['running']} / 守护 {pc['daemon']} / 僵尸 {pc['zombie']}",
            f"服务:         总 {total_svc} / 活跃 {active_svc} / 失败 {failed_svc}",
            f"网络:         {self.interface_count} 个接口 / {self.connection_count} 个连接",
            f"最高温度:     {fmt_float(self.max_temp, '°C')}",
            f"风扇转速:     {str(self.fan_rpm) + ' RPM' if self.fan_rpm is not None else '固件未暴露'}",
            "",
            "提示: 方向键选择，Enter 查看，Esc 返回；? 查看帮助。",
        ]
        return lines

    # ------------------------------------------------------------------
    # Process screens
    # ------------------------------------------------------------------
    def filtered_processes(self) -> list[ProcessInfo]:
        cur = self.current()
        tab = cur.get("tab", 0)
        mode = PROCESS_TABS[tab][1] if 0 <= tab < len(PROCESS_TABS) else "all"
        filt = cur.get("filter", "").strip().lower()
        result = []
        for proc in self.processes:
            if mode == "running" and proc.state != "R":
                continue
            if mode == "daemon" and not proc.daemon:
                continue
            if mode == "zombie" and proc.state != "Z":
                continue
            if mode == "sleeping" and proc.state != "S":
                continue
            if filt:
                haystack = f"{proc.pid} {proc.user} {proc.comm} {proc.args}".lower()
                if filt not in haystack:
                    continue
            result.append(proc)
        return result

    def handle_processes_key(self, key: int) -> None:
        cur = self.current()
        procs = self.filtered_processes()
        if key in (curses.KEY_LEFT, ord("h")):
            cur["tab"] = (cur["tab"] - 1) % len(PROCESS_TABS)
            cur["sel"] = 0
            cur["scroll"] = 0
        elif key in (curses.KEY_RIGHT, ord("l")):
            cur["tab"] = (cur["tab"] + 1) % len(PROCESS_TABS)
            cur["sel"] = 0
            cur["scroll"] = 0
        elif key == curses.KEY_UP:
            if procs:
                cur["sel"] = (cur["sel"] - 1) % len(procs)
        elif key in (curses.KEY_DOWN, ord("j")):
            if procs:
                cur["sel"] = (cur["sel"] + 1) % len(procs)
        elif key in (curses.KEY_PPAGE,):
            cur["sel"] = max(0, cur["sel"] - 10)
        elif key in (curses.KEY_NPAGE,):
            cur["sel"] = min(max(0, len(procs) - 1), cur["sel"] + 10)
        elif key in (10, 13, curses.KEY_ENTER):
            if procs:
                proc = procs[min(cur["sel"], len(procs) - 1)]
                self.open_process_detail(proc.pid)
        elif key == ord("k"):
            if procs:
                proc = procs[min(cur["sel"], len(procs) - 1)]
                self.signal_process(proc.pid, signal.SIGKILL, "SIGKILL")
        elif key in (ord("/"),):
            value = self.prompt_input("过滤进程（PID / 用户 / 命令，留空清除）:", cur.get("filter", ""))
            if value is not None:
                cur["filter"] = value
                cur["sel"] = 0
                cur["scroll"] = 0

    def open_process_detail(self, pid: int) -> None:
        lines = self.collector.process_detail(pid)
        self.push("process_detail", {"kind": "process", "pid": pid, "title": f"进程详情 · PID {pid}", "lines": lines})

    def handle_process_detail_key(self, key: int) -> None:
        cur = self.current()
        ctx = cur.get("context", {})
        pid = int(ctx.get("pid", 0))
        if key == curses.KEY_UP:
            cur["scroll"] = max(0, cur["scroll"] - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            cur["scroll"] += 1
        elif key == curses.KEY_PPAGE:
            cur["scroll"] = max(0, cur["scroll"] - 15)
        elif key == curses.KEY_NPAGE:
            cur["scroll"] += 15
        elif key == curses.KEY_HOME:
            cur["scroll"] = 0
        elif key == curses.KEY_END:
            cur["scroll"] = max(0, len(ctx.get("lines", [])) - 1)
        elif key in (ord("r"),):
            ctx["lines"] = self.collector.process_detail(pid)
            self.set_message("进程详情已刷新")
        elif key == ord("t"):
            self.signal_process(pid, signal.SIGTERM, "SIGTERM")
        elif key in (ord("9"), ord("k")):
            self.signal_process(pid, signal.SIGKILL, "SIGKILL")
        elif key in (ord("z"),):
            self.signal_process(pid, signal.SIGSTOP, "SIGSTOP")
        elif key in (ord("c"),):
            self.signal_process(pid, signal.SIGCONT, "SIGCONT")

    def signal_process(self, pid: int, sig: signal.Signals, label: str) -> None:
        if pid <= 1 or pid == os.getpid():
            self.set_message("拒绝操作 PID 1 或当前管理器自身")
            return
        name = next((p.comm for p in self.processes if p.pid == pid), str(pid))
        if not self.confirm(f"向 PID {pid} ({name}) 发送 {label}？"):
            return
        try:
            os.kill(pid, sig)
            self.set_message(f"已向 PID {pid} 发送 {label}")
            self.refresh_data(force=True)
            ctx = self.current().get("context", {})
            if ctx.get("kind") == "process":
                ctx["lines"] = self.collector.process_detail(pid)
        except ProcessLookupError:
            self.set_message(f"PID {pid} 已不存在")
        except PermissionError as exc:
            self.set_message(f"权限不足: {exc}")
        except OSError as exc:
            self.set_message(f"操作失败: {exc}")

    # ------------------------------------------------------------------
    # Network screen
    # ------------------------------------------------------------------
    def network_rows(self) -> list[str]:
        cur = self.current()
        tab = cur.get("tab", 0)
        now = time.monotonic()
        cached = self.network_cache.get(tab)
        if cached is None or now - cached[0] >= 8.0:
            _headings, rows = self.collector.network_tab(tab)
            self.network_cache[tab] = (now, rows)
        else:
            rows = cached[1]
        filt = cur.get("filter", "").strip().lower()
        if filt:
            rows = [row for row in rows if filt in row.lower()]
        return rows

    def handle_network_key(self, key: int) -> None:
        cur = self.current()
        rows = self.network_rows()
        if key in (curses.KEY_LEFT, ord("h")):
            cur["tab"] = (cur["tab"] - 1) % len(NETWORK_TABS)
            cur["sel"] = 0
            cur["scroll"] = 0
        elif key in (curses.KEY_RIGHT, ord("l")):
            cur["tab"] = (cur["tab"] + 1) % len(NETWORK_TABS)
            cur["sel"] = 0
            cur["scroll"] = 0
        elif key in (curses.KEY_UP, ord("k")):
            if rows:
                cur["sel"] = (cur["sel"] - 1) % len(rows)
        elif key in (curses.KEY_DOWN, ord("j")):
            if rows:
                cur["sel"] = (cur["sel"] + 1) % len(rows)
        elif key in (curses.KEY_PPAGE,):
            cur["sel"] = max(0, cur["sel"] - 12)
        elif key in (curses.KEY_NPAGE,):
            cur["sel"] = min(max(0, len(rows) - 1), cur["sel"] + 12)
        elif key in (10, 13, curses.KEY_ENTER):
            if rows:
                row = rows[min(cur["sel"], len(rows) - 1)]
                tab = cur["tab"]
                if tab == 0:
                    name = row.split()[0] if row.split() else ""
                    body = run_cmd(["ip", "addr", "show", "dev", name], timeout=5).combined
                    lines = [row, "", section(f"接口 {name} 详情", body)]
                    title = f"网络接口 · {name}"
                elif tab == 1:
                    lines = [row, "", section("套接字详情", f"本地: {row.split()[4] if len(row.split()) > 4 else '?'}\n对端: {row.split()[5] if len(row.split()) > 5 else '?'}\n进程: {row.split(None, 6)[6] if len(row.split(None, 6)) > 6 else '(未知)'}")]
                    title = "网络连接详情"
                else:
                    lines = rows
                    title = f"网络详情 · {NETWORK_TABS[tab]}"
                self.push("detail", {"kind": "text", "title": title, "lines": lines, "source": ("network", tab)})
        elif key == ord("/"):
            value = self.prompt_input("过滤当前网络列表（留空清除）:", cur.get("filter", ""))
            if value is not None:
                cur["filter"] = value
                cur["sel"] = 0

    # ------------------------------------------------------------------
    # Service screens
    # ------------------------------------------------------------------
    def filtered_services(self) -> list[ServiceInfo]:
        cur = self.current()
        filt = cur.get("filter", "").strip().lower()
        failed_only = bool(cur.get("failed_only", False))
        result = []
        for service in self.services:
            if failed_only and service.active != "failed":
                continue
            haystack = f"{service.unit} {service.description} {service.active} {service.sub}".lower()
            if filt and filt not in haystack:
                continue
            result.append(service)
        return result

    def handle_services_key(self, key: int) -> None:
        cur = self.current()
        services = self.filtered_services()
        if key in (curses.KEY_UP, ord("k")):
            if services:
                cur["sel"] = (cur["sel"] - 1) % len(services)
        elif key in (curses.KEY_DOWN, ord("j")):
            if services:
                cur["sel"] = (cur["sel"] + 1) % len(services)
        elif key in (curses.KEY_PPAGE,):
            cur["sel"] = max(0, cur["sel"] - 12)
        elif key in (curses.KEY_NPAGE,):
            cur["sel"] = min(max(0, len(services) - 1), cur["sel"] + 12)
        elif key in (10, 13, curses.KEY_ENTER):
            if services:
                service = services[min(cur["sel"], len(services) - 1)]
                lines = self.collector.service_detail(service.unit)
                self.push(
                    "service_detail",
                    {"kind": "service", "unit": service.unit, "title": f"服务详情 · {service.unit}", "lines": lines},
                )
        elif key == ord("f"):
            cur["failed_only"] = not bool(cur.get("failed_only", False))
            cur["sel"] = 0
            self.set_message("仅显示失败服务" if cur["failed_only"] else "显示全部服务")
        elif key == ord("/"):
            value = self.prompt_input("过滤服务（名称 / 描述 / 状态，留空清除）:", cur.get("filter", ""))
            if value is not None:
                cur["filter"] = value
                cur["sel"] = 0

    def handle_service_detail_key(self, key: int) -> None:
        cur = self.current()
        ctx = cur.get("context", {})
        unit = str(ctx.get("unit", ""))
        if key in (curses.KEY_UP, ord("k")):
            cur["scroll"] = max(0, cur["scroll"] - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            cur["scroll"] += 1
        elif key == curses.KEY_PPAGE:
            cur["scroll"] = max(0, cur["scroll"] - 15)
        elif key == curses.KEY_NPAGE:
            cur["scroll"] += 15
        elif key == curses.KEY_HOME:
            cur["scroll"] = 0
        elif key == curses.KEY_END:
            cur["scroll"] = max(0, len(ctx.get("lines", [])) - 1)
        elif key == ord("R"):
            ctx["lines"] = self.collector.service_detail(unit)
            self.set_message("服务详情已刷新")
        elif key in (ord("s"), ord("x"), ord("r"), ord("e"), ord("d")):
            action = {"s": "start", "x": "stop", "r": "restart", "e": "enable", "d": "disable"}[chr(key)]
            labels = {"start": "启动", "stop": "停止", "restart": "重启", "enable": "启用", "disable": "禁用"}
            if self.confirm(f"对 {unit} 执行“{labels[action]}”？"):
                result = self.collector.service_action(unit, action)
                if result.ok:
                    self.set_message(f"{unit}: {labels[action]}成功")
                else:
                    self.set_message(f"{unit}: {labels[action]}失败 · {result.combined[:100]}")
                self.refresh_data(force=True)
                ctx["lines"] = self.collector.service_detail(unit)

    # ------------------------------------------------------------------
    # System / hardware topic screens
    # ------------------------------------------------------------------
    def topic_summaries(self, screen: str) -> dict[str, str]:
        if screen == "system_info":
            total_mem, used_mem, swap_total, swap_used = self.mem_summary()
            users = run_cmd(["who"], timeout=3).output.splitlines()
            return {
                "host": f"{self.identity['hostname']} | {self.identity['arch']}",
                "cpu": self.identity["cpu"],
                "memory": f"内存 {human_bytes(used_mem)}/{human_bytes(total_mem)} | Swap {human_bytes(swap_used)}/{human_bytes(swap_total)}",
                "kernel": self.identity["kernel"],
                "users": f"{len(users)} 个登录会话",
                "platform": self.identity["os"],
            }
        total, used, free = self.root_disk()
        return {
            "filesystems": f"/ 使用 {human_bytes(used)}/{human_bytes(total)}",
            "block": "磁盘与分区拓扑",
            "sensors": f"最高温度 {fmt_float(self.max_temp, '°C')} | 风扇 {self.fan_rpm if self.fan_rpm is not None else 'N/A'}",
            "pci": "GPU、网卡与内核驱动",
        }

    def handle_topic_key(self, key: int, topics: list[tuple[str, str, str]]) -> None:
        cur = self.current()
        if key in (curses.KEY_UP, ord("k")):
            cur["sel"] = (cur["sel"] - 1) % len(topics)
        elif key in (curses.KEY_DOWN, ord("j")):
            cur["sel"] = (cur["sel"] + 1) % len(topics)
        elif key in (10, 13, curses.KEY_ENTER):
            topic_id, title, _desc = topics[cur["sel"]]
            self.open_topic(topic_id, title)

    def open_topic(self, topic_id: str, title: str) -> None:
        if self.current()["screen"] == "system_info":
            lines = self.collector.system_topic_content(topic_id)
            source = ("system_topic", topic_id)
        else:
            lines = self.collector.disk_topic_content(topic_id)
            source = ("hardware_topic", topic_id)
        self.push("detail", {"kind": "text", "title": title, "lines": lines, "source": source})

    # ------------------------------------------------------------------
    # Logs and generic detail
    # ------------------------------------------------------------------
    def handle_logs_key(self, key: int) -> None:
        cur = self.current()
        if key in (curses.KEY_UP, ord("k")):
            if self.logs:
                cur["sel"] = (cur["sel"] - 1) % len(self.logs)
        elif key in (curses.KEY_DOWN, ord("j")):
            if self.logs:
                cur["sel"] = (cur["sel"] + 1) % len(self.logs)
        elif key in (curses.KEY_PPAGE,):
            cur["sel"] = max(0, cur["sel"] - 12)
        elif key in (curses.KEY_NPAGE,):
            cur["sel"] = min(max(0, len(self.logs) - 1), cur["sel"] + 12)
        elif key in (10, 13, curses.KEY_ENTER):
            if self.logs:
                line = self.logs[min(cur["sel"], len(self.logs) - 1)]
                self.push("detail", {"kind": "text", "title": "日志详情", "lines": wrap_display(line, max(20, self.stdscr.getmaxyx()[1] - 4)), "source": ("logs", None)})

    def handle_detail_key(self, key: int) -> None:
        cur = self.current()
        ctx = cur.get("context", {})
        lines = ctx.get("lines", [])
        if key in (curses.KEY_UP, ord("k")):
            cur["scroll"] = max(0, cur["scroll"] - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            cur["scroll"] += 1
        elif key == curses.KEY_PPAGE:
            cur["scroll"] = max(0, cur["scroll"] - 15)
        elif key == curses.KEY_NPAGE:
            cur["scroll"] += 15
        elif key == curses.KEY_HOME:
            cur["scroll"] = 0
        elif key == curses.KEY_END:
            cur["scroll"] = max(0, len(lines) - 1)
        elif key == ord("r"):
            self.reload_detail(ctx)

    def reload_detail(self, ctx: dict) -> None:
        source_kind, source_id = ctx.get("source", ("", None))
        if source_kind == "overview":
            ctx["lines"] = self.overview_text()
        elif source_kind == "system_topic":
            ctx["lines"] = self.collector.system_topic_content(str(source_id))
        elif source_kind == "hardware_topic":
            ctx["lines"] = self.collector.disk_topic_content(str(source_id))
        elif source_kind == "logs":
            self.logs = self.collector.recent_logs()
            ctx["lines"] = ["日志列表已刷新，返回查看。"]
        self.set_message("内容已刷新")

    # ------------------------------------------------------------------
    # Help / dialogs
    # ------------------------------------------------------------------
    def show_help(self) -> None:
        lines = [
            "SYSTEM MAMAGER 键盘说明",
            "",
            "↑ / ↓ 或 j          移动光标、滚动详情",
            "← / → 或 h / l    在进程/网络页切换分类",
            "Enter             进入选中的功能或详情",
            "Esc / q           返回上一级；在总览退出",
            "r                 刷新当前数据",
            "?                 打开本帮助",
            "",
            "进程列表：k=直接 SIGKILL 当前进程（有确认框）\n进程详情：t=SIGTERM, k/9=SIGKILL, z=SIGSTOP, c=SIGCONT",
            "服务详情：s=启动, x=停止, r=重启, e=启用, d=禁用, R=刷新",
            "",
            "危险操作都会弹出确认框。该程序以 root 运行，请谨慎操作。",
            "",
            "网络页包含：接口、连接、路由、DNS、防火墙、代理、安全概览。\n数据来源：/proc, /sys, systemctl, ss, ip, nft/iptables, journalctl, sensors 等系统自带工具。",
        ]
        self.push("detail", {"kind": "text", "title": "帮助", "lines": lines, "source": ("static", None)})

    def prompt_input(self, prompt: str, initial: str = "") -> Optional[str]:
        self.stdscr.timeout(-1)
        value = initial
        try:
            while True:
                h, w = self.stdscr.getmaxyx()
                box_w = min(max(50, display_width(prompt) + 8), max(20, w - 4))
                box_h = 5
                y = max(1, h // 2 - box_h // 2)
                x = max(1, (w - box_w) // 2)
                self.draw_box(y, x, box_h, box_w)
                self.add(y + 1, x + 2, prompt, box_w - 4, curses.A_BOLD)
                self.add(y + 2, x + 2, "> " + value, box_w - 4, self.color(1))
                self.add(y + 3, x + 2, "Enter 确认 · Esc 取消 · Backspace 删除", box_w - 4, curses.A_DIM)
                self.stdscr.refresh()
                key = self.stdscr.getch()
                if key in (27,):
                    return None
                if key in (10, 13, curses.KEY_ENTER):
                    return value
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    value = value[:-1]
                elif key == 21:
                    value = ""
                elif 32 <= key <= 126:
                    if display_width(value) < box_w - 8:
                        value += chr(key)
        finally:
            self.stdscr.timeout(250)

    def confirm(self, prompt: str) -> bool:
        self.stdscr.timeout(-1)
        try:
            while True:
                h, w = self.stdscr.getmaxyx()
                box_w = min(max(54, display_width(prompt) + 8), max(20, w - 4))
                box_h = 6
                y = max(1, h // 2 - box_h // 2)
                x = max(1, (w - box_w) // 2)
                self.draw_box(y, x, box_h, box_w)
                wrapped = wrap_display(prompt, box_w - 4)
                for idx, line in enumerate(wrapped[:2]):
                    self.add(y + 1 + idx, x + 2, line, box_w - 4, curses.A_BOLD | self.color(3))
                self.add(y + 4, x + 2, "Enter / y 确认    n / Esc 取消", box_w - 4, curses.A_DIM)
                self.stdscr.refresh()
                key = self.stdscr.getch()
                if key in (10, 13, curses.KEY_ENTER, ord("y"), ord("Y")):
                    return True
                if key in (27, ord("n"), ord("N")):
                    return False
        finally:
            self.stdscr.timeout(250)

    def draw_box(self, y: int, x: int, h: int, w: int) -> None:
        if h < 2 or w < 2:
            return
        try:
            self.stdscr.attron(self.color(1))
            self.stdscr.addstr(y, x, "┌" + "─" * (w - 2) + "┐")
            for row in range(1, h - 1):
                self.stdscr.addstr(y + row, x, "│")
                self.stdscr.addstr(y + row, x + w - 1, "│")
            self.stdscr.addstr(y + h - 1, x, "└" + "─" * (w - 2) + "┘")
            self.stdscr.attroff(self.color(1))
        except curses.error:
            pass

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------
    def draw(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 12 or w < 50:
            text = "终端窗口太小，请调整到至少 50x12"
            self.add(max(0, h // 2), 1, text, max(1, w - 2), curses.A_BOLD | self.color(4))
            self.stdscr.refresh()
            return
        self.draw_header(h, w)
        screen = self.current()["screen"]
        body_top = 3
        body_bottom = h - 1
        if screen == "overview":
            self.draw_overview(body_top, body_bottom, w)
            footer = "↑/↓ 选择   Enter 进入   R 刷新   ? 帮助   Q 退出"
        elif screen == "processes":
            self.draw_processes(body_top, body_bottom, w)
            footer = "↑/↓ 移动  ←/→ 分类  / 过滤  Enter 详情  k KILL  R 刷新  Esc 返回"
        elif screen == "process_detail":
            self.draw_detail(body_top, body_bottom, w)
            footer = "↑/↓ 滚动  t TERM  k/9 KILL  z STOP  c CONT  r 刷新  Esc 返回"
        elif screen == "network":
            self.draw_network(body_top, body_bottom, w)
            footer = "↑/↓ 移动  ←/→ 切换视图  / 过滤  Enter 详情  R 刷新  Esc 返回"
        elif screen == "services":
            self.draw_services(body_top, body_bottom, w)
            footer = "↑/↓ 移动  / 过滤  f 仅失败  Enter 详情  R 刷新  Esc 返回"
        elif screen == "service_detail":
            self.draw_detail(body_top, body_bottom, w)
            footer = "↑/↓ 滚动  s 启动  x 停止  r 重启  e 启用  d 禁用  R 刷新  Esc 返回"
        elif screen in ("system_info", "hardware"):
            self.draw_topics(body_top, body_bottom, w, screen)
            footer = "↑/↓ 选择   Enter 查看详情   R 刷新   Esc 返回"
        elif screen == "logs":
            self.draw_logs(body_top, body_bottom, w)
            footer = "↑/↓ 移动   Enter 查看   R 刷新   Esc 返回"
        elif screen == "detail":
            self.draw_detail(body_top, body_bottom, w)
            footer = "↑/↓ 滚动  PgUp/PgDn 翻页  r 刷新  Esc 返回"
        else:
            footer = "Esc 返回"
        self.draw_footer(h - 1, w, footer)
        self.stdscr.refresh()

    def draw_header(self, h: int, w: int) -> None:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        title = f" {APP_NAME} v{APP_VERSION} "
        left = f"{title} {self.identity['hostname']}  root  {now}"
        self.add(0, 0, left, w, curses.A_BOLD | self.color(1))
        total_mem, used_mem, swap_total, swap_used = self.mem_summary()
        mem_pct = 100.0 * used_mem / total_mem if total_mem else 0.0
        swap_pct = 100.0 * swap_used / swap_total if swap_total else 0.0
        temp_attr = self.color(4) if self.max_temp is not None and self.max_temp >= 80 else self.color(2)
        if self.max_temp is not None and self.max_temp >= 70:
            temp_attr = self.color(3)
        self.add(
            1,
            0,
            f" Uptime {human_duration(self.collector.uptime_seconds())} | "
            f"Load {self.loads[0]:.2f}/{self.loads[1]:.2f}/{self.loads[2]:.2f} | "
            f"CPU {fmt_float(self.cpu_usage, '%')} | "
            f"Mem {mem_pct:.0f}% ({human_bytes(used_mem)}/{human_bytes(total_mem)}) | "
            f"Swap {swap_pct:.0f}% | Temp {fmt_float(self.max_temp, '°C')}",
            w,
            curses.A_BOLD | temp_attr,
        )
        try:
            self.stdscr.addstr(2, 0, "─" * w, self.color(1))
        except curses.error:
            pass

    def draw_footer(self, y: int, w: int, footer: str) -> None:
        if self.message and time.monotonic() <= self.message_until:
            text = f" {self.message}  |  {footer}"
            attr = curses.A_REVERSE | self.color(2)
        else:
            text = f" {footer}"
            attr = curses.A_REVERSE
        self.add(y, 0, pad_display(text, w), w, attr)

    def draw_overview(self, top: int, bottom: int, w: int) -> None:
        cur = self.current()
        items = self.overview_items()
        cur["sel"] = min(cur["sel"], len(items) - 1)
        self.add(top, 2, "功能总览", w - 4, curses.A_BOLD | self.color(1))
        self.add(top + 1, 2, "所有系统管理功能均从这里进入。按 Enter 查看具体信息。", w - 4, curses.A_DIM)
        start = top + 3
        for idx, item in enumerate(items):
            if start + idx >= bottom:
                break
            selected = idx == cur["sel"]
            marker = "▶" if selected else " "
            number = f"{idx + 1:02d}"
            title_width = 18
            line = f" {marker} [{number}] {pad_display(item['title'], title_width)} {item['summary']}"
            attr = curses.A_REVERSE | (self.color(6) if self.has_color else 0) if selected else 0
            self.add(start + idx, 1, pad_display(line, w - 2), w - 2, attr)
        info_y = start + len(items) + 1
        if info_y < bottom:
            pc = self.process_counts()
            _, _, failed = self.service_counts()
            warn_attr = self.color(4) if pc["zombie"] or failed else self.color(2)
            self.add(
                info_y,
                2,
                f"状态：{pc['total']} 进程 / {pc['zombie']} 僵尸 / {failed} 失败服务 / "
                f"{self.interface_count} 网络接口 / 温度 {fmt_float(self.max_temp, '°C')}",
                w - 4,
                curses.A_BOLD | warn_attr,
            )

    def draw_tabs(self, y: int, w: int, tabs: list[str], selected: int) -> None:
        x = 1
        for idx, label in enumerate(tabs):
            text = f" {label} "
            attr = curses.A_REVERSE | self.color(6) if idx == selected else curses.A_BOLD
            self.add(y, x, text, max(0, w - x - 1), attr)
            x += display_width(text) + 1
            if x >= w - 2:
                break

    def draw_processes(self, top: int, bottom: int, w: int) -> None:
        cur = self.current()
        procs = self.filtered_processes()
        if procs:
            cur["sel"] = min(cur["sel"], len(procs) - 1)
        tab = cur.get("tab", 0)
        self.draw_tabs(top, w, [f"{name}" for name, _ in PROCESS_TABS], tab)
        title = f"进程管理  过滤: {cur.get('filter') or '无'}  共 {len(procs)} 条"
        self.add(top + 1, 1, title, w - 2, curses.A_BOLD)
        header_y = top + 2
        if w >= 100:
            cols = [("PID", 7, "right"), ("USER", 12, "left"), ("STAT", 6, "left"), ("CPU%", 7, "right"), ("MEM%", 7, "right"), ("ELAPSED", 10, "left"), ("COMMAND", max(10, w - 61), "left")]
        else:
            cols = [("PID", 7, "right"), ("STAT", 6, "left"), ("CPU%", 7, "right"), ("COMMAND", max(10, w - 24), "left")]
        line = " " + " ".join(pad_display(name, width, align) for name, width, align in cols)
        self.add(header_y, 0, line, w, curses.A_BOLD | self.color(1))
        rows_top = header_y + 1
        visible = max(0, bottom - rows_top)
        cur["scroll"] = max(0, min(cur.get("scroll", 0), max(0, len(procs) - visible)))
        if procs and cur["sel"] < cur["scroll"]:
            cur["scroll"] = cur["sel"]
        if procs and cur["sel"] >= cur["scroll"] + visible:
            cur["scroll"] = cur["sel"] - visible + 1
        for offset in range(visible):
            idx = cur["scroll"] + offset
            if idx >= len(procs):
                break
            p = procs[idx]
            if w >= 100:
                values = [
                    (str(p.pid), 7, "right"),
                    (p.user, 12, "left"),
                    (p.state, 6, "left"),
                    (f"{p.cpu:.1f}", 7, "right"),
                    (f"{p.mem_pct:.1f}", 7, "right"),
                    (human_duration(p.elapsed), 10, "left"),
                    (p.args or p.comm, max(10, w - 61), "left"),
                ]
            else:
                values = [
                    (str(p.pid), 7, "right"),
                    (p.state, 6, "left"),
                    (f"{p.cpu:.1f}", 7, "right"),
                    (p.args or p.comm, max(10, w - 24), "left"),
                ]
            line = " " + " ".join(pad_display(value, width, align) for value, width, align in values)
            attr = curses.A_REVERSE | (self.color(6) if self.has_color else 0) if idx == cur["sel"] else 0
            if p.state == "Z":
                attr = attr or self.color(4)
            self.add(rows_top + offset, 0, pad_display(line, w), w, attr)

    def draw_network(self, top: int, bottom: int, w: int) -> None:
        cur = self.current()
        tab = cur.get("tab", 0)
        self.draw_tabs(top, w, NETWORK_TABS, tab)
        rows = self.network_rows()
        self.add(top + 1, 1, f"网络状态 · {NETWORK_TABS[tab]} · {len(rows)} 条", w - 2, curses.A_BOLD)
        rows_top = top + 2
        visible = max(0, bottom - rows_top)
        if rows:
            cur["sel"] = min(cur["sel"], len(rows) - 1)
            if cur["sel"] < cur.get("scroll", 0):
                cur["scroll"] = cur["sel"]
            elif cur["sel"] >= cur.get("scroll", 0) + visible:
                cur["scroll"] = cur["sel"] - visible + 1
        else:
            self.add(rows_top, 2, "(无数据)", w - 4, curses.A_DIM)
            return
        for offset in range(visible):
            idx = cur.get("scroll", 0) + offset
            if idx >= len(rows):
                break
            row = rows[idx]
            attr = curses.A_REVERSE | (self.color(6) if self.has_color else 0) if idx == cur["sel"] else 0
            self.add(rows_top + offset, 0, pad_display(" " + row, w), w, attr)

    def draw_services(self, top: int, bottom: int, w: int) -> None:
        cur = self.current()
        services = self.filtered_services()
        if services:
            cur["sel"] = min(cur["sel"], len(services) - 1)
        try:
            _total, active, failed = self.service_counts()
        except Exception:
            active = failed = 0
        mode = "仅失败" if cur.get("failed_only") else "全部"
        self.add(top, 1, f"服务管理 · {mode} · 活跃 {active} · 失败 {failed} · 当前 {len(services)}", w - 2, curses.A_BOLD | (self.color(4) if failed else 0))
        header_y = top + 1
        cols = [("UNIT", min(42, max(18, w // 2)), "left"), ("LOAD", 9, "left"), ("ACTIVE", 10, "left"), ("SUB", 12, "left"), ("DESCRIPTION", max(10, w - 76), "left")]
        self.add(header_y, 0, " " + " ".join(pad_display(n, ww, al) for n, ww, al in cols), w, curses.A_BOLD | self.color(1))
        rows_top = header_y + 1
        visible = max(0, bottom - rows_top)
        if services:
            if cur["sel"] < cur.get("scroll", 0):
                cur["scroll"] = cur["sel"]
            elif cur["sel"] >= cur.get("scroll", 0) + visible:
                cur["scroll"] = cur["sel"] - visible + 1
        for offset in range(visible):
            idx = cur.get("scroll", 0) + offset
            if idx >= len(services):
                break
            s = services[idx]
            values = [
                (s.unit, cols[0][1], "left"),
                (s.load, 9, "left"),
                (s.active, 10, "left"),
                (s.sub, 12, "left"),
                (s.description, cols[4][1], "left"),
            ]
            line = " " + " ".join(pad_display(v, ww, al) for v, ww, al in values)
            attr = curses.A_REVERSE | (self.color(6) if self.has_color else 0) if idx == cur["sel"] else 0
            if s.active == "failed":
                attr = attr or self.color(4)
            self.add(rows_top + offset, 0, pad_display(line, w), w, attr)

    def draw_topics(self, top: int, bottom: int, w: int, screen: str) -> None:
        cur = self.current()
        topics = SYSTEM_TOPICS if screen == "system_info" else HARDWARE_TOPICS
        summaries = self.topic_summaries(screen)
        cur["sel"] = min(cur["sel"], len(topics) - 1)
        title = "系统信息" if screen == "system_info" else "磁盘与硬件"
        self.add(top, 1, title, w - 2, curses.A_BOLD | self.color(1))
        self.add(top + 1, 1, "Enter 查看完整详情 · Esc 返回", w - 2, curses.A_DIM)
        start = top + 3
        for idx, (topic_id, label, desc) in enumerate(topics):
            if start + idx >= bottom:
                break
            selected = idx == cur["sel"]
            summary = summaries.get(topic_id, desc)
            line = f" {'▶' if selected else ' '} [{idx + 1:02d}] {pad_display(label, 18)} {summary}"
            attr = curses.A_REVERSE | (self.color(6) if self.has_color else 0) if selected else 0
            self.add(start + idx, 1, pad_display(line, w - 2), w - 2, attr)

    def draw_logs(self, top: int, bottom: int, w: int) -> None:
        cur = self.current()
        if self.logs:
            cur["sel"] = min(cur["sel"], len(self.logs) - 1)
        self.add(top, 1, f"日志与告警 · 本次启动 warning 及以上 · {len(self.logs)} 条", w - 2, curses.A_BOLD | self.color(3))
        rows_top = top + 1
        visible = max(0, bottom - rows_top)
        if self.logs:
            if cur["sel"] < cur.get("scroll", 0):
                cur["scroll"] = cur["sel"]
            elif cur["sel"] >= cur.get("scroll", 0) + visible:
                cur["scroll"] = cur["sel"] - visible + 1
        for offset in range(visible):
            idx = cur.get("scroll", 0) + offset
            if idx >= len(self.logs):
                break
            line = self.logs[idx]
            attr = curses.A_REVERSE | (self.color(6) if self.has_color else 0) if idx == cur["sel"] else 0
            self.add(rows_top + offset, 0, pad_display(" " + line, w), w, attr)

    def draw_detail(self, top: int, bottom: int, w: int) -> None:
        cur = self.current()
        ctx = cur.get("context", {})
        lines = ctx.get("lines", [])
        title = str(ctx.get("title", "详情"))
        self.add(top, 1, title, w - 2, curses.A_BOLD | self.color(1))
        self.add(top + 1, 1, f"第 {cur.get('scroll', 0) + 1} / {max(1, len(lines))} 行", w - 2, curses.A_DIM)
        rows_top = top + 2
        visible = max(0, bottom - rows_top)
        max_scroll = max(0, len(lines) - visible)
        cur["scroll"] = max(0, min(cur.get("scroll", 0), max_scroll))
        for offset in range(visible):
            idx = cur["scroll"] + offset
            if idx >= len(lines):
                break
            self.add(rows_top + offset, 1, lines[idx], w - 2)


# ---------------------------------------------------------------------------
# Entry point / self-test
# ---------------------------------------------------------------------------

HELP_TEXT = """SYSTEM MAMAGER - Linux 系统统一管理终端

用法:
  sudo /home/tony/.applications/system_mamager/system_mamager [选项]

选项:
  --self-test    以 root 权限采集一次数据并检查关键功能
  --version      显示版本
  -h, --help     显示本帮助

界面:
  总览使用 ↑/↓ 选择，Enter 进入，Esc 返回，q 退出。
  进程/网络页面用 ←/→ 切换分类；/ 可以过滤；进程列表按 k 可直接 SIGKILL。
  进程详情可发送 TERM/KILL/STOP/CONT 信号。
  服务详情可启动、停止、重启、启用或禁用服务。

该程序只使用 Python 标准库；数据来自 /proc、/sys 和系统自带命令。
"""


def self_test() -> int:
    if os.geteuid() != 0:
        print("self-test 需要 root 权限：sudo python3 system_mamager.py --self-test", file=sys.stderr)
        return 1
    print(f"{APP_NAME} {APP_VERSION} self-test")
    collector = Collector()
    errors: list[str] = []
    identity = collector.identity()
    print(f"host: {identity['hostname']}  kernel: {identity['kernel']}  python: {platform.python_version()}")
    collector.cpu_usage()
    processes = collector.list_processes()
    time.sleep(0.35)
    processes = collector.list_processes()
    if not processes:
        errors.append("进程采集为空")
    zombie_count = sum(1 for p in processes if p.state == "Z")
    daemon_count = sum(1 for p in processes if p.daemon)
    print(f"processes: {len(processes)}  running: {sum(1 for p in processes if p.state == 'R')}  daemons: {daemon_count}  zombies: {zombie_count}")
    services = collector.list_services()
    if not services:
        errors.append("systemd 服务采集为空")
    print(f"services: {len(services)}  failed: {sum(1 for s in services if s.active == 'failed')}")
    interfaces = collector.list_interfaces()
    connections = collector.list_connections()
    if not interfaces:
        errors.append("网络接口采集为空")
    print(f"network: interfaces={len(interfaces)} connections={len(connections)}")
    mem = collector.memory_info()
    if not mem.get("MemTotal"):
        errors.append("内存信息采集失败")
    print(f"memory: {human_bytes(mem.get('MemTotal', 0))}  swap: {human_bytes(mem.get('SwapTotal', 0))}")
    temp, fan = collector.temperature_summary()
    print(f"thermal: max_temp={fmt_float(temp, '°C')} fan={str(fan) + ' RPM' if fan is not None else 'N/A'}")
    host_info = collector.system_topic_content("host")
    if not host_info:
        errors.append("系统信息主题采集为空")
    print(f"system_topic_host_lines: {len(host_info)}")
    for tab, label in ((4, "firewall"), (5, "proxy"), (6, "security")):
        headings, tab_lines = collector.network_tab(tab)
        print(f"network_{label}: {len(tab_lines)} lines")
        if not tab_lines:
            errors.append(f"网络 {label} 信息采集为空")
    logs = collector.recent_logs()
    print(f"recent_warning_logs: {len(logs)}")
    if errors:
        print("RESULT: FAILED")
        for error in errors:
            print(f" - {error}")
        return 1
    print("RESULT: OK")
    print("root-only curses TUI imports and non-interactive collectors are working.")
    return 0


def run_tui(stdscr: "curses.window") -> None:
    App(stdscr).run()


def main(argv: list[str]) -> int:
    if "--version" in argv:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    if "-h" in argv or "--help" in argv:
        print(HELP_TEXT)
        return 0
    if os.geteuid() != 0:
        print("SYSTEM MAMAGER 需要 root 权限。", file=sys.stderr)
        print("请使用：sudo /home/tony/.applications/system_mamager/system_mamager", file=sys.stderr)
        return 1
    if "--self-test" in argv:
        return self_test()
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("该终端界面需要一个 TTY。请在终端中运行。", file=sys.stderr)
        return 1
    try:
        curses.wrapper(run_tui)
    except KeyboardInterrupt:
        return 130
    except curses.error as exc:
        print(f"curses 初始化失败: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
