"""
Process Information Collector Module
Refactored from process_list.py for better integration
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

def write_blocks(path: Path, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            pid = row.get("ProcessId") or row.get("PID") or row.get("Id") or ""
            name = row.get("Name") or ""
            cmd  = row.get("CommandLine") or ""
            if isinstance(cmd, str):
                cmd = " ".join(cmd.split())
            f.write(f"ID: {pid}, Name: {name}, CommandLine: {cmd}\n")
            f.write("===============\n")

def normalize_json_list(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        return [obj]
    return []

def fetch_via_powershell() -> Optional[List[Dict[str, Any]]]:
    if not shutil.which("powershell"):
        return None
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,CommandLine | "
        "ConvertTo-Json -Depth 3"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        data = json.loads(out.decode("utf-8", "ignore") or "[]")
        rows = normalize_json_list(data)
        for r in rows:
            r.setdefault("ProcessId", r.get("ProcessID"))
            r.setdefault("Name", r.get("ExecutablePath") or r.get("Caption") or r.get("Name"))
            r.setdefault("CommandLine", r.get("CommandLine"))
        return rows
    except Exception:
        return None

def fetch_via_psutil() -> Optional[List[Dict[str, Any]]]:
    try:
        import psutil
    except Exception:
        return None
    rows: List[Dict[str, Any]] = []
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            info = p.info
            pid = info.get("pid")
            name = info.get("name") or ""
            cmdl = info.get("cmdline") or []
            cmd = " ".join(cmdl) if isinstance(cmdl, list) else (cmdl or "")
            rows.append({"ProcessId": pid, "Name": name, "CommandLine": cmd})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rows

def fetch_via_wmic() -> Optional[List[Dict[str, Any]]]:
    if not shutil.which("wmic"):
        return None
    cmd = [
        "wmic", "process",
        "get", "ProcessId,Name,CommandLine",
        "/FORMAT:CSV"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        text = out.decode("utf-8", "ignore")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        rows: List[Dict[str, Any]] = []
        headers: List[str] = []
        for ln in lines:
            parts = [p for p in ln.split(",")]
            if not headers:
                headers = parts
                continue
            if len(parts) != len(headers):
                continue
            rec = dict(zip(headers, parts))
            rows.append({
                "ProcessId": rec.get("ProcessId"),
                "Name": rec.get("Name"),
                "CommandLine": rec.get("CommandLine"),
            })
        return rows
    except Exception:
        return None

def collect_processes(output_file: str):
    """Collect running processes information and save to file"""
    if os.name != "nt":
        print("This script must be run on Windows.")
        return False

    rows = (
        fetch_via_powershell()
        or fetch_via_psutil()
        or fetch_via_wmic()
        or []
    )

    def _pid(x: Dict[str, Any]) -> int:
        try:
            return int(x.get("ProcessId") or 0)
        except Exception:
            return 0
    rows.sort(key=_pid)

    out_path = Path(output_file)
    write_blocks(out_path, rows)
    print(f"[Done] Wrote {out_path.resolve()} with {len(rows)} processes.")
    return True
