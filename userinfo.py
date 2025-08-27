import os
import sys
import platform
import socket
import uuid
import locale
import getpass
import datetime
import subprocess
from pathlib import Path

OUT_FILE = "UserInformation.txt"

import ctypes

def get_total_ram_mb() -> str:
    """Return total RAM in MB (Windows)."""
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return f"{round(stat.ullTotalPhys / (1024**2), 1)} MB"
    except Exception:
        pass
    return "Unknown"


def get_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "Unknown"

def get_timezone() -> str:
    try:
        from datetime import datetime
        import tzlocal
        return str(tzlocal.get_localzone())
    except Exception:
        return datetime.now().astimezone().tzname()

def get_resolution() -> str:
    try:
        import ctypes
        user32 = ctypes.windll.user32
        user32.SetProcessDPIAware()
        return f"{{Width={user32.GetSystemMetrics(0)}, Height={user32.GetSystemMetrics(1)}}}"
    except Exception:
        return "Unknown"

def get_hwid() -> str:
    try:
        return uuid.UUID(int=uuid.getnode()).hex.upper()
    except Exception:
        return "Unknown"

def get_antivirus() -> str:
    try:
        out = subprocess.check_output(
            ["powershell", "-Command", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName"],
            stderr=subprocess.DEVNULL
        )
        return "\n".join([line.strip() for line in out.decode().splitlines() if line.strip()])
    except Exception:
        return "Unknown"

def main():
    uname = platform.uname()
    info = {
        "Build ID": str(uuid.uuid4())[:8],  # random build ID
        "IP": get_ip(),
        "FileLocation": sys.executable,
        "UserName": getpass.getuser(),
        "Country": os.environ.get("LANG", "Unknown"),
        "Zip Code": "Unknown",
        "Location": "Unknown",
        "HWID": get_hwid(),
        "Current Language": locale.getdefaultlocale()[0] or "Unknown",
        "ScreenSize": get_resolution(),
        "TimeZone": get_timezone(),
        "Operation System": f"{uname.system} {uname.release} {platform.architecture()[0]}",
        "UAC": "Unknown",
        "Process Elevation": "False",
        "Log date": datetime.datetime.now().strftime("%m/%d/%Y %I:%M:%S %p"),
    }

    lines = []
    lines.append("**********************************************")
    lines.append("*            User Information Export         *")
    lines.append("**********************************************\n")
    for k, v in info.items():
        lines.append(f"{k}: {v}")
    lines.append("\nAvailable KeyboardLayouts: ")
    lines.append(locale.getdefaultlocale()[0] or "Unknown")
    lines.append("\nHardwares: ")
    lines.append(f"Name: {uname.processor}")
    lines.append(f"Name: Total of RAM, {get_total_ram_mb()}")
    lines.append("\nAnti-Viruses: ")
    lines.append(get_antivirus())

    out_path = Path(OUT_FILE)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[Done] Wrote {out_path.resolve()}")

if __name__ == "__main__":
    main()
