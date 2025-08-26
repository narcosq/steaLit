import os
import json
import base64
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterable, Tuple, Callable
from collections import defaultdict

# Third-party deps expected:
#   pip install -U browser-cookie3 pywin32 pycryptodome
try:
    from Crypto.Cipher import AES  # pycryptodome
except Exception:
    AES = None  # will error later with a clear message

try:
    import win32crypt  # pywin32
except Exception:
    win32crypt = None  # will error later with a clear message


def convert_to_netscape_time(ts):
    """Convert timestamp to Netscape cookie file format (seconds since epoch)."""
    try:
        return str(int(ts)) if ts else "0"
    except Exception:
        return "0"


def iter_cookies_from(callable_fetch: Callable[[], Iterable],
                      label: str,
                      suppress: bool = True) -> Iterable[Tuple]:
    """
    Yield cookies in Netscape tuple.
    If suppress=True, catches exceptions and logs; if False, lets exceptions bubble up.
    """
    def _iter():
        for c in callable_fetch():
            yield (
                c.domain,
                "TRUE" if c.domain.startswith(".") else "FALSE",
                c.path,
                "TRUE" if getattr(c, "secure", False) else "FALSE",
                convert_to_netscape_time(getattr(c, "expires", 0)),
                c.name,
                c.value,
            )

    if suppress:
        try:
            yield from _iter()
        except Exception as e:
            print(f"[{label}] Skipped: {e!s}")
    else:
        # Do not swallow exceptions -> allow fallback logic to trigger
        yield from _iter()


def chromium_profile_paths(vendor: str):
    """
    Yield tuples (cookie_file, key_file, profile_name) for all profiles of a Chromium-based browser on Windows.
    Tries both 'Network/Cookies' and legacy 'Cookies'.
    vendor examples: 'Google/Chrome', 'Microsoft/Edge'
    """
    base = Path(os.getenv("LOCALAPPDATA", "")) / vendor / "User Data"
    key_file = base / "Local State"
    if not base.exists():
        return

    # Default first, then Profile *
    candidates = [base / "Default"] + sorted(p for p in base.glob("Profile *") if p.is_dir())
    for prof in candidates:
        # Newer location
        cookies_new = prof / "Network" / "Cookies"
        # Legacy location
        cookies_old = prof / "Cookies"
        if cookies_new.exists():
            yield cookies_new, key_file, prof.name
        elif cookies_old.exists():
            yield cookies_old, key_file, prof.name


def with_temp_copy(src: Path) -> Path:
    """Copy DB to a temp file to avoid locks; return temp path."""
    tmpdir = Path(tempfile.mkdtemp(prefix="ck_"))
    dst = tmpdir / src.name
    try:
        shutil.copy2(src, dst)
        return dst
    except Exception as e:
        print(f"[Copy] Could not copy DB '{src}': {e!s}. Will try direct read.")
        return src  # fall back: let browser_cookie3 or sqlite try its own logic


# ----------------------------
# Manual Chromium decryption
# ----------------------------

def _require_crypto_deps():
    if AES is None:
        raise RuntimeError("pycryptodome is not available. Install with: pip install pycryptodome")
    if win32crypt is None:
        raise RuntimeError("pywin32 is not available. Install with: pip install pywin32")


def load_chromium_key(key_file: Path) -> bytes:
    """Get AES key from 'Local State' using DPAPI."""
    _require_crypto_deps()
    try:
        with open(key_file, "r", encoding="utf-8") as f:
            js = json.load(f)
        ek_b64 = js["os_crypt"]["encrypted_key"]  # base64 string
        ek = base64.b64decode(ek_b64)[5:]         # strip 'DPAPI' prefix
        key = win32crypt.CryptUnprotectData(ek, None, None, None, 0)[1]
        if not key:
            raise RuntimeError("DPAPI returned empty key")
        return key
    except Exception as e:
        print(f"[Key] Failed to load/decrypt AES key from '{key_file}': {e!s}")
        return b""


def decrypt_chromium_value(enc: bytes, key: bytes) -> str:
    """
    Decrypt Chromium cookie value.
    Supports 'v10'/'v11'/'v20' headers: 3-byte header + 12-byte nonce + ciphertext + 16-byte tag.
    Legacy format: DPAPI blob.
    """
    _require_crypto_deps()
    if not enc:
        return ""
    try:
        hdr = enc[:3]
        # match b'v' + 2 digits (e.g., v10, v11, v20)
        if len(hdr) == 3 and hdr[0:1] == b"v" and all(48 <= b <= 57 for b in hdr[1:3]):
            nonce = enc[3:15]
            ct = enc[15:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct[:-16], ct[-16:]).decode("utf-8", "ignore")
        # Legacy DPAPI blob
        dec = win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
        return dec.decode("utf-8", "ignore")
    except Exception:
        return ""


def chrome_expires_utc_to_unix(expires_utc: int) -> int:
    """
    Chromium stores expires_utc in microseconds since 1601-01-01.
    Convert to seconds since Unix epoch.
    """
    if not expires_utc or expires_utc <= 0:
        return 0
    # 11644473600000000 = difference between Windows epoch (1601) and Unix epoch (1970) in microseconds
    return (expires_utc - 11644473600000000) // 1000000


def _b2s(x):
    """Return str for mixed bytes/str inputs."""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x).decode("utf-8", "ignore")
    return x or ""


def iter_chromium_cookies_direct(cookie_db: Path, key_file: Path, label: str) -> Iterable[Tuple]:
    """
    Yield Netscape tuples reading the SQLite DB directly (fallback without browser_cookie3).
    Requires:
      - load_chromium_key
      - with_temp_copy
      - chrome_expires_utc_to_unix
      - decrypt_chromium_value
      - convert_to_netscape_time
    """
    key = load_chromium_key(key_file)
    if not key:
        print(f"[{label}] Skipped: cannot obtain AES key")
        return

    src = with_temp_copy(cookie_db)
    try:
        with sqlite3.connect(str(src)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("""
                SELECT
                    host_key AS domain,
                    path,
                    is_secure,
                    expires_utc,
                    name,
                    value,
                    CAST(encrypted_value AS BLOB) AS encrypted_value
                FROM cookies
            """)
            for r in cur:
                # Convert Chromium expires_utc (µs since 1601-01-01) -> Unix seconds
                ts = chrome_expires_utc_to_unix(int(r["expires_utc"] or 0))

                # Prefer plaintext "value"; if empty, decrypt "encrypted_value"
                val = r["value"] or ""
                if not val:
                    encv = r["encrypted_value"]
                    if encv is not None:
                        # ensure bytes
                        if isinstance(encv, memoryview):
                            encv = encv.tobytes()
                        elif isinstance(encv, str):
                            encv = encv.encode("latin1", "ignore")
                        val = decrypt_chromium_value(encv, key) or ""

                yield (
                    _b2s(r["domain"]),
                    "TRUE" if _b2s(r["domain"]).startswith(".") else "FALSE",
                    _b2s(r["path"]),
                    "TRUE" if r["is_secure"] else "FALSE",
                    convert_to_netscape_time(ts),
                    _b2s(r["name"]),
                    _b2s(val),
                )
    except Exception as e:
        print(f"[{label}] Fallback read failed: {e!s}")


# ----------------------------
# Filename helpers
# ----------------------------

def make_chromium_label(vendor: str, prof_name: str, cookie_db: Path) -> str:
    """Return label like 'Google_[Chrome]_Default Network' or 'Microsoft_[Edge]_Profile 1 Network'."""
    if vendor.startswith("Google/Chrome"):
        prefix = "Google_[Chrome]"
    elif vendor.startswith("Microsoft/Edge"):
        prefix = "Microsoft_[Edge]"
    else:
        prefix = vendor  # fallback, shouldn't happen here

    # Detect whether DB came from Network/Cookies or legacy Cookies
    loc = "Network" if any(p.name == "Network" for p in cookie_db.parents) else "Cookies"
    return f"{prefix}_{prof_name} {loc}"


def write_netscape_file(path: Path, items):
    """Write Netscape cookie file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for d in items:
            row = [x if x is not None else "" for x in d]
            f.write(f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}\t{row[4]}\t{row[5]}\t{row[6]}\n")


# ----------------------------
# Main aggregator
# ----------------------------

def get_browser_cookies(output_file="cookies.txt"):
    """Collect cookies from Chrome, Edge, and Firefox, write in Netscape format."""
    # Late import to allow running even if not installed (only Firefox will work without deps)
    try:
        import browser_cookie3 as bc3  # type: ignore
        bc3_version = getattr(__import__('browser_cookie3'), '__version__', 'unknown')
        print(f"[Info] browser_cookie3 version: {bc3_version}")
    except ImportError:
        bc3 = None
        print("[Warn] browser_cookie3 is not installed. Install with: pip install browser-cookie3")

    cookies_data = []
    # Per-profile collectors for Chromium-based browsers
    per_profile = defaultdict(list)  # key: label from make_chromium_label(...), value: list of tuples

    # --- Chrome (enumerate all profiles) ---
    any_chrome = False
    for cookie_db, key_file, prof_name in chromium_profile_paths("Google/Chrome"):
        any_chrome = True
        copy_path = with_temp_copy(cookie_db)
        print(f"[Chrome] Using profile '{prof_name}': {cookie_db}")
        label_fs = make_chromium_label("Google/Chrome", prof_name, cookie_db)

        used_bc3 = False
        batch = []
        if bc3 is not None:
            try:
                # Do NOT suppress exceptions here; we want fallback to trigger if bc3 fails
                batch = list(
                    iter_cookies_from(
                        lambda p=copy_path, k=key_file: bc3.chrome(cookie_file=str(p), key_file=str(k)),
                        f"Chrome:{prof_name}",
                        suppress=False,
                    )
                )
                used_bc3 = True
            except Exception as e:
                print(f"[Chrome:{prof_name}] bc3 failed: {e!s}. Trying direct fallback.")

        if not used_bc3:
            batch = list(iter_chromium_cookies_direct(cookie_db, key_file, f"Chrome:{prof_name}"))

        # accumulate
        if batch:
            cookies_data.extend(batch)
            per_profile[label_fs].extend(batch)

    if not any_chrome:
        print("[Chrome] No explicit profile paths found. Trying auto discovery.")
        if bc3 is not None:
            try:
                batch = list(iter_cookies_from(lambda: bc3.chrome(), "Chrome(auto)", suppress=False))
                if batch:
                    cookies_data.extend(batch)
                    # auto-discovery may mix profiles; write only to combined file
            except Exception as e:
                print(f"[Chrome(auto)] bc3 failed: {e!s}")

    # --- Edge (enumerate all profiles) ---
    any_edge = False
    for cookie_db, key_file, prof_name in chromium_profile_paths("Microsoft/Edge"):
        any_edge = True
        copy_path = with_temp_copy(cookie_db)
        print(f"[Edge] Using profile '{prof_name}': {cookie_db}")
        label_fs = make_chromium_label("Microsoft/Edge", prof_name, cookie_db)

        used_bc3 = False
        batch = []
        if bc3 is not None:
            try:
                batch = list(
                    iter_cookies_from(
                        lambda p=copy_path, k=key_file: bc3.edge(cookie_file=str(p), key_file=str(k)),
                        f"Edge:{prof_name}",
                        suppress=False,
                    )
                )
                used_bc3 = True
            except Exception as e:
                print(f"[Edge:{prof_name}] bc3 failed: {e!s}. Trying direct fallback.")

        if not used_bc3:
            batch = list(iter_chromium_cookies_direct(cookie_db, key_file, f"Edge:{prof_name}"))

        # accumulate
        if batch:
            cookies_data.extend(batch)
            per_profile[label_fs].extend(batch)

    if not any_edge:
        print("[Edge] No explicit profile paths found. Trying auto discovery.")
        if bc3 is not None:
            try:
                batch = list(iter_cookies_from(lambda: bc3.edge(), "Edge(auto)", suppress=False))
                if batch:
                    cookies_data.extend(batch)
                    # auto-discovery may mix profiles; write only to combined file
            except Exception as e:
                print(f"[Edge(auto)] bc3 failed: {e!s}")

    # --- Firefox (auto) ---
    if bc3 is not None:
        # For Firefox we can keep suppress=True; failures here are non-critical
        cookies_data.extend(iter_cookies_from(lambda: bc3.firefox(), "Firefox", suppress=True))
    else:
        print("[Firefox] Skipped because browser_cookie3 is not installed.")

    # Write combined file
    combined = Path(output_file)
    write_netscape_file(combined, cookies_data)
    print(f"[Done] Saved {len(cookies_data)} cookies to {combined}")

    # Write per-profile files (Chromium-only)
    out_dir = combined.parent if combined.parent.as_posix() != "." else Path.cwd()
    for label, items in per_profile.items():
        # exact label as filename + .txt, as requested
        file_path = out_dir / f"{label}.txt"
        write_netscape_file(file_path, items)
        print(f"[Done] Saved {len(items)} cookies to '{file_path.name}'")


if __name__ == "__main__":
    if os.name == "nt":
        print("Info: Run as the same Windows user who used the browsers.")
        print("Info: Close Chrome/Edge/Firefox and disable background apps (chrome://settings/system).")
        print("Info: Avoid running from services/SYSTEM; prefer normal user session.")
    else:
        print("Warn: This script is tailored for Windows DPAPI decryption.")

    get_browser_cookies()