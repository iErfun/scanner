#!/usr/bin/env python3
"""
Simple metadata / EXIF extractor for images and basic document info.
Authorized testing / forensics only.
"""
import os
import sys
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import mutagen
    HAS_MUTAGEN = True
except ImportError:
    HAS_MUTAGEN = False


class C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GLD = "\033[38;2;239;190;112m"
    CRM = "\033[38;2;232;112;125m"


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def extract_image_exif(path: str) -> dict:
    data = {}
    if not HAS_PIL:
        return {"error": "Pillow not installed (pip install Pillow)"}
    try:
        img = Image.open(path)
        data["format"] = img.format
        data["size"] = f"{img.width}x{img.height}"
        data["mode"] = img.mode
        exif = img._getexif()
        if not exif:
            data["exif"] = {}
            return data
        decoded = {}
        for tag_id, value in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo" and isinstance(value, dict):
                gps = {}
                for t, v in value.items():
                    gps[GPSTAGS.get(t, t)] = v
                decoded["GPSInfo"] = gps
            else:
                try:
                    decoded[str(tag)] = str(value)[:200]
                except Exception:
                    decoded[str(tag)] = "<unreadable>"
        data["exif"] = decoded
    except Exception as e:
        data["error"] = str(e)
    return data


def extract_basic_file_info(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"error": f"File not found: {path}"}
    st = p.stat()
    info = {
        "path": str(p.resolve()),
        "name": p.name,
        "size_bytes": st.st_size,
        "size_human": _human_size(st.st_size),
        "modified": __import__("datetime").datetime.fromtimestamp(st.st_mtime).isoformat(),
        "extension": p.suffix.lower(),
    }
    return info


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".gif", ".bmp"}


def analyze_file(path: str) -> dict:
    info = extract_basic_file_info(path)
    if "error" in info:
        return info
    ext = info.get("extension", "")
    if ext in IMAGE_EXTS:
        info["image"] = extract_image_exif(path)
    return info


def run():
    _clear()
    print(f"{C.GLD}{C.B}")
    print("  METADATA EXTRACTOR")
    print(f"{C.R}")
    print(f"{C.D}  Extract basic file info and image EXIF (if Pillow installed){C.R}\n")

    if not HAS_PIL:
        print(f"{C.YEL}[!] Pillow not installed — only basic file info available{C.R}")
        print(f"{C.D}    pip install Pillow{C.R}\n")

    path = input(f"{C.CYN}[?] File or directory path: {C.R}").strip().strip('"').strip("'")
    if not path:
        print(f"{C.RED}[!] No path given{C.R}")
        input(f"\n{C.D}Enter to continue...{C.R}")
        return

    p = Path(path)
    files = []
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = [f for f in p.rglob("*") if f.is_file()][:50]
        print(f"{C.CYN}[*] Scanning up to 50 files in directory...{C.R}")
    else:
        print(f"{C.RED}[!] Path does not exist{C.R}")
        input(f"\n{C.D}Enter to continue...{C.R}")
        return

    for f in files:
        print(f"\n{C.GLD}{'─' * 50}{C.R}")
        result = analyze_file(str(f))
        if "error" in result and "path" not in result:
            print(f"{C.RED}[!] {result['error']}{C.R}")
            continue
        print(f"{C.GRN}File:{C.R} {result.get('name')}")
        print(f"  Path:     {result.get('path')}")
        print(f"  Size:     {result.get('size_human')} ({result.get('size_bytes')} bytes)")
        print(f"  Modified: {result.get('modified')}")
        img = result.get("image")
        if img:
            if "error" in img:
                print(f"  {C.YEL}Image: {img['error']}{C.R}")
            else:
                print(f"  Format:   {img.get('format')}  Size: {img.get('size')}  Mode: {img.get('mode')}")
                exif = img.get("exif") or {}
                if exif:
                    print(f"  {C.CYN}EXIF:{C.R}")
                    for k, v in list(exif.items())[:20]:
                        print(f"    {k}: {v}")
                    if len(exif) > 20:
                        print(f"    ... +{len(exif)-20} more tags")
                else:
                    print(f"  {C.D}No EXIF data{C.R}")

    print()
    input(f"{C.D}Enter to continue...{C.R}")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRM}Bye{C.R}")
