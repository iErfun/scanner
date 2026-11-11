import os
import re
import sys
import time
import random
import itertools
from datetime import datetime


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    ORANGE = '\033[38;2;255;165;0m'
    DIM_GRAY = '\033[38;2;137;151;171m'
    NEON_CYAN = '\033[38;2;82;190;255m'
    NEON_PURPLE = '\033[38;2;151;145;235m'
    FRAME = '\033[38;2;138;92;246m'
    CRIMSON = '\033[38;2;232;112;125m'
    GOLD = '\033[38;2;239;190;112m'
    DIM = '\033[2m'


C = Colors
ANSI_RE = re.compile(r'\033\[[0-9;]*m')

# memory cap for dedup — beyond this, dedup is disabled to avoid OOM on huge targets
MAX_SEEN = 2_000_000


# ---------- helpers ----------
def visible_len(text):
    return len(ANSI_RE.sub('', text))


def pad(text, width, align="left"):
    diff = max(width - visible_len(text), 0)
    if align == "left":
        return text + " " * diff
    if align == "right":
        return " " * diff + text
    left = diff // 2
    right = diff - left
    return " " * left + text + " " * right


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ---------- banner ----------
def print_banner():
    print(f"""{C.RED }{C.BOLD}
██     ██ ▄████▄ █████▄  ████▄  ██     ██ ▄█████ ██████   
██ ▄█▄ ██ ██  ██ ██▄▄██▄ ██  ██ ██     ██ ▀▀▀▄▄▄   ██     
 ▀██▀██▀  ▀████▀ ██   ██ ████▀  ██████ ██ █████▀   ██
{C.RESET}""")


# ---------- constants ----------
LEET = {
    "a": ["a", "4", "@"], "e": ["e", "3"], "i": ["i", "1", "!"],
    "o": ["o", "0"], "s": ["s", "5", "$"], "t": ["t", "7"],
    "g": ["g", "9"], "b": ["b", "8"], "l": ["l", "1"],
}

SYMBOLS = ["!", "@", "#", "$", ".", "_", "-"]
LATIN_YEARS = list(range(1950, 2031))
PERSIAN_YEARS = list(range(1350, 1421))
COMMON_SUFFIX = [
    "123", "1234", "12345", "123456", "1", "12", "007", "69", "777",
    "2024", "2023", "2022", "2021", "2020", "111", "000", "321",
]

KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "123456", "1234567890", "qazwsx", "qweasd", "1q2w3e4r", "123qwe",
    "zaq12wsx", "1qaz2wsx", "1234qwer", "qwer1234", "abc123",
]

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "shadow", "superman", "batman",
    "football", "baseball", "sunshine", "princess", "iloveyou",
    "trustno1", "michael", "jennifer", "daniel", "jessica", "charlie",
    "hunter", "ranger", "buster", "soccer", "hockey", "killer",
    "george", "robert", "thomas", "matthew", "andrew", "joshua",
    "pepper", "ginger", "cheese", "freedom", "whatever", "computer",
    "internet", "starwars", "pokemon", "minecraft", "google",
]


# ---------- cleaning ----------
def clean_word(w):
    return "".join(c for c in (w or "").strip().lower() if c.isalnum())


def clean_output(line):
    """Return clean line or None to skip."""
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    line = "".join(c for c in line if c.isprintable() and c not in "\t\r\n")
    if not line or len(line) > 128:
        return None
    return line


# ---------- variants ----------
def leet_variants(word, max_out=20):
    """Bounded leet variants (avoids combinatorial explosion)."""
    word = clean_word(word)
    if not word:
        return []
    options = [LEET.get(ch, [ch]) for ch in word]
    out = []
    for combo in itertools.product(*options):
        out.append("".join(combo))
        if len(out) >= max_out:
            break
    return out


def case_variants(word):
    word = clean_word(word)
    if not word:
        return []
    return list({word.lower(), word.upper(), word.capitalize()})


def word_expander(words):
    out = set()
    for w in words:
        wc = clean_word(w)
        if not wc:
            continue
        out.update(case_variants(wc))
        out.update(leet_variants(wc))
    return list(out)


# ---------- streams ----------
def stream_basic(base):
    for w in base:
        yield w
    for w in base:
        for y in LATIN_YEARS:
            yield f"{w}{y}"
            yield f"{y}{w}"
        for y in PERSIAN_YEARS:
            yield f"{w}{y}"
            yield f"{y}{w}"
    for w in base:
        for s in COMMON_SUFFIX:
            yield f"{w}{s}"
            yield f"{s}{w}"
    for w in base:
        for s in SYMBOLS:
            for y in LATIN_YEARS:
                yield f"{w}{s}{y}"


def stream_combinations(base):
    for a in base:
        for b in base:
            if a == b:
                continue
            yield f"{a}{b}"
            yield f"{a}.{b}"
            yield f"{a}_{b}"
            yield f"{a}-{b}"
    for a in base:
        for b in base:
            if a == b:
                continue
            for y in LATIN_YEARS[::3]:
                yield f"{a}{b}{y}"
                yield f"{a}{y}{b}"


def stream_symbols(base):
    for w in base:
        for s in SYMBOLS:
            for n in range(0, 1000):
                yield f"{w}{s}{n:03d}"
    for w in base:
        for s in SYMBOLS:
            for y in LATIN_YEARS:
                yield f"{w}{s}{y}{s}"


def stream_keyboard(base):
    """Keyboard patterns + top common passwords, independent of input."""
    for p in KEYBOARD_PATTERNS + COMMON_PASSWORDS:
        yield p
        for s in COMMON_SUFFIX[:8]:
            yield f"{p}{s}"
        for s in ("!", "@", "#"):
            yield f"{p}{s}"


def stream_random(base):
    base = base or ["user"]
    while True:
        w1 = random.choice(base)
        w2 = random.choice(base) if random.random() > 0.5 else ""
        sep = random.choice(SYMBOLS) if random.random() > 0.5 else ""
        num = random.choice([
            str(random.randint(0, 99)),
            str(random.randint(1950, 2030)),
            random.choice(COMMON_SUFFIX),
        ])
        caps = random.choice([str.lower, str.upper, str.capitalize])
        pw = f"{caps(w1)}{sep}{caps(w2)}{num}"
        if random.random() > 0.7:
            pw += random.choice(SYMBOLS)
        yield pw


def username_stream(base):
    base = [clean_word(w) for w in base if clean_word(w)] or ["user"]
    for w in base:
        yield w
        for i in range(10000):
            yield f"{w}{i}"
    for a in base:
        for b in base:
            if a == b:
                continue
            yield f"{a}{b}"
            yield f"{a}.{b}"
            yield f"{a}_{b}"
            yield f"{a[0]}{b}"


# ---------- round-robin ----------
def roundrobin(*iterables):
    iterators = [iter(it) for it in iterables]
    while iterators:
        for it in list(iterators):
            try:
                yield next(it)
            except StopIteration:
                iterators.remove(it)


# ---------- dedup ----------
def dedup_add(line, seen):
    if len(seen) < MAX_SEEN:
        if line in seen:
            return False
        seen.add(line)
        return True
    return True  # dedup disabled after cap


# ---------- progress ----------
def print_progress(written, target, start_time, last_update):
    now = time.time()
    if now - last_update < 0.4:
        return last_update
    elapsed = now - start_time
    speed = written / elapsed if elapsed > 0 else 0
    remaining = max(target - written, 0)
    eta = remaining / speed if speed > 0 else 0
    pct = min(written / target * 100, 100) if target else 0
    bar_len = 25
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(
        f"\r  {C.NEON_CYAN}[{bar}]{C.RESET} "
        f"{C.GOLD}{written:,}{C.RESET}/{target:,} "
        f"| {C.GREEN}{speed:,.0f}{C.RESET} l/s "
        f"| ETA {C.YELLOW}{int(eta)}s{C.RESET}   "
    )
    sys.stdout.flush()
    return now


# ---------- writers ----------
def write_stream(path, mode, base, target):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    seen = set()
    written = 0

    if mode == "1":
        streams = [stream_basic(base)]
    elif mode == "2":
        streams = [stream_combinations(base)]
    elif mode == "3":
        streams = [stream_symbols(base)]
    elif mode == "4":
        streams = [stream_keyboard(base), stream_basic(base),
                   stream_combinations(base), stream_symbols(base)]
    else:  # "5" — everything, round-robin
        streams = [stream_keyboard(base), stream_basic(base),
                   stream_combinations(base), stream_symbols(base),
                   stream_random(base)]

    combined = roundrobin(*streams) if mode in ("4", "5") else streams[0]

    start_time = time.time()
    last_update = start_time

    with open(path, "w", encoding="utf-8", errors="ignore") as fout:
        for raw in combined:
            line = clean_output(raw)
            if line is None:
                continue
            if not dedup_add(line, seen):
                continue
            fout.write(line + "\n")
            written += 1
            last_update = print_progress(written, target, start_time, last_update)
            if written >= target:
                break

    print()
    return written


def write_usernames(path, base, target):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    seen = set()
    written = 0
    start_time = time.time()
    last_update = start_time

    with open(path, "w", encoding="utf-8", errors="ignore") as fout:
        for raw in username_stream(base):
            line = clean_output(raw)
            if line is None:
                continue
            if not dedup_add(line, seen):
                continue
            fout.write(line + "\n")
            written += 1
            last_update = print_progress(written, target, start_time, last_update)
            if written >= target:
                break

    print()
    return written


# ---------- UI ----------
def ask(label, default="", hint=""):
    d = f" {C.DIM}[{default}]{C.RESET}" if default else ""
    h = f" {C.DIM_GRAY}{hint}{C.RESET}" if hint else ""
    print(f"  {C.NEON_CYAN}{label}{C.RESET}{h}{d}")
    print(f"  {C.GOLD}>>{C.RESET} ", end="")
    v = input().strip()
    return v if v else default


def ask_words(label, hint=""):
    raw = ask(label, "", hint)
    if not raw or raw.lower() == "skip":
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def ask_target():
    raw = ask("Target lines", "1000000", "(default 1M)")
    try:
        return max(1, int(raw.replace(",", "").replace("_", "")))
    except ValueError:
        return 1_000_000


def step_header(n, total, title):
    print()
    print(f"  {C.FRAME}╭{'─' * 56}╮{C.RESET}")
    print(f"  {C.FRAME}│{C.RESET} {C.DIM}STEP {n}/{total}{C.RESET}  {C.BOLD}{C.WHITE}{title}{C.RESET}"
          f"{' ' * max(0, 56 - len(title) - len(f'STEP {n}/{total}') - 3)}{C.FRAME}│{C.RESET}")
    print(f"  {C.FRAME}╰{'─' * 56}╯{C.RESET}")


def menu():
    width = 54
    print(f"{C.FRAME}╭{'─' * width}╮{C.RESET}")
    print(f"{C.FRAME}│{C.RESET}  {C.NEON_CYAN}{C.BOLD}GENERATOR {C.RESET}{' ' * (width - 12)}{C.FRAME}│{C.RESET}")
    print(f"{C.FRAME}├{'─' * width}┤{C.RESET}")
    for key, label in [("1", "Password wordlist"), ("2", "Username wordlist"), ("0", "Exit")]:
        row = f"  {C.GOLD}{C.BOLD}{key}{C.RESET}   {C.WHITE}{label}{C.RESET}"
        print(f"{C.FRAME}│{C.RESET}{pad(row, width)}{C.FRAME}│{C.RESET}")
    print(f"{C.FRAME}╰{'─' * width}╯{C.RESET}")


def ask_mode():
    print()
    print(f"  {C.NEON_CYAN}Mode{C.RESET}")
    print(f"    {C.GOLD}1{C.RESET}  Basic         {C.DIM}(name, name+year, name+123, name!2024){C.RESET}")
    print(f"    {C.GOLD}2{C.RESET}  Combinations  {C.DIM}(name+family, family+name+year){C.RESET}")
    print(f"    {C.GOLD}3{C.RESET}  Symbols       {C.DIM}(name@000-999, name#year#){C.RESET}")
    print(f"    {C.GOLD}4{C.RESET}  Smart mix     {C.DIM}(keyboard + basic + combos + symbols){C.RESET}")
    print(f"    {C.GOLD}5{C.RESET}  Brute         {C.DIM}(everything + random, biggest output){C.RESET}")
    return ask("Choose mode", "5", "(1-5)")


def finalize(path, lines, kind, elapsed):
    inner = 60
    line = "═" * inner
    print()
    print(f"  {C.FRAME}╔{line}╗{C.RESET}")
    print(f"  {C.FRAME}║{C.RESET}{pad(f'{C.NEON_PURPLE}{C.BOLD}DONE{C.RESET}', inner, 'center')}{C.FRAME}║{C.RESET}")
    print(f"  {C.FRAME}╠{line}╣{C.RESET}")
    rows = [
        ("Type", f"{C.WHITE}{kind}{C.RESET}"),
        ("File", f"{C.NEON_CYAN}{path}{C.RESET}"),
        ("Lines", f"{C.GOLD}{lines:,}{C.RESET}"),
        ("Time", f"{C.GREEN}{elapsed:.1f}s{C.RESET}"),
        ("Speed", f"{C.GREEN}{(lines / elapsed if elapsed else 0):,.0f} l/s{C.RESET}"),
    ]
    for k, v in rows:
        print(f"  {C.FRAME}║{C.RESET}{pad(f'  {C.NEON_CYAN}{k:<7}{C.RESET}{C.DIM_GRAY}:{C.RESET} {v}', inner)}{C.FRAME}║{C.RESET}")
    print(f"  {C.FRAME}╚{line}╝{C.RESET}")


# ---------- flows ----------
def collect_words():
    step_header(1, 3, "Target info")
    names = ask_words("Names (first,last,nick)", "(comma separated)")
    years = ask_words("Years / dates", "(1990, 1375, 2024)")
    extra = ask_words("Other words", "(brands, hobbies, anything)")
    return names + years + extra


def run_password():
    words = collect_words()
    if not words:
        print(f"  {C.CRIMSON}[!] no words provided{C.RESET}")
        return

    step_header(2, 3, "Settings")
    mode = ask_mode()
    target = ask_target()

    step_header(3, 3, "Output")
    out = ask("Output file", "output/passwords.txt")

    print(f"\n  {C.GREEN}base words{C.RESET}: {len(words)}"
          f"  |  {C.GREEN}mode{C.RESET}: {mode}"
          f"  |  {C.GREEN}target{C.RESET}: {target:,}")
    print(f"  {C.DIM}generating...{C.RESET}\n")

    base = word_expander(words)
    t0 = time.time()
    try:
        lines = write_stream(out, mode, base, target)
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}[!] interrupted{C.RESET}")
        return
    finalize(out, lines, "password", time.time() - t0)


def run_username():
    words = collect_words()
    if not words:
        print(f"  {C.CRIMSON}[!] no words provided{C.RESET}")
        return

    step_header(2, 3, "Settings")
    target = ask_target()

    step_header(3, 3, "Output")
    out = ask("Output file", "output/usernames.txt")

    print(f"\n  {C.GREEN}base words{C.RESET}: {len(words)}"
          f"  |  {C.GREEN}target{C.RESET}: {target:,}")
    print(f"  {C.DIM}generating...{C.RESET}\n")

    base = [clean_word(w) for w in words if clean_word(w)]
    t0 = time.time()
    try:
        lines = write_usernames(out, base, target)
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}[!] interrupted{C.RESET}")
        return
    finalize(out, lines, "username", time.time() - t0)


def run():
    while True:
        clear()
        print_banner()
        menu()
        print(f"\n  {C.GOLD}{C.BOLD}>>{C.RESET} ", end="")
        try:
            choice = input().strip() or "1"
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {C.CRIMSON}bye{C.RESET}")
            return

        if choice == "0":
            print(f"  {C.CRIMSON}{C.BOLD}bye{C.RESET}")
            return
        if choice == "1":
            run_password()
        elif choice == "2":
            run_username()
        else:
            print(f"  {C.CRIMSON}[!] invalid{C.RESET}")

        try:
            input(f"\n  {C.DIM}press Enter to continue{C.RESET}")
        except (EOFError, KeyboardInterrupt):
            return


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRIMSON}bye{C.RESET}")
