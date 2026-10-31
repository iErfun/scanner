import os
import re
import sys
import json
import random
import string
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
    DIM_GRAY = '\033[38;2;110;110;120m'
    NEON_CYAN = '\033[38;2;0;255;213m'
    NEON_PURPLE = '\033[38;2;191;64;255m'
    CORNFLOWER_BLUE = '\033[38;2;100;149;237m'
    SKY_BLUE = '\033[38;2;135;206;235m'
    FRAME = '\033[38;2;138;92;246m'
    CRIMSON = '\033[38;2;220;20;60m'
    AQUA = '\033[38;2;0;255;255m'
    TEAL = '\033[38;2;0;128;128m'
    GOLD = '\033[38;2;255;215;0m'
    DIM = '\033[2m'


C = Colors
ANSI_RE = re.compile(r'\033\[[0-9;]*m')


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


LEET = {
    "a": ["a", "4", "@"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "g": ["g", "9"],
    "b": ["b", "8"],
    "l": ["l", "1"],
}

SYMBOLS = ["!", "@", "#", "$", ".", "_", "-"]
YEARS_RANGE = list(range(1950, 2031))
COMMON_SUFFIX = [
    "123", "1234", "12345", "123456", "1", "12", "007", "69", "777",
    "2024", "2023", "2022", "2021", "2020", "111", "000", "321",
]


def clean_word(w):
    return "".join(c for c in w.strip().lower() if c.isalnum())


def leet_variants(word):
    word = clean_word(word)
    if not word:
        return []
    chars_options = [LEET.get(ch, [ch]) for ch in word]
    return ["".join(c) for c in itertools.product(*chars_options)]


def case_variants(word):
    word = clean_word(word)
    if not word:
        return []
    v = {word.lower(), word.upper(), word.capitalize()}
    if len(word) > 1:
        v.add(word[0].upper() + word[1:].lower())
    return list(v)


def word_expander(words):
    out = set()
    for w in words:
        w = clean_word(w)
        if not w:
            continue
        out.update(case_variants(w))
        out.update(leet_variants(w))
    return list(out)


# ---------- generators ----------
def stream_basic(words):
    base = word_expander(words)
    for w in base:
        yield w
    for w in base:
        for n in YEARS_RANGE:
            yield f"{w}{n}"
            yield f"{n}{w}"
    for w in base:
        for s in COMMON_SUFFIX:
            yield f"{w}{s}"
            yield f"{s}{w}"
    for w in base:
        for s in SYMBOLS:
            for n in YEARS_RANGE:
                yield f"{w}{s}{n}"


def stream_combinations(words):
    base = word_expander(words)
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
            for y in YEARS_RANGE[::2]:
                yield f"{a}{b}{y}"
                yield f"{a}{y}{b}"


def stream_symbols(words):
    base = word_expander(words)
    for w in base:
        for s1 in SYMBOLS:
            for n in range(0, 1000):
                yield f"{w}{s1}{n:03d}"
    for w in base:
        for s in SYMBOLS:
            for y in YEARS_RANGE:
                yield f"{w}{s}{y}{s}"


def stream_random(words):
    base = word_expander(words) or ["user"]
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


def username_stream(words):
    base = [clean_word(w) for w in words if clean_word(w)] or ["user"]
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


# ---------- writers ----------
def write_stream(path, mode, words, target):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    seen = set()
    written = 0

    streams_map = {
        "1": [stream_basic],
        "2": [stream_combinations],
        "3": [stream_symbols],
        "4": [stream_random],
        "5": [stream_basic, stream_combinations, stream_symbols, stream_random],
    }
    streams = [fn(words) for fn in streams_map.get(mode, [stream_basic])]

    with open(path, "w", encoding="utf-8", errors="ignore") as fout:
        stop = False
        for stream in streams:
            for line in stream:
                line = line.strip()
                if not line or line in seen:
                    continue
                seen.add(line)
                fout.write(line + "\n")
                written += 1
                if written % 100000 == 0:
                    sys.stdout.write(
                        f"\r  {C.NEON_CYAN}writing...{C.RESET} "
                        f"{C.GOLD}{written:,}{C.RESET} lines"
                    )
                    sys.stdout.flush()
                if written >= target:
                    stop = True
                    break
            if stop:
                break

    print()
    return written


def write_usernames(path, words, target):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    seen = set()
    written = 0

    with open(path, "w", encoding="utf-8", errors="ignore") as fout:
        for line in username_stream(words):
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            fout.write(line + "\n")
            written += 1
            if written % 100000 == 0:
                sys.stdout.write(
                    f"\r  {C.NEON_CYAN}writing...{C.RESET} "
                    f"{C.GOLD}{written:,}{C.RESET} lines"
                )
                sys.stdout.flush()
            if written >= target:
                break
    print()
    return written


# ---------- UI ----------
def ask_words(label, hint=""):
    print(f"\n{C.NEON_CYAN}{label}{C.RESET} {C.DIM_GRAY}{hint}{C.RESET}")
    print(f"{C.DIM_GRAY}  (comma separated, empty = skip){C.RESET}")
    print(f"{C.GOLD}>>{C.RESET} ", end="")
    raw = input().strip()
    if not raw or raw.lower() == "skip":
        return []
    return [x.strip() for x in raw.split(",") if x.strip() and x.strip().lower() != "skip"]


def ask_target():
    print(f"\n{C.NEON_CYAN}Target lines{C.RESET} {C.DIM_GRAY}(default 1,000,000){C.RESET}")
    print(f"{C.DIM_GRAY}  ex: 100000 / 5000000 / 50000000{C.RESET}")
    print(f"{C.GOLD}>>{C.RESET} ", end="")
    t = input().strip().replace(",", "").replace("_", "").replace(" ", "")
    try:
        n = int(t) if t else 1_000_000
        return max(1, n)
    except ValueError:
        return 1_000_000


def ask_output(default_name):
    print(f"\n{C.NEON_CYAN}Output file{C.RESET} {C.DIM_GRAY}(default: {default_name}){C.RESET}")
    print(f"{C.GOLD}>>{C.RESET} ", end="")
    p = input().strip()
    return p if p else default_name


def ask_mode():
    print(f"\n{C.NEON_CYAN}Generation mode{C.RESET}")
    print(f"  {C.GOLD}1{C.RESET}  Basic {C.DIM_GRAY}(name, name+year, name+123, ...){C.RESET}")
    print(f"  {C.GOLD}2{C.RESET}  Combinations {C.DIM_GRAY}(name+family, family+name+year, ...){C.RESET}")
    print(f"  {C.GOLD}3{C.RESET}  Symbols {C.DIM_GRAY}(name@123, name#1990# ...){C.RESET}")
    print(f"  {C.GOLD}4{C.RESET}  Random mix {C.DIM_GRAY}(randomly combined){C.RESET}")
    print(f"  {C.GOLD}5{C.RESET}  All {C.DIM_GRAY}(combine all, biggest output){C.RESET}")
    print(f"{C.GOLD}>>{C.RESET} ", end="")
    return input().strip() or "1"


def banner():
    art = r"""
 ██╗    ██╗ ██████╗ ██████╗ ██████╗ ██╗     ██╗███████╗████████╗
 ██║    ██║██╔═══██╗██╔══██╗██╔══██╗██║     ██║██╔════╝╚══██╔══╝
 ██║ █╗ ██║██║   ██║██████╔╝██║  ██║██║     ██║███████╗   ██║   
 ██║███╗██║██║   ██║██╔══██╗██║  ██║██║     ██║╚════██║   ██║   
 ╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝███████╗██║███████║   ██║   
  ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝╚══════╝   ╚═╝   
"""
    print(f"{C.NEON_PURPLE}{C.BOLD}{art}{C.RESET}")
    print(f"{C.NEON_CYAN}{C.BOLD}{'WORDLIST GENERATOR'.center(70)}{C.RESET}")
    print(f"{C.DIM_GRAY}{'build custom wordlists from target info'.center(70)}{C.RESET}")
    print()


def menu():
    width = 54
    print(f"{C.FRAME}╔{'═' * width}╗{C.RESET}")
    print(f"{C.FRAME}║{C.RESET}{pad(f'{C.NEON_CYAN}{C.BOLD}MODULE{C.RESET}', width, 'center')}{C.FRAME}║{C.RESET}")
    print(f"{C.FRAME}╠{'═' * width}╣{C.RESET}")
    for key, label, col in [
        ("1", "Password List", C.NEON_CYAN),
        ("2", "Username List", C.CORNFLOWER_BLUE),
        ("0", "Exit", C.CRIMSON),
    ]:
        row = f"  {C.GOLD}{C.BOLD}{key}{C.RESET}  {col}{label}{C.RESET}"
        print(f"{C.FRAME}║{C.RESET}{pad(row, width)}{C.FRAME}║{C.RESET}")
    print(f"{C.FRAME}╚{'═' * width}╝{C.RESET}")


def collect_personal_info():
    print(f"\n{C.NEON_PURPLE}{C.BOLD}--- target info ---{C.RESET}")
    first = ask_words("First names", "(ali, mohammad, sara)")
    last = ask_words("Last names", "(ahmadi, rezaei)")
    nick = ask_words("Nicknames", "(mamad, ali_king)")
    partner = ask_words("Partner names", "(optional)")
    pet = ask_words("Pet names", "(optional)")
    brand = ask_words("Brands / hobby", "(ferrari, arsenal, cat)")
    years = ask_words("Years / dates", "(1990, 1370, 2024)")
    extra = ask_words("Extra words", "(anything else)")
    return [w for w in (first + last + nick + partner + pet + brand + years + extra) if w.strip()]


def finalize(path, lines, kind):
    inner = 62
    line = "═" * inner
    print()
    print(f"{C.FRAME}╔{line}╗{C.RESET}")
    print(f"{C.FRAME}║{C.RESET}{pad(f'{C.NEON_PURPLE}{C.BOLD}RESULTS{C.RESET}', inner, 'center')}{C.FRAME}║{C.RESET}")
    print(f"{C.FRAME}╠{line}╣{C.RESET}")
    for k, v in [("Type", f"{C.WHITE}{kind}{C.RESET}"),
                 ("File", f"{C.NEON_CYAN}{path}{C.RESET}"),
                 ("Lines", f"{C.GOLD}{lines:,}{C.RESET}")]:
        print(f"{C.FRAME}║{C.RESET}{pad(f'  {C.NEON_CYAN}{k:<10}{C.RESET} {C.DIM_GRAY}:{C.RESET} {v}', inner)}{C.FRAME}║{C.RESET}")
    print(f"{C.FRAME}╚{line}╝{C.RESET}")


def run_password():
    words = collect_personal_info()
    if not words:
        print(f"{C.CRIMSON}no words provided, aborting{C.RESET}")
        return
    print(f"{C.GREEN}  base words: {len(words)}{C.RESET}")

    mode = ask_mode()
    target = ask_target()
    out = ask_output("output/passwords.txt")

    print(f"\n{C.GOLD}Generating...{C.RESET}\n")
    t0 = datetime.now()
    lines = write_stream(out, mode, words, target)
    dt = (datetime.now() - t0).total_seconds()

    finalize(out, lines, "password")
    print(f"{C.DIM_GRAY}  done in {dt:.1f}s{C.RESET}")


def run_username():
    words = collect_personal_info()
    if not words:
        print(f"{C.CRIMSON}no words provided, aborting{C.RESET}")
        return
    print(f"{C.GREEN}  base words: {len(words)}{C.RESET}")

    target = ask_target()
    out = ask_output("output/usernames.txt")

    print(f"\n{C.GOLD}Generating...{C.RESET}\n")
    t0 = datetime.now()
    lines = write_usernames(out, words, target)
    dt = (datetime.now() - t0).total_seconds()

    finalize(out, lines, "username")
    print(f"{C.DIM_GRAY}  done in {dt:.1f}s{C.RESET}")


def run():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        banner()
        menu()
        print(f"\n{C.GOLD}{C.BOLD}>>{C.RESET} ", end="")
        choice = input().strip() or "1"

        if choice == "0":
            print(f"{C.CRIMSON}{C.BOLD}Bye{C.RESET}")
            break
        if choice == "1":
            run_password()
        elif choice == "2":
            run_username()
        else:
            print(f"{C.CRIMSON}Invalid{C.RESET}")

        input(f"\n{C.DIM_GRAY}Enter to continue{C.RESET}")


if __name__ == "__main__":
    run()