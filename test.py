#!/usr/bin/env python3
import os

class Colors:
    R = '\033[0m'
    B = '\033[1m'
    D = '\033[2m'
    RED = '\033[91m'
    GRN = '\033[92m'
    YEL = '\033[93m'
    CYN = '\033[96m'
    WHT = '\033[97m'
    DIM_GRAY = '\033[38;2;110;110;120m'
    NEON_CYAN = '\033[38;2;0;255;213m'
    NEON_PURPLE = '\033[38;2;191;64;255m'
    CORNFLOWER = '\033[38;2;100;149;237m'
    CRIMSON = '\033[38;2;220;20;60m'
    GOLD = '\033[38;2;255;215;0m'

    NEON_GREEN = '\033[38;2;57;255;20m'
    NEON_PINK = '\033[38;2;255;20;147m'
    NEON_ORANGE = '\033[38;2;255;140;0m'
    NEON_BLUE = '\033[38;2;0;150;255m'
    NEON_RED = '\033[38;2;255;40;40m'
    NEON_YELLOW = '\033[38;2;255;255;0m'
    NEON_LIME = '\033[38;2;180;255;0m'
    AQUA = '\033[38;2;0;255;255m'
    MAGENTA = '\033[38;2;255;0;255m'
    PINK = '\033[38;2;255;192;203m'
    ORANGE = '\033[38;2;255;165;0m'
    SKY = '\033[38;2;135;206;235m'
    MINT = '\033[38;2;152;255;152m'
    LAVENDER = '\033[38;2;230;190;255m'
    SILVER = '\033[38;2;192;192;192m'
    TEAL = '\033[38;2;0;128;128m'
    INDIGO = '\033[38;2;75;0;130m'
    HOT_PINK = '\033[38;2;255;105;180m'
    ROYAL_BLUE = '\033[38;2;65;105;225m'
    EMERALD = '\033[38;2;80;200;120m'
    FIRE = '\033[38;2;255;69;0m'


C = Colors

os.system("clear" if os.name == "posix" else "cls")

print(f"{C.B}{C.NEON_CYAN}=== COLOR PALETTE TEST ==={C.R}\n")

colors = [
    ("R",         C.R,         "Reset"),
    ("B",         C.B,         "Bold"),
    ("D",         C.D,         "Dim"),
    ("RED",       C.RED,       "Red"),
    ("GRN",       C.GRN,       "Green"),
    ("YEL",       C.YEL,       "Yellow"),
    ("CYN",       C.CYN,       "Cyan"),
    ("WHT",       C.WHT,       "White"),
    ("DIM_GRAY",  C.DIM_GRAY,  "Dim Gray"),
    ("NEON_CYAN", C.NEON_CYAN, "Neon Cyan"),
    ("NEON_PURPLE", C.NEON_PURPLE, "Neon Purple"),
    ("CORNFLOWER", C.CORNFLOWER, "Cornflower"),
    ("CRIMSON",   C.CRIMSON,   "Crimson"),
    ("GOLD",      C.GOLD,      "Gold"),
    ("NEON_GREEN", C.NEON_GREEN, "Neon Green"),
    ("NEON_PINK", C.NEON_PINK, "Neon Pink"),
    ("NEON_ORANGE", C.NEON_ORANGE, "Neon Orange"),
    ("NEON_BLUE", C.NEON_BLUE, "Neon Blue"),
    ("NEON_RED",  C.NEON_RED,  "Neon Red"),
    ("NEON_YELLOW", C.NEON_YELLOW, "Neon Yellow"),
    ("NEON_LIME", C.NEON_LIME, "Neon Lime"),
    ("AQUA",      C.AQUA,      "Aqua"),
    ("MAGENTA",   C.MAGENTA,   "Magenta"),
    ("PINK",      C.PINK,      "Pink"),
    ("ORANGE",    C.ORANGE,    "Orange"),
    ("SKY",       C.SKY,       "Sky"),
    ("MINT",      C.MINT,      "Mint"),
    ("LAVENDER",  C.LAVENDER,  "Lavender"),
    ("SILVER",    C.SILVER,    "Silver"),
    ("TEAL",      C.TEAL,      "Teal"),
    ("INDIGO",    C.INDIGO,    "Indigo"),
    ("HOT_PINK",  C.HOT_PINK,  "Hot Pink"),
    ("ROYAL_BLUE", C.ROYAL_BLUE, "Royal Blue"),
    ("EMERALD",   C.EMERALD,   "Emerald"),
    ("FIRE",      C.FIRE,      "Fire"),
]

for name, code, label in colors:
    if name in ("B", "D"):
        print(f"  {code}{label:<14}{C.R}  {code}████████████{C.R}  -> {name}")
    else:
        print(f"  {code}{label:<14}{C.R}  {code}████████████{C.R}  -> {name}")

print(f"\n{C.DIM_GRAY}--- Sample usage ---{C.R}")
print(f"  {C.NEON_GREEN}[+] Success message{C.R}")
print(f"  {C.NEON_RED}[!] Error message{C.R}")
print(f"  {C.NEON_ORANGE}[*] Warning message{C.R}")
print(f"  {C.NEON_BLUE}[i] Info message{C.R}")
print(f"  {C.NEON_PINK}[?] Question{C.R}")
print(f"  {C.GOLD}>> prompt {C.R}")
print()