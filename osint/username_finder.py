#!/usr/bin/env python3
import os
import sys
import time
import json
import random
import threading
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

OUT = "username_output"
os.makedirs(OUT, exist_ok=True)


class C:
    R = '\033[0m';
    B = '\033[1m';
    D = '\033[2m'
    RED = '\033[91m';
    GRN = '\033[92m';
    YEL = '\033[93m'
    CYN = '\033[96m';
    WHT = '\033[97m'
    GLD = '\033[38;2;255;215;0m'
    PUR = '\033[38;2;191;64;255m'
    NEO = '\033[38;2;0;255;213m'
    CRM = '\033[38;2;220;20;60m'


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def rand_ua():
    return random.choice(USER_AGENTS)


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def header(title):
    print(f"\n{C.PUR}{'=' * 70}{C.R}")
    print(f"{C.B}{C.WHT}  {title}{C.R}")
    print(f"{C.PUR}{'=' * 70}{C.R}\n")


def line():
    print(f"{C.PUR}{'-' * 70}{C.R}")


def gen_numbers(u):
    return [
        f"{u}1", f"{u}12", f"{u}123", f"{u}1234",
        f"{u}007", f"{u}99", f"{u}69", f"{u}77",
        f"{u}0", f"{u}01", f"{u}2", f"{u}3",
        f"1{u}", f"{u}11", f"{u}22",
    ]


def gen_prefix(u):
    return [
        f"iam{u}", f"real{u}", f"the{u}",
        f"mr{u}", f"its{u}", f"this{u}",
        f"official{u}", f"x{u}",
        f"iam_{u}", f"real_{u}", f"the_{u}",
        f"mr_{u}", f"its_{u}",
    ]


def gen_suffix(u):
    return [
        f"{u}_dev", f"{u}_official", f"{u}_hq",
        f"{u}_real", f"{u}_ir", f"{u}_iran",
        f"{u}_pro", f"{u}_x", f"{u}_x1",
        f"{u}dev", f"{u}official", f"{u}real",
        f"{u}x", f"{u}pro", f"{u}_0",
    ]


def gen_years(u):
    years = ["2020", "2021", "2022", "2023", "2024", "2025"]
    out = []
    for y in years:
        out.append(f"{u}{y}")
        out.append(f"{u}_{y}")
    for y in ["1370", "1380", "1390", "1400", "1403"]:
        out.append(f"{u}{y}")
    return out


def gen_case(u):
    return [
        u.capitalize(),
        u.upper(),
        u.lower(),
        u[0].upper() + u[1:].lower() if len(u) > 1 else u,
        u[0:1].lower() + u[1:].upper() if len(u) > 1 else u,
    ]


def gen_leet(u):
    leet_map = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7'],
        'g': ['9'],
        'b': ['8'],
        'l': ['1'],
    }
    out = set()
    for i, c in enumerate(u.lower()):
        if c in leet_map:
            for r in leet_map[c]:
                out.add(u[:i] + r + u[i + 1:])
    result = [u.lower()]
    for c in u.lower():
        new_result = []
        for prefix in result:
            if c in leet_map:
                for r in leet_map[c]:
                    new_result.append(prefix + r)
            else:
                new_result.append(prefix + c)
        result = new_result
        if len(result) > 50:
            break
    out.update(result[:20])
    return list(out)


def gen_separators(u):
    if len(u) < 2:
        return []
    return [
        f"_{u}_", f"{u}_", f"_{u}",
        ".".join(u), "_".join(u), "-".join(u),
        f"{u}.", f".{u}",
    ]


def gen_reversed(u):
    return [u[::-1], f"{u}_{u[::-1]}", f"{u[::-1]}_{u}"]


def gen_combos(u):
    return [
        f"{u}_iran", f"{u}_ir", f"{u}_king",
        f"{u}_master", f"{u}_god", f"{u}_legend",
        f"{u}_313", f"{u}_110", f"{u}_2024",
        f"{u}_1", f"1_{u}",
        f"{u}_on", f"{u}_off",
    ]


def gen_plural(u):
    return [
        f"{u}s", f"{u}_s", f"{u}1", f"1{u}",
        f"{u}es", f"{u}_e",
    ]


VARIATION_CATEGORIES = {
    "1": ("Numbers", gen_numbers),
    "2": ("Prefix", gen_prefix),
    "3": ("Suffix", gen_suffix),
    "4": ("Years", gen_years),
    "5": ("Case", gen_case),
    "6": ("Leet", gen_leet),
    "7": ("Separators", gen_separators),
    "8": ("Reversed", gen_reversed),
    "9": ("Combos", gen_combos),
    "10": ("Plural", gen_plural),
}


def build_variations(username, categories):
    variations = [username]
    seen = {username.lower()}

    for cat_key in categories:
        if cat_key not in VARIATION_CATEGORIES:
            continue
        _, fn = VARIATION_CATEGORIES[cat_key]
        for v in fn(username):
            if v.lower() not in seen:
                seen.add(v.lower())
                variations.append(v)

    return variations


SITES = {
    "GitHub": {"url": "https://github.com/{}", "signs": ["repositories", "followers", "contribution"]},
    "Twitter": {"url": "https://twitter.com/{}", "signs": ["followers", "tweets"]},
    "Instagram": {"url": "https://instagram.com/{}", "signs": ["followers", "posts"]},
    "Reddit": {"url": "https://reddit.com/user/{}", "signs": ["karma", "cake day"]},
    "TikTok": {"url": "https://tiktok.com/@{}", "signs": ["followers", "video"]},
    "YouTube": {"url": "https://youtube.com/@{}", "signs": ["subscribers", "videos"]},
    "Pinterest": {"url": "https://pinterest.com/{}", "signs": ["pins", "followers"]},
    "Telegram": {"url": "https://t.me/{}", "signs": ["subscribers", "members"]},
    "Facebook": {"url": "https://facebook.com/{}", "signs": ["friends", "posts"]},
    "LinkedIn": {"url": "https://linkedin.com/in/{}", "signs": ["connections", "experience"]},
    "Snapchat": {"url": "https://snapchat.com/add/{}", "signs": []},
    "VK": {"url": "https://vk.com/{}", "signs": ["friends", "followers"]},
    "Tumblr": {"url": "https://{}.tumblr.com", "signs": ["posts", "followers"]},
    "Flickr": {"url": "https://flickr.com/people/{}", "signs": ["photos", "followers"]},
    "Twitch": {"url": "https://twitch.tv/{}", "signs": ["followers", "viewers"]},
    "GitLab": {"url": "https://gitlab.com/{}", "signs": ["projects", "activity"]},
    "Bitbucket": {"url": "https://bitbucket.org/{}", "signs": ["repositories", "workspace"]},
    "CodePen": {"url": "https://codepen.io/{}", "signs": ["pens", "followers"]},
    "Replit": {"url": "https://replit.com/@{}", "signs": ["repls", "followers"]},
    "Dev.to": {"url": "https://dev.to/{}", "signs": ["posts", "followers"]},
    "Medium": {"url": "https://medium.com/@{}", "signs": ["followers", "stories"]},
    "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "signs": ["karma", "created"]},
    "StackOverflow": {"url": "https://stackoverflow.com/users/{}", "signs": ["reputation", "badges"]},
    "Docker Hub": {"url": "https://hub.docker.com/u/{}", "signs": ["repositories"]},
    "NPM": {"url": "https://npmjs.com/~{}", "signs": ["packages"]},
    "PyPI": {"url": "https://pypi.org/user/{}", "signs": ["projects"]},
    "Keybase": {"url": "https://keybase.io/{}", "signs": ["proofs", "devices"]},
    "Kaggle": {"url": "https://kaggle.com/{}", "signs": ["datasets", "notebooks"]},
    "Behance": {"url": "https://behance.net/{}", "signs": ["projects", "appreciations"]},
    "Dribbble": {"url": "https://dribbble.com/{}", "signs": ["shots", "followers"]},
    "DeviantArt": {"url": "https://{}.deviantart.com", "signs": ["watchers", "deviations"]},
    "ArtStation": {"url": "https://artstation.com/{}", "signs": ["projects", "followers"]},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "signs": ["followers", "tracks"]},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "signs": ["playlists", "followers"]},
    "Bandcamp": {"url": "https://{}.bandcamp.com", "signs": ["tracks", "albums"]},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "signs": ["games", "hours"]},
    "About.me": {"url": "https://about.me/{}", "signs": ["bio", "links"]},
    "WordPress": {"url": "https://{}.wordpress.com", "signs": ["posts", "blog"]},
    "Patreon": {"url": "https://patreon.com/{}", "signs": ["patrons", "posts"]},
    "Mastodon": {"url": "https://mastodon.social/@{}", "signs": ["followers", "posts"]},
    "Vimeo": {"url": "https://vimeo.com/{}", "signs": ["videos", "followers"]},
    "SlideShare": {"url": "https://slideshare.net/{}", "signs": ["presentations"]},
    "Gravatar": {"url": "https://gravatar.com/{}", "signs": ["profile"]},
    "ProductHunt": {"url": "https://producthunt.com/@{}", "signs": ["followers", "upvotes"]},
    "AngelList": {"url": "https://angel.co/u/{}", "signs": ["followers"]},
    "Badoo": {"url": "https://badoo.com/{}", "signs": ["followers", "photos"]},
    "Ask.fm": {"url": "https://ask.fm/{}", "signs": ["answers", "followers"]},
    "Trello": {"url": "https://trello.com/{}", "signs": ["boards"]},
    "Etsy": {"url": "https://etsy.com/people/{}", "signs": ["sales", "favorites"]},
}


class ProxyPool:
    def __init__(self, proxies):
        self.proxies = [p for p in proxies if p]
        self.index = 0
        self.lock = threading.Lock()
        self.dead = set()

    def get(self):
        if not self.proxies:
            return None
        with self.lock:
            healthy = [p for p in self.proxies if p not in self.dead]
            if not healthy:
                return None
            p = healthy[self.index % len(healthy)]
            self.index += 1
            return p

    def mark_dead(self, p):
        with self.lock:
            self.dead.add(p)

    def total(self):
        return len(self.proxies)

    def alive(self):
        return len([p for p in self.proxies if p not in self.dead])


def load_proxies(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" not in line:
                line = "http://" + line
            out.append(line)
    return list(dict.fromkeys(out))


def proxy_dict(url):
    if not url:
        return None
    return {"http": url, "https": url}


class RateLimiter:
    def __init__(self, delay):
        self.delay = delay
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self):
        if self.delay <= 0:
            return
        with self.lock:
            now = time.time()
            elapsed = now - self.last
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last = time.time()


def check_site(name, info, username, proxy_url, timeout=10):
    url = info["url"].format(username)

    try:
        r = requests.get(
            url,
            proxies=proxy_dict(proxy_url),
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": rand_ua()},
        )

        if r.status_code == 404:
            return (name, url, "not_found", None)

        if r.status_code in (200, 301, 302):
            body = r.text[:10000].lower()

            neg = ["user not found", "page not found",
                   "doesn't exist", "no user",
                   "not exist", "not registered"]
            for n in neg:
                if n in body:
                    return (name, url, "not_found", None)

            signs = info.get("signs", [])
            matched = [s for s in signs if s.lower() in body]

            if matched:
                return (name, url, "found", matched)

            return (name, url, "possible", None)

        if r.status_code == 403:
            return (name, url, "blocked", None)

        return (name, url, f"status_{r.status_code}", None)

    except requests.exceptions.ProxyError:
        return (name, url, "proxy_dead", proxy_url)
    except requests.exceptions.Timeout:
        return (name, url, "timeout", None)
    except requests.exceptions.ConnectionError:
        return (name, url, "conn_error", None)
    except Exception:
        return (name, url, "error", None)


def scan(variations, proxies=None, threads=5, delay=0.5, mode="parallel"):
    pool = ProxyPool(proxies or [])
    limiter = RateLimiter(delay)

    sites = list(SITES.items())
    tasks = []
    for var in variations:
        for site_name, info in sites:
            tasks.append((var, site_name, info))

    total = len(tasks)

    results = {
        "variations": variations,
        "started_at": datetime.now().isoformat(),
        "mode": mode,
        "delay": delay,
        "threads": threads,
        "proxy_count": pool.total(),
        "total_requests": total,
        "found": [],
        "possible": [],
        "errors": [],
        "site_summary": {},
    }
    lock = threading.Lock()
    counter = {"done": 0}

    def worker(task):
        var, site_name, info = task

        limiter.wait()
        proxy_url = pool.get()

        with lock:
            counter["done"] += 1
            n = counter["done"]

        result = check_site(site_name, info, var, proxy_url)
        sname, url, status, extra = result

        if status == "proxy_dead" and proxy_url:
            pool.mark_dead(proxy_url)

        pct = (n / total) * 100
        bar_len = 20
        filled = int(bar_len * n / total)
        bar = "#" * filled + "-" * (bar_len - filled)

        prefix = f"  {C.D}[{bar}] {pct:5.1f}%{C.R}"

        if status == "found":
            signs = f"  {C.D}({','.join(extra[:2])}){C.R}" if extra else ""
            sys.stdout.write(f"\r{' ' * 100}\r")
            print(f"{C.GRN}[+]{C.R} {C.GLD}{var:<20}{C.R} @ {C.CYN}{sname:<15}{C.R} {url}{signs}")
            with lock:
                results["found"].append({
                    "variation": var, "site": sname,
                    "url": url, "signs": extra,
                })
                results["site_summary"].setdefault(sname, []).append(var)

        elif status == "possible":
            with lock:
                results["possible"].append({
                    "variation": var, "site": sname, "url": url,
                })

        elif status != "not_found":
            with lock:
                results["errors"].append({
                    "variation": var, "site": sname,
                    "status": status, "proxy": proxy_url,
                })

        sys.stdout.write(f"\r{prefix} {C.D}{var:<20} @ {sname:<15}{C.R}")
        sys.stdout.flush()

    print(f"\n{C.GLD}[*] Total requests: {total}{C.R}")
    print(f"{C.D}    Variations: {len(variations)} x Sites: {len(sites)}{C.R}\n")

    if mode == "sequential":
        for t in tasks:
            worker(t)
    else:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(worker, t) for t in tasks]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

    sys.stdout.write(f"\r{' ' * 100}\r")
    print()

    results["finished_at"] = datetime.now().isoformat()
    results["proxy_alive"] = pool.alive()
    results["proxy_dead"] = list(pool.dead)

    return results


def choose_scan_mode(username):
    header("SCAN MODE")

    print(f"  Username: {C.GLD}{username}{C.R}\n")

    print(f"  {C.GLD}[1]{C.R} {C.NEO}Single{C.R}         - only \"{username}\"")
    print(f"  {C.GLD}[2]{C.R} {C.NEO}Quick{C.R}          - 20 variations (numbers+prefix+suffix)")
    print(f"  {C.GLD}[3]{C.R} {C.NEO}Deep{C.R}           - 100+ variations (all categories)")
    print(f"  {C.GLD}[4]{C.R} {C.NEO}Custom{C.R}         - choose categories")
    print(f"  {C.GLD}[5]{C.R} {C.NEO}Custom List{C.R}    - provide own list")
    print(f"  {C.GLD}[0]{C.R} {C.CRM}Back{C.R}")

    print(f"\n{C.GLD}>>{C.R} ", end="")
    c = input().strip()

    if c == "0":
        return None

    if c == "1":
        return [username]

    if c == "2":
        cats = ["1", "2", "3"]
        vars = build_variations(username, cats)
        print(f"\n{C.GRN}[+] Generated: {len(vars)} variations{C.R}")
        return vars

    if c == "3":
        cats = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
        vars = build_variations(username, cats)
        print(f"\n{C.GRN}[+] Generated: {len(vars)} variations{C.R}")
        return vars

    if c == "4":
        header("CUSTOM CATEGORIES")

        print(f"  {C.NEO}Which categories?{C.R}\n")
        for k, (name, _) in VARIATION_CATEGORIES.items():
            print(f"  {C.GLD}{k:>2}{C.R}. {name}")

        print(f"\n{C.D}  Example: 1,2,3  or  all  or Enter (default 1,2,3){C.R}")
        print(f"{C.GLD}>>{C.R} ", end="")
        sel = input().strip()

        if not sel:
            cats = ["1", "2", "3"]
        elif sel.lower() == "all":
            cats = list(VARIATION_CATEGORIES.keys())
        else:
            cats = [x.strip() for x in sel.replace(" ", "").split(",") if x.strip() in VARIATION_CATEGORIES]

        if not cats:
            print(f"{C.CRM}[!] Invalid selection{C.R}")
            input(f"\n{C.D}Enter...{C.R}")
            return None

        vars = build_variations(username, cats)
        print(f"\n{C.GRN}[+] Generated: {len(vars)} variations{C.R}")

        print(f"\n{C.NEO}Preview (first 15):{C.R}")
        for v in vars[:15]:
            print(f"  {C.D}*{C.R} {v}")
        if len(vars) > 15:
            print(f"  {C.D}... and {len(vars) - 15} more{C.R}")

        print(f"\n{C.GLD}Continue? [y/n]{C.R}: ", end="")
        if input().strip().lower() != "y":
            return None
        return vars

    if c == "5":
        header("CUSTOM LIST")

        print(f"  {C.NEO}[1]{C.R} File path")
        print(f"  {C.NEO}[2]{C.R} Paste (comma separated)")
        print(f"{C.GLD}>>{C.R} ", end="")
        m = input().strip()

        items = []
        if m == "1":
            print(f"{C.NEO}File path{C.R}: ", end="")
            p = input().strip().strip('"').strip("'")
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    items = [l.strip() for l in f if l.strip()]
        elif m == "2":
            print(f"{C.NEO}Variations (comma separated){C.R}:")
            print(f"{C.GLD}>>{C.R} ", end="")
            items = [x.strip() for x in input().split(",") if x.strip()]

        if not items:
            print(f"{C.CRM}[!] No items{C.R}")
            input(f"\n{C.D}Enter...{C.R}")
            return None

        if username not in items:
            items.insert(0, username)

        print(f"\n{C.GRN}[+] Loaded: {len(items)} variations{C.R}")
        return items

    return None


def save_report(results):
    ts = int(time.time())
    path = f"{OUT}/scan_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return path


def print_summary(results):
    header("SUMMARY")

    print(f"  {C.NEO}Variations:  {C.R}{len(results['variations'])}")
    print(f"  {C.NEO}Requests:    {C.R}{results['total_requests']}")
    print(f"  {C.NEO}Proxies:     {C.R}{results['proxy_count']} "
          f"(alive: {results['proxy_alive']}, dead: {len(results['proxy_dead'])})")
    print()

    line()
    print(f"  {C.GRN}Found:     {len(results['found'])}{C.R}")
    print(f"  {C.YEL}Possible:  {len(results['possible'])}{C.R}")
    print(f"  {C.CRM}Errors:    {len(results['errors'])}{C.R}")
    line()

    if results["site_summary"]:
        print(f"\n{C.GRN}{C.B}[+] Accounts by site:{C.R}\n")
        for site, vars in sorted(results["site_summary"].items()):
            print(f"  {C.GLD}{site:<15}{C.R} -> {C.NEO}{', '.join(vars)}{C.R}")


def banner():
    clear()
    print(f"""{C.NEO}{C.B}
██╗   ██╗███████╗███████╗██████╗ ███╗   ██╗ █████╗ ███╗   ███╗███████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗████╗ ████║██╔════╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║   ██║███████╗█████╗  ██████╔╝██╔██╗ ██║███████║██╔████╔██║█████╗      █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║   ██║╚════██║██╔══╝  ██╔══██╗██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝      ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝███████║███████╗██║  ██║██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

{C.R}""")
    print(f"""{C.GRN}BOOM""")


def run():
    while True:
        banner()

        username = input(f"{C.GLD}Username to search{C.R} (Enter=exit): ").strip()
        if not username:
            return

        variations = choose_scan_mode(username)
        if not variations:
            continue

        print(f"\n{C.NEO}Use proxies?{C.R} {C.D}(y/n, default n){C.R}: ", end="")
        proxies = []
        if input().strip().lower() == "y":
            print(f"{C.NEO}Proxy file path{C.R}: ", end="")
            pf = input().strip().strip('"').strip("'")
            proxies = load_proxies(pf)
            if proxies:
                print(f"{C.GRN}[+] Loaded {len(proxies)} proxies{C.R}")
            else:
                print(f"{C.YEL}[!] No proxies - direct mode{C.R}")

        print(f"\n{C.NEO}Delay between packets{C.R} {C.D}(default 0.5s){C.R}: ", end="")
        d = input().strip()
        try:
            delay = float(d) if d else 0.5
        except ValueError:
            delay = 0.5

        print(f"{C.NEO}Threads{C.R} {C.D}(default 5){C.R}: ", end="")
        t = input().strip()
        threads = int(t) if t.isdigit() else 5

        print(f"\n{C.NEO}Execution:{C.R}")
        print(f"  {C.GLD}1{C.R}  Parallel    {C.D}(fast){C.R}")
        print(f"  {C.GLD}2{C.R}  Sequential  {C.D}(silent){C.R}")
        print(f"{C.GLD}>>{C.R} ", end="")
        m = input().strip()
        mode = "sequential" if m == "2" else "parallel"

        print(f"\n{C.PUR}{'-' * 70}{C.R}")
        print(f"  Username:    {C.GLD}{username}{C.R}")
        print(f"  Variations:  {len(variations)}")
        print(f"  Sites:       {len(SITES)}")
        print(f"  Requests:    {len(variations) * len(SITES)}")
        print(f"  Proxies:     {len(proxies)}")
        print(f"  Delay:       {delay}s")
        print(f"  Threads:     {threads}")
        print(f"  Mode:        {mode}")
        print(f"  Est. Time:   ~{int(len(variations) * len(SITES) * delay / max(threads, 1))}s")
        print(f"{C.PUR}{'-' * 70}{C.R}\n")

        print(f"{C.GLD}Start? (y/n){C.R}: ", end="")
        if input().strip().lower() != "y":
            continue

        header("SCANNING...")
        start = time.time()
        results = scan(variations, proxies, threads, delay, mode)
        elapsed = time.time() - start

        print(f"\n{C.NEO}Time: {C.R}{elapsed:.1f}s")

        print_summary(results)

        path = save_report(results)
        print(f"\n{C.GRN}[+] Saved: {path}{C.R}")

        input(f"\n{C.D}Enter...{C.R}")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRM}Bye{C.R}")