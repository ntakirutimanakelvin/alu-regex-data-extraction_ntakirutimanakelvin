import re
import json
from pathlib import Path

SRC = "input/raw-text.txt"
DST = "output/sample-output.json"

PAT_MAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PAT_CARD = re.compile(r"\b(?:\d[ \-]*){13,19}\b")
PAT_LINK = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
PAT_TEL = re.compile(r"\+?\d[\d .()\-]{6,20}\d")

THREATS = [
    (re.compile(r"<\s*script", re.I), "script"),
    (re.compile(r"<\s*iframe", re.I), "iframe"),
    (re.compile(r"<\s*(object|embed)", re.I), "plugin"),
    (re.compile(r"on(error|click|load)\s*=", re.I), "handler"),
    (re.compile(r"javascript:", re.I), "js-url"),
    (re.compile(r"data:text/html", re.I), "data-url"),
    (re.compile(r"' OR '1'='1", re.I), "tautology"),
    (re.compile(r"DROP TABLE", re.I), "drop"),
    (re.compile(r"UNION SELECT", re.I), "union"),
]

END_CHARS = ".,;:!?)]}'\"\\"

def read_src(path=SRC):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print("missing " + path)
        return None

def check_mail(s):
    s = s.strip().strip(END_CHARS + ",")
    if s.count("@") != 1:
        return False
    if ".." in s or " " in s:
        return False
    if len(s) < 5 or len(s) > 254:
        return False
    a, b = s.split("@")
    if not a or not b or "." not in b:
        return False
    if a[0] == "." or a[-1] == "." or a[-1] == "-":
        return False
    if b[0] in ".-" or b[-1] in ".-":
        return False
    for part in b.split("."):
        if not part or part[0] == "-" or part[-1] == "-":
            return False
        if "_" in part or " " in part:
            return False
    tail = b.rsplit(".", 1)[1]
    if len(tail) < 2 or not tail.isalpha():
        return False
    return True

def alu_kind(s):
    s = s.strip().lower()
    if "@" not in s or " " in s or ".." in s:
        return None
    _, d = s.rsplit("@", 1)
    if d == "si.alueducation.com":
        return "si"
    if d == "alumni.alueducation.com":
        return "alumni"
    if d == "alueducation.com":
        return "official"
    return "general"

def check_card(s):
    d = re.sub(r"[ \-]", "", s.strip())
    if not d.isdigit() or not 13 <= len(d) <= 19:
        return False
    if d == d[0] * len(d):
        return False
    tot = 0
    for i, c in enumerate(d[::-1]):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        tot += n
    return tot % 10 == 0

def check_link(s):
    s = s.strip().rstrip(END_CHARS)
    if " " in s or "\t" in s:
        return False
    t = s.lower()
    if not t.startswith("http://") and not t.startswith("https://"):
        return False
    host = t.split("://", 1)[1].split("/", 1)[0].split(":")[0].split("@")[-1]
    if "." not in host:
        return False
    if host[0] in ".-" or host[-1] in ".-":
        return False
    if re.fullmatch(r"[a-z0-9.\-]+", host) is None:
        return False
    return True

def check_tel(s):
    if re.search(r"[A-Za-z]", s):
        return False
    if "/" in s or re.search(r"\d{4}-\d{2}-\d{2}", s):
        return False
    d = re.sub(r"\D", "", s)
    if not 7 <= len(d) <= 15 or len(set(d)) == 1:
        return False
    if len(d) >= 10:
        plus = s.strip().startswith("+")
        par = "(" in s or ")" in s
        if not (plus or par or len(re.findall(r"[\s.\-()]", s)) >= 2):
            return False
    return True

def short_mail(s):
    a, b = s.split("@", 1)
    return a[0] + "***@" + b

def short_card(s):
    d = re.sub(r"[ \-]", "", s)
    return "XXXX-XXXX-XXXX-" + d[-4:]

def short_tel(s):
    d = re.sub(r"\D", "", s)
    return "+*** *** " + d[-3:]

def clean_snip(line):
    line = PAT_MAIL.sub("[mail-hidden]", line)
    line = re.sub(r"\b(?:\d[ \-]*){13,19}\b", "[card-hidden]", line)
    return line.strip()[:120]

def danger(text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for rx, tag in THREATS:
            if rx.search(line):
                out.append({"line": i, "tag": tag, "cut": clean_snip(line)})
                break
    return out

def gather(text):
    mails = []
    off = []
    alm = []
    si = []
    for m in PAT_MAIL.finditer(text):
        v = m.group(0).strip().strip(END_CHARS + ",")
        if not check_mail(v):
            continue
        k = alu_kind(v)
        h = short_mail(v)
        mails.append({"hide": h, "alu": k})
        if k == "official":
            off.append(h)
        elif k == "alumni":
            alm.append(h)
        elif k == "si":
            si.append(h)
    bad = danger(text)
    badlines = set(x["line"] for x in bad)
    pos = [0]
    for m in re.finditer(r"\n", text):
        pos.append(m.start() + 1)
    import bisect
    cards = []
    for m in PAT_CARD.finditer(text):
        if bisect.bisect_right(pos, m.start()) in badlines:
            continue
        v = m.group(0).strip()
        if check_card(v):
            cards.append({"hide": short_card(v), "ok": True})
    links = []
    for m in PAT_LINK.finditer(text):
        v = m.group(0).rstrip(END_CHARS)
        if check_link(v):
            links.append({"link": v})
    tels = []
    for m in PAT_TEL.finditer(text):
        v = m.group(0).strip().rstrip(".,;:")
        if check_tel(v):
            tels.append({"hide": short_tel(v)})
    return mails, off, alm, si, cards, links, tels, bad

def main():
    text = read_src(SRC)
    if not text:
        print("empty")
        return None
    mails, off, alm, si, cards, links, tels, bad = gather(text)
    print("mails " + str(len(mails)) + " off " + str(len(off)) + " alm " + str(len(alm)) + " si " + str(len(si)))
    for e in mails[:6]:
        print(e["hide"] + " " + e["alu"])
    print("cards " + str(len(cards)))
    for c in cards:
        print(c["hide"])
    print("links " + str(len(links)))
    for u in links[:6]:
        print(u["link"])
    print("tels " + str(len(tels)))
    for t in tels[:6]:
        print(t["hide"])
    print("danger " + str(len(bad)))
    data = {
        "file": SRC,
        "kinds": ["mails", "cards", "links", "tels"],
        "mails": mails,
        "alu_official": off,
        "alu_alumni": alm,
        "alu_si": si,
        "cards": cards,
        "links": links,
        "tels": tels,
        "dangers": bad,
        "totals": {
            "mails": len(mails),
            "official": len(off),
            "alumni": len(alm),
            "si": len(si),
            "cards": len(cards),
            "links": len(links),
            "tels": len(tels),
            "danger": len(bad),
        },
    }
    p = Path(DST)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("saved " + DST)
    return data

if __name__ == "__main__":
    main()
