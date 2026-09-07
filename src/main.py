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
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        print("missing " + path)
        return None

def check_mail(candidate):
    candidate = candidate.strip().strip(END_CHARS + ",")
    if candidate.count("@") != 1:
        return False
    if ".." in candidate or " " in candidate:
        return False
    if len(candidate) < 5 or len(candidate) > 254:
        return False
    local, domain = candidate.split("@")
    if not local or not domain or "." not in domain:
        return False
    if local[0] == "." or local[-1] == "." or local[-1] == "-":
        return False
    if domain[0] in ".-" or domain[-1] in ".-":
        return False
    for part in domain.split("."):
        if not part or part[0] == "-" or part[-1] == "-":
            return False
        if "_" in part or " " in part:
            return False
    tail = domain.rsplit(".", 1)[1]
    if len(tail) < 2 or not tail.isalpha():
        return False
    return True

def alu_kind(mail_text):
    mail_text = mail_text.strip().lower()
    if "@" not in mail_text or " " in mail_text or ".." in mail_text:
        return None
    _, domain = mail_text.rsplit("@", 1)
    if domain == "si.alueducation.com":
        return "si"
    if domain == "alumni.alueducation.com":
        return "alumni"
    if domain == "alueducation.com":
        return "official"
    return "general"

def check_card(card_text):
    number = re.sub(r"[ \-]", "", card_text.strip())
    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    if number == number[0] * len(number):
        return False
    total = 0
    for index, digit in enumerate(number[::-1]):
        value = int(digit)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0

def check_link(link_text):
    link_text = link_text.strip().rstrip(END_CHARS)
    if " " in link_text or "\t" in link_text:
        return False
    lowered = link_text.lower()
    if not lowered.startswith("http://") and not lowered.startswith("https://"):
        return False
    host = lowered.split("://", 1)[1].split("/", 1)[0].split(":")[0].split("@")[-1]
    if "." not in host:
        return False
    if host[0] in ".-" or host[-1] in ".-":
        return False
    if re.fullmatch(r"[a-z0-9.\-]+", host) is None:
        return False
    return True

def check_tel(phone_text):
    if re.search(r"[A-Za-z]", phone_text):
        return False
    if "/" in phone_text or re.search(r"\d{4}-\d{2}-\d{2}", phone_text):
        return False
    digits = re.sub(r"\D", "", phone_text)
    if not 7 <= len(digits) <= 15 or len(set(digits)) == 1:
        return False
    if len(digits) >= 10:
        has_plus = phone_text.strip().startswith("+")
        has_bracket = "(" in phone_text or ")" in phone_text
        if not (has_plus or has_bracket or len(re.findall(r"[\s.\-()]", phone_text)) >= 2):
            return False
    return True

def short_mail(mail_text):
    local, domain = mail_text.split("@", 1)
    return local[0] + "***@" + domain

def short_card(card_text):
    number = re.sub(r"[ \-]", "", card_text)
    return "XXXX-XXXX-XXXX-" + number[-4:]

def short_tel(phone_text):
    digits = re.sub(r"\D", "", phone_text)
    return "+*** *** " + digits[-3:]

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
