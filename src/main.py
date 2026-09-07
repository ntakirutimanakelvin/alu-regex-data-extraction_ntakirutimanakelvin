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
