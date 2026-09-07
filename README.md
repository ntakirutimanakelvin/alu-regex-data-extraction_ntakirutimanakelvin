# Library Regex Extraction

Program that reads the untrusted library sync file and extracts 4 kinds of data:
mails, cards, links and tels.

## Data

- mails with ALU groups official, alumni and si
- cards with Luhn check
- links starting with http or https
- tels with 7 to 15 digits

## Files

input/raw-text.txt holds the test data.
src/main.py holds the code.
output/sample-output.json holds the masked result.

## Safety

Nothing raw is saved. Mails, cards and tels are shortened before print or save.
Bad lines with script, iframe, object, embed, javascript, data urls and SQL
words are flagged and cards on those lines are skipped.

## Run

```bash
python src/main.py
```

Needs Python 3.10+, nothing else to install.
