"""RECORDS.xlsx, the records of this repository as one workbook (Vendored, Vendored notes, Register map, Superseded), and
the research gate: a workbook is accepted when the Hub's index lists it. This repository's own, at the path the index gives;
another repository's only as a read-only copy at research/REPO/PATH whose digest is the index's; no workbook the index does
not list. RESEARCH-INDEX.xlsx here is a copy of the Hub's; the Hub's `check.py --pins` reads red when it is not the Hub's.
One planted fault for each rule."""
import hashlib
import os
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import xlsx  # noqa: E402

BOOK = ROOT / "RECORDS.xlsx"
INDEX = "RESEARCH-INDEX.xlsx"
ME = "Ward"
HEADS = {
    "Vendored": ["SYMBOL", "LOCAL-PATH", "OWNER-REPO", "OWNER-PATH", "DIGEST", "WHY"],
    "Vendored notes": ["n", "text"],
    "Register map": ["entry", "verdict", "runner", "note"],
    "Superseded": ["id", "sheet", "reason", "date"],
}


def natural(k):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", k)]


def book_findings(path):
    book, filters, found = dict(xlsx.read_xlsx(path)), xlsx.filtered(path), []
    for name, head in HEADS.items():
        sheet = book.get(name)
        if sheet is None or sheet[0] != head:
            found.append(f"sheets: {name} has no header {head}")
            continue
        if filters.get(name) != "A1:%s%d" % (chr(64 + len(head)), len(sheet)):
            found.append(f"filter: {name} has no autoFilter over its header and rows")
        keys = [tuple(r[:2]) if name == "Vendored" else natural(r[0]) for r in sheet[1:]]
        if keys != sorted(keys):
            found.append(f"sort: {name} is not sorted by its key")
        seen = [repr(k) for k in keys]
        found += [f"keys: {name} repeats {k}" for k in sorted({k for k in seen if seen.count(k) > 1})]
        found += [f"sheets: {name} line {i} has {len(r)} cells, not {len(head)}" for i, r in enumerate(sheet[1:], 2)
                  if len(r) != len(head)]
    live = {"Vendored": {r[0] for r in book.get("Vendored", [])[1:]}, "Register map": {r[0] for r in book.get("Register map", [])[1:]}}
    for r in book.get("Superseded", [])[1:]:
        if len(r) == 4 and (not r[2].strip() or not r[3].strip()):
            found.append(f"superseded: {r[0]} has no reason or no date")
        if len(r) == 4 and r[0] in live.get(r[1], ()):
            found.append(f"keys: id {r[0]} is in {r[1]} and in Superseded")
    return found


def research(root):
    index = os.path.join(root, INDEX)
    if not os.path.exists(index):
        return [f"research: {INDEX} is missing"]
    rows = dict(xlsx.read_xlsx(index)).get("Index", [])[1:]
    own = {row[2] for row in rows if row[1] == ME}
    copies = {f"research/{row[1]}/{row[2]}": row for row in rows if row[1] != ME}
    here = set()
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        here |= {os.path.relpath(os.path.join(directory, f), root).replace(os.sep, "/") for f in files if f.endswith(".xlsx")}
    found = []
    for name in sorted(here - {INDEX}):
        if name in own:
            continue
        if name in copies:
            if hashlib.sha256(open(os.path.join(root, name), "rb").read()).hexdigest() != copies[name][4]:
                found.append(f"research: {name} is edited here; {copies[name][1]} owns it and is its only editor")
        else:
            found.append(f"research: {name} is no workbook the index lists for {ME}")
    return found + [f"research: {name} is listed as owned by {ME} and is missing" for name in sorted(own - here)]


def gate(files, rows, no_index=False):
    with tempfile.TemporaryDirectory() as tmp:
        if not no_index:
            xlsx.write_xlsx(os.path.join(tmp, INDEX), [("Index", [["id", "repo", "path", "sheets", "sha256", "owner"]] + rows)])
        for name, data in files.items():
            os.makedirs(os.path.dirname(os.path.join(tmp, name)), exist_ok=True)
            pathlib.Path(tmp, name).write_bytes(data)
        return research(tmp)


def planted(edit, filters=True):
    with tempfile.TemporaryDirectory() as tmp:
        book = dict(xlsx.read_xlsx(BOOK))
        edit(book)
        path = os.path.join(tmp, "R.xlsx")
        xlsx.write_xlsx(path, list(book.items()), filters=filters)
        return book_findings(path)


class Records(unittest.TestCase):
    def red(self, text, found):
        self.assertTrue(any(f.startswith(text) or text in f for f in found), (text, found))

    def test_the_workbook_and_the_gate_hold_on_this_repository(self):
        self.assertEqual([], book_findings(BOOK))
        self.assertEqual([], research(str(ROOT)))
        self.assertEqual([], planted(lambda b: None))

    def test_unsorted(self):
        self.red("sort: Register map", planted(lambda b: b["Register map"].insert(1, b["Register map"].pop(5))))

    def test_repeated_key(self):
        self.red("keys: Register map repeats", planted(lambda b: b["Register map"].append(list(b["Register map"][1]))))

    def test_no_filter(self):
        self.red("filter:", planted(lambda b: None, filters=False))

    def test_wrong_header_and_short_row(self):
        self.red("sheets: Vendored has no header", planted(lambda b: b["Vendored"].__setitem__(0, ["SYMBOL"])))
        self.red("sheets: Register map line", planted(lambda b: b["Register map"].append(["Z9", "RUNNER"])))

    def test_superseded_rules(self):
        self.red("superseded: x", planted(lambda b: b["Superseded"].append(["x", "Register map", "", "2026-11-17"])))
        self.red("superseded: x", planted(lambda b: b["Superseded"].append(["x", "Register map", "why", ""])))
        self.red("is in Register map and in Superseded",
                 planted(lambda b: b["Superseded"].append([b["Register map"][1][0], "Register map", "why", "2026-11-17"])))

    mine = ["X1", "Ward", "RECORDS.xlsx", "Register map", "a" * 64, "Ward"]
    theirs = ["X2", "Keel", "MEASURED.xlsx", "Measured", hashlib.sha256(b"theirs").hexdigest(), "Keel"]
    own = {"RECORDS.xlsx": b"m"}

    def test_the_research_gate(self):
        self.assertEqual([], gate(self.own, [self.mine, self.theirs]))
        self.assertEqual([], gate(dict(self.own, **{"research/Keel/MEASURED.xlsx": b"theirs"}), [self.mine, self.theirs]))
        self.red("is edited here; Keel owns it", gate(dict(self.own, **{"research/Keel/MEASURED.xlsx": b"x"}), [self.mine, self.theirs]))
        self.red("is no workbook the index lists", gate(dict(self.own, **{"other.xlsx": b"x"}), [self.mine, self.theirs]))
        self.red("is listed as owned by Ward and is missing", gate({}, [self.mine, self.theirs]))
        self.red("is missing", gate(self.own, [self.mine], no_index=True))


if __name__ == "__main__":
    unittest.main()
