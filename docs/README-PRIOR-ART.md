# README prior art

No network research was used for this rewrite. It adopts durable structural conventions from
well-known open-source security and command-line projects, not their wording:

- **ripgrep** — a concrete one-sentence definition, a runnable command near the top, and limits
  stated beside capabilities.
- **fzf** — a visual-first terminal story and a copy-paste quickstart.
- **age** — a deliberately narrow contract, explicit non-goals, and a small operator-facing
  surface.
- **Semgrep** — an approachable security-rule catalog organized around what each named check
  examines.
- **Makoto** — the supplied local house style: exact counts and identifiers, explicit hook and
  protocol wiring, an auditable allow annotation, and caveats adjacent to claims.

Every Ward implementation claim and example was then derived from the shipped tree; the sibling
engine framing came from the supplied release brief. The README makes no benchmark, popularity, or
efficacy claim.
