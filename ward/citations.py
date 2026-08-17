"""Resolve repository-local references made by documentation and JSON manifests.

This is deliberately a small, conservative parser rather than a URL checker.  A source
under version control must not cite a local file that is absent from the same checkout;
network references have a different availability and ownership boundary.  The companion
test treats every discovered local reference as a build-time obligation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse


_MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
# Do not let a fenced block consume the inline spans that follow it.  Local paths in
# executable examples are commands or scratch files, not documentary citations, so this
# intentionally recognises only one-line inline code spans.
_CODE_SPAN = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_PATHLIKE = re.compile(
    r"(?:\.{1,2}/)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+"
    r"\.(?:md|json|py|sh|toml|ya?ml|txt)$|^(?:LICENSE|NOTICE)$"
)
_SKIP_DIRS = frozenset({".git", ".pytest_cache", "__pycache__", "build", "dist"})


@dataclass(frozen=True)
class RelativeReference:
    """One repository-local reference and the file that made it."""

    source: Path
    target: str
    kind: str

    def display(self, root: Path) -> str:
        return f"{self.source.relative_to(root)} [{self.kind}] -> {self.target}"


def _repository_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file() and path.suffix in {".md", ".json"}:
            yield path


def _without_fragment(target: str) -> str:
    return target.split("#", 1)[0].strip()


def _is_relative_target(target: str) -> bool:
    """Whether ``target`` is a local target, not an anchor, absolute path, or URI."""
    if not target or target.startswith("/") or target.startswith("#"):
        return False
    if urlparse(target).scheme:
        return False
    return True


def _is_relative_path(target: str) -> bool:
    """Whether ``target`` has the path-like form appropriate for code and JSON values."""
    if not _is_relative_target(target):
        return False
    return target in {".", "./", "..", "../"} or bool(_PATHLIKE.fullmatch(target))


def _markdown_references(path: Path) -> Iterator[RelativeReference]:
    text = path.read_text(encoding="utf-8")
    for match in _MARKDOWN_LINK.finditer(text):
        target = match.group(1).strip()
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        # A Markdown title follows whitespace.  Ward's documentation currently has none,
        # but resolving the destination rather than its title is the only relevant claim.
        target = target.split(maxsplit=1)[0] if target else target
        target = _without_fragment(target)
        # Markdown's link grammar supplies the structural context, so an extensionless
        # target such as ``[guide](CONTRIBUTING)`` is still a repository citation.
        if _is_relative_target(target):
            yield RelativeReference(path, target, "markdown-link")
    for match in _CODE_SPAN.finditer(text):
        target = _without_fragment(match.group(1).strip())
        if _is_relative_path(target):
            yield RelativeReference(path, target, "documented-path")


def _json_strings(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from _json_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _json_strings(nested)
    elif isinstance(value, str):
        yield value


def _json_references(path: Path) -> Iterator[RelativeReference]:
    content = json.loads(path.read_text(encoding="utf-8"))
    for value in _json_strings(content):
        target = _without_fragment(value)
        if _is_relative_path(target):
            yield RelativeReference(path, target, "json-value")


def relative_references(root: Path) -> list[RelativeReference]:
    """Return all local references in Markdown documentation and JSON manifests."""
    root = root.resolve()
    references: list[RelativeReference] = []
    for path in _repository_files(root):
        if path.suffix == ".md":
            references.extend(_markdown_references(path))
        else:
            references.extend(_json_references(path))
    return references


def dangling_relative_references(root: Path) -> list[RelativeReference]:
    """Return local documentation/manifest references whose targets do not exist."""
    return [
        reference
        for reference in relative_references(root)
        if not (reference.source.parent / reference.target).exists()
    ]
