#!/usr/bin/env python3
"""CLI utility that finds and validates links in Markdown files."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

import requests
from markdown_it import MarkdownIt

MAX_CONCURRENT_REQUESTS = 5
TIMEOUT_SECONDS = 5
MAX_SHOWN_BROKEN = 10
GIT_CLONE_TIMEOUT_SECONDS = 120

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

SKIPPED_SCHEMES = {"mailto", "tel", "ftp", "ftps", "javascript", "data"}


@dataclass
class LinkInfo:
    md_file: str
    line: int
    raw_url: str
    link_type: str  # "http" | "file" | "local"
    check_target: str  # URL for http, filesystem path (string) for file/local


@dataclass
class CheckResult:
    ok: bool
    reason: str
    severity: str  # "red" | "yellow" | ""


@dataclass
class BrokenLink:
    link: LinkInfo
    reason: str
    severity: str


def find_line_number(lines: list[str], start: int, end: int, *needles: str) -> int:
    # markdown-it normalizes hrefs (percent-encoding spaces/non-ASCII), so
    # the raw source line may contain either the encoded or decoded form
    # depending on how the link was written; try both.
    for i in range(start, min(end, len(lines))):
        line = lines[i]
        if any(needle and needle in line for needle in needles):
            return i + 1
    return start + 1


def classify_url(raw_url: str) -> tuple[str, Optional[str]]:
    raw_url = raw_url.strip()
    if not raw_url or raw_url.startswith("#"):
        return "skip", None

    parsed = urlsplit(raw_url)
    scheme = parsed.scheme.lower()

    if scheme in ("http", "https"):
        return "http", raw_url
    if scheme == "file":
        path = unquote(parsed.path)
        return "file", path
    if scheme in SKIPPED_SCHEMES:
        return "skip", None

    # Local filesystem path (relative or absolute); drop query/fragment.
    # markdown-it percent-encodes non-ASCII/unsafe characters (spaces,
    # Cyrillic, etc.) in every link href, not just file:// URIs, so this
    # needs decoding back to real characters before touching the filesystem.
    return "local", unquote(parsed.path)


def parse_markdown_links(md_file: Path, root: Path) -> list[LinkInfo]:
    try:
        text = md_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"{YELLOW}Warning: could not read {md_file}: {exc}{RESET}", file=sys.stderr)
        return []

    md = MarkdownIt("commonmark")
    # The default validator rejects file:// (and a few other) schemes as an
    # XSS precaution for HTML rendering. We only inspect tokens, never
    # render HTML, so it's safe to accept every scheme here and let our own
    # classify_url() decide what to do with it.
    md.validateLink = lambda url: True
    try:
        tokens = md.parse(text)
    except Exception as exc:  # noqa: BLE001 - keep scanning other files
        print(f"{YELLOW}Warning: could not parse {md_file}: {exc}{RESET}", file=sys.stderr)
        return []

    lines = text.splitlines()
    rel_path = md_file.relative_to(root).as_posix()
    results: list[LinkInfo] = []

    for token in tokens:
        if token.type != "inline" or token.map is None or not token.children:
            continue
        start, end = token.map

        for child in token.children:
            href: Optional[str] = None
            if child.type == "link_open":
                href = child.attrGet("href")
            elif child.type == "image":
                href = child.attrGet("src")

            if not href:
                continue

            link_type, target = classify_url(href)
            if link_type == "skip" or target is None:
                continue

            line_no = find_line_number(lines, start, end, href, unquote(href))

            if link_type == "local":
                if target.startswith("/"):
                    resolved = target
                else:
                    resolved = str(md_file.parent / target)
                display_url = target
            elif link_type == "file":
                resolved = target
                display_url = target
            else:  # http
                resolved = href
                display_url = href

            results.append(
                LinkInfo(
                    md_file=rel_path,
                    line=line_no,
                    raw_url=display_url,
                    link_type=link_type,
                    check_target=resolved,
                )
            )

    return results


def check_http_url(url: str) -> CheckResult:
    try:
        response = requests.head(
            url, allow_redirects=True, timeout=TIMEOUT_SECONDS, headers=HEADERS
        )
        if response.status_code in (403, 405):
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=TIMEOUT_SECONDS,
                headers=HEADERS,
                stream=True,
            )
            response.close()

        status = response.status_code
        if 200 <= status < 400:
            return CheckResult(True, "", "")
        return CheckResult(False, f"HTTP {status}", "red")

    except requests.exceptions.Timeout:
        return CheckResult(False, f"Timeout after {TIMEOUT_SECONDS}s", "yellow")
    except requests.exceptions.ConnectionError as exc:
        message = str(exc).lower()
        dns_markers = (
            "name or service not known",
            "nodename nor servname",
            "getaddrinfo failed",
            "gaierror",
            "temporary failure in name resolution",
        )
        if any(marker in message for marker in dns_markers):
            return CheckResult(False, "DNS error", "yellow")
        return CheckResult(False, "Connection error", "yellow")
    except requests.exceptions.RequestException as exc:
        return CheckResult(False, f"Network error: {type(exc).__name__}", "yellow")


def check_local(link: LinkInfo) -> Optional[BrokenLink]:
    if not Path(link.check_target).exists():
        reason = "Local file not found" if link.link_type == "local" else "File not found"
        return BrokenLink(link, reason, "red")
    return None


def run_checks(links: list[LinkInfo]) -> list[BrokenLink]:
    broken: list[BrokenLink] = []

    for link in links:
        if link.link_type in ("local", "file"):
            result = check_local(link)
            if result is not None:
                broken.append(result)

    http_links = [link for link in links if link.link_type == "http"]
    unique_urls = sorted({link.check_target for link in http_links})
    url_results: dict[str, CheckResult] = {}

    if unique_urls:
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            future_to_url = {
                executor.submit(check_http_url, url): url for url in unique_urls
            }
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url_results[url] = future.result()
                except Exception as exc:  # noqa: BLE001 - never crash the whole run
                    url_results[url] = CheckResult(False, f"Network error: {exc}", "yellow")

    for link in http_links:
        result = url_results[link.check_target]
        if not result.ok:
            broken.append(BrokenLink(link, result.reason, result.severity))

    return broken


def print_report(total_checked: int, broken: list[BrokenLink]) -> None:
    print(f"Links checked: {CYAN}{total_checked}{RESET}")
    broken_count = len(broken)
    if broken_count == 0:
        print(f"Broken links: {GREEN}0{RESET}")
    else:
        print(f"Broken links: {RED}{broken_count}{RESET}")
    print()

    if broken_count == 0:
        print(f"{GREEN}No broken links found.{RESET}")
        return

    shown = broken[:MAX_SHOWN_BROKEN]
    for item in shown:
        color = RED if item.severity == "red" else YELLOW
        print(f"{RED}BROKEN{RESET}  {item.link.md_file}:{item.link.line}")
        print(f"        {item.link.raw_url}")
        print(f"        {color}{item.reason}{RESET}")
        print()

    if broken_count > MAX_SHOWN_BROKEN:
        print("...")
        print(f"Showing {MAX_SHOWN_BROKEN} of {broken_count} broken links.")


def looks_like_git_url(source: str) -> bool:
    return source.startswith(("http://", "https://", "git@", "ssh://", "git://")) or source.endswith(
        ".git"
    )


# Matches web-UI browsing URLs like:
#   https://github.com/user/repo/tree/main
#   https://github.com/user/repo/tree/main/some/subdir
#   https://github.com/user/repo/blob/main/README.md
#   https://gitlab.com/user/repo/-/tree/main
# and extracts (clone_url, branch) from them, since these are not valid
# `git clone` URLs on their own.
GIT_WEB_TREE_RE = re.compile(
    r"^(https?://(?:www\.)?[^/]+/[^/]+/[^/]+?)(?:\.git)?/(?:-/)?(?:tree|blob|commits|src)/([^/?#]+)(?:[/?#].*)?$"
)


def normalize_git_source(source: str) -> tuple[str, Optional[str]]:
    """Turn a GitHub/GitLab/Bitbucket web-browsing URL into a (clone_url, branch) pair."""
    match = GIT_WEB_TREE_RE.match(source)
    if match:
        repo_url, branch = match.groups()
        return repo_url, branch
    return source, None


def clone_repo(url: str) -> Path:
    clone_url, branch = normalize_git_source(url)
    tmp_dir = Path(tempfile.mkdtemp(prefix="linkchecker-"))
    branch_note = f" (branch: {branch})" if branch else ""
    print(f"{CYAN}Cloning {clone_url}{branch_note} ...{RESET}")

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [clone_url, str(tmp_dir)]

    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_CLONE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"{RED}Error: git is not installed or not on PATH{RESET}", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(
            f"{RED}Error: git clone timed out after {GIT_CLONE_TIMEOUT_SECONDS}s{RESET}",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        print(f"{RED}Error: git clone failed: {stderr}{RESET}", file=sys.stderr)
        sys.exit(1)
    return tmp_dir


def main() -> None:
    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {Path(sys.argv[0]).name} <directory-or-git-url>",
            file=sys.stderr,
        )
        sys.exit(1)

    source = sys.argv[1]
    temp_dir: Optional[Path] = None
    exit_code = 0

    try:
        if looks_like_git_url(source):
            temp_dir = clone_repo(source)
            root = temp_dir
        else:
            root = Path(source)
            if not root.is_dir():
                print(f"{RED}Error: {root} is not a directory{RESET}", file=sys.stderr)
                sys.exit(1)
            root = root.resolve()

        md_files = sorted(root.rglob("*.md"))

        all_links: list[LinkInfo] = []
        for md_file in md_files:
            all_links.extend(parse_markdown_links(md_file, root))

        broken = run_checks(all_links)
        print_report(len(all_links), broken)
        exit_code = 1 if broken else 0
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
