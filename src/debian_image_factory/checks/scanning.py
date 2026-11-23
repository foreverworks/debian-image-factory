"""Finding a snapshot ID, a private key and a credential token in a stream of chunks, pure.

A match may straddle two chunks, so each chunk is searched together with the tail of the text before it.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

OVERLAP: Final = 1280
"""Bytes kept between chunks. At least as long as the longest thing looked for: a PyPI token is at most
20 + 1000 characters, a key header with its newline and the first sixteen characters of its body come to
103 bytes, and a snapshot ID is 16."""

KEY_MARKER: Final = b"-----BEGIN "

ELF_MAGIC: Final = b"\x7fELF"
"""A compiled program starts with these bytes. Programs carry sample and test strings (Debian's `gh` holds a
GitHub token-shaped one, which its own tests use), so credential shapes are searched in text and data, not
in executables; a private key block is searched everywhere."""

KEY_BLOCK: Final = re.compile(
    rb"(?<![^\n])-----BEGIN (?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?-----[ \t]*\r?\n"
    rb"(?:[A-Za-z0-9+/]{16}|[A-Za-z][A-Za-z-]*: |\r?\n)"
)
"""A private key as a file holds one, not as a document talks about one: the header owns its line, from
its first column, and is followed by the key's own first line (base64, a `Proc-Type:` or armor header,
or the blank line after an armor header). A sentence that quotes the header does not match."""


@dataclass(frozen=True, slots=True)
class Token:
    """A credential shape: a name for the report, the plain bytes any match contains (a cheap prefilter,
    so a chunk without them is never searched with the expression), the expression, and the end a
    documentation example carries (`AKIAIOSFODNN7EXAMPLE` is AWS's own sample), which makes a match benign."""

    name: str
    markers: tuple[bytes, ...]
    pattern: re.Pattern[bytes]
    example_suffix: bytes = b""


TOKENS: Final = (
    # GitHub: a prefix for the kind (ghp_ personal, gho_ OAuth, ghu_ and ghs_ app user and installation, ghr_
    # refresh), "_", and 36 base62 characters, 40 in all. Docs: "About authentication to GitHub", token
    # formats (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github),
    # and the GitHub blog's "Behind GitHub's new authentication token formats" (the underscore, 40
    # characters kept); the 36 comes from gitleaks' rules (github.go: `ghp_[0-9a-zA-Z]{36}`).
    Token(
        "GitHub token",
        (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"),
        re.compile(rb"(?<![A-Za-z0-9])gh[pousr]_[0-9A-Za-z]{36}"),
    ),
    # GitHub fine-grained personal access token: `github_pat_` and 82 word characters (gitleaks github.go:
    # `github_pat_\w{82}`); GitHub's docs name the prefix and give no length.
    Token("GitHub fine-grained token", (b"github_pat_",), re.compile(rb"(?<![A-Za-z0-9])github_pat_[0-9A-Za-z_]{82}")),
    # AWS access key ID: AKIA (long-term key) or ASIA (temporary STS key), then 16 characters of base32,
    # 20 in all. Prefixes: AWS IAM docs, "Understanding unique ID prefixes"
    # (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html); length and alphabet:
    # gitleaks aws.go `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`. AWS's own samples end in EXAMPLE.
    Token(
        "AWS access key ID",
        (b"AKIA", b"ASIA"),
        re.compile(rb"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z2-7]{16}(?![A-Za-z0-9])"),
        b"EXAMPLE",
    ),
    # Slack: `xox` and b (bot), p (user), a, r or s (legacy), "-", one to three groups of digits and a
    # secret of letters and digits, dash separated, "most secrets are 32 characters" (Slack docs,
    # https://docs.slack.dev/authentication/tokens); group and secret sizes from gitleaks slack.go
    # (`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`, `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`,
    # `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}`); app-level `xapp-1-A0123456789-1234567890123-<64>` likewise.
    Token(
        "Slack token",
        (b"xoxb-", b"xoxp-", b"xoxa-", b"xoxr-", b"xoxs-"),
        re.compile(rb"(?<![A-Za-z0-9])xox[abprs]-[0-9]{8,14}(?:-[0-9]{8,14}){0,2}-[A-Za-z0-9]{18,40}"),
    ),
    Token(
        "Slack app-level token",
        (b"xapp-",),
        re.compile(rb"(?<![A-Za-z0-9])xapp-[0-9]-[A-Za-z0-9]{8,12}-[0-9]{10,14}-[A-Za-z0-9]{64}"),
    ),
    # npm granular and classic automation tokens: `npm_` and 36 letters and digits (gitleaks npm.go
    # `npm_[a-z0-9]{36}`; npm's docs name no format).
    Token("npm token", (b"npm_",), re.compile(rb"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}")),
    # PyPI upload token: `pypi-` and a macaroon whose first bytes are always the base64 of the PyPI
    # location, `AgEIcHlwaS5vcmc`, then 50 to 1000 base64url characters (gitleaks pypi.go
    # `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`).
    Token(
        "PyPI token",
        (b"pypi-AgEIcHlwaS5vcmc",),
        re.compile(rb"(?<![A-Za-z0-9])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}"),
    ),
    # GitLab personal, project and group access tokens: `glpat-` (the default prefix, GitLab docs
    # https://docs.gitlab.com/security/tokens/) and 20 characters of letters, digits, `_` and `-`
    # (gitleaks gitlab.go `glpat-[\w-]{20}`). Longer routable tokens start the same way and match too.
    Token("GitLab token", (b"glpat-",), re.compile(rb"(?<![A-Za-z0-9])glpat-[0-9A-Za-z_-]{20}")),
)
"""Credential shapes with a fixed, documented prefix and length, so Debian's own files almost never match."""


@dataclass(frozen=True, slots=True)
class TokenHit:
    """A token found: its kind and a redacted form (the first four characters and the length), never the token."""

    kind: str
    redacted: str


@dataclass(frozen=True, slots=True)
class Hits:
    needle: bool
    key: bool
    tokens: tuple[TokenHit, ...] = ()
    """The first match of each kind of token found, in TOKENS order."""


def redacted(match: bytes) -> str:
    """`ghp_…(40 characters)`: enough to tell which shape matched, nothing that could be used."""
    return f"{match[:4].decode('ascii', 'replace')}…({len(match)} characters)"


def token_hits(buffer: bytes, found: dict[str, TokenHit]) -> None:
    """Add to `found` the first match of every kind of token in `buffer` that has none yet.

    A match that starts at offset 0 is not trusted: the character before it may have been cut off with
    the chunk, and the buffer's first byte is only a start of text for the first chunk (which begins
    with a newline of its own)."""
    for token in TOKENS:
        if token.name in found or not any(marker in buffer for marker in token.markers):
            continue
        for match in token.pattern.finditer(buffer):
            text = match.group()
            if match.start() > 0 and not (token.example_suffix and text.endswith(token.example_suffix)):
                found[token.name] = TokenHit(token.name, redacted(text))
                break


type Needle = str | Sequence[str] | None
"""What to look for: one text, several (any of them counts) or nothing."""


def needles_of(needle: Needle) -> tuple[str, ...]:
    """The non-empty texts of a `Needle`, as a tuple."""
    if needle is None:
        return ()
    return tuple(one for one in ((needle,) if isinstance(needle, str) else needle) if one)


def scan(chunks: Iterable[bytes], needle: bytes | Sequence[bytes] | None, keys: bool) -> Hits:
    """Whether the bytes hold `needle` (or any of several), and whether they hold a private key block or a
    credential token
    (when `keys`).

    Stops reading once the needle was found (or none was asked for) and no key search was asked for. Tokens
    are not searched in an executable (`ELF_MAGIC`).
    """
    needles = (needle,) if isinstance(needle, bytes) else tuple(needle or ())
    needles = tuple(one for one in needles if one)
    found_needle, found_key = False, False
    found_tokens: dict[str, TokenHit] = {}
    tail = b"\n"  # the start of the file counts as the start of a line
    tokens = keys
    for index, chunk in enumerate(chunks):
        if index == 0 and chunk.startswith(ELF_MAGIC):
            tokens = False
        buffer = tail + chunk
        if needles and not found_needle and any(one in buffer for one in needles):
            found_needle = True
        if keys and not found_key and KEY_MARKER in buffer:
            # a match that starts in the tail was complete in the buffer before: it was judged there
            found_key = any(match.start() > 0 for match in KEY_BLOCK.finditer(buffer))
        if tokens:
            token_hits(buffer, found_tokens)
        if not keys and (found_needle or not needles):
            break
        tail = buffer[-OVERLAP:]
    return Hits(found_needle, found_key, tuple(found_tokens[t.name] for t in TOKENS if t.name in found_tokens))
