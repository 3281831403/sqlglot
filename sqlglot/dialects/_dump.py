from __future__ import annotations

import re
from typing import NamedTuple

# Keywords that open a stored-program block closed by END
_BLOCK_OPENERS = frozenset(
    {
        "BEGIN",
        "CASE",
        "IF",
        "LOOP",
        "REPEAT",
        "WHILE",
    }
)

_DELIMITER_RE = re.compile(r"[ \t]*DELIMITER[ \t]+(\S+)[ \t]*\r?$", re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_EXECUTABLE_COMMENT_RE = re.compile(r"^\/\*!(?:\d{3,6})?[ \t]*")


class DumpSegment(NamedTuple):
    text: str
    kind: str  # "sql" | "delimiter" | "comment"


def split_mysql_dump(sql: str) -> list[DumpSegment]:
    """
    Splits a mysqldump script into its top-level statements.

    Unlike a naive split on `;`, this scanner is aware of the client-side
    `DELIMITER` directive and of stored-program `BEGIN ... END` blocks, so the
    semicolons found inside a trigger/procedure body never break a statement.
    MySQL executable comments (``/*!...*/``) are surfaced as their own segments
    instead of being stripped as ordinary comments.

    Args:
        sql: the mysqldump script.

    Returns:
        The list of segments, one per statement/directive/executable comment.
        Comments-only and whitespace-only gaps don't produce segments.
    """
    segments: list[DumpSegment] = []

    delimiter = ";"
    start = 0
    # Keywords of the stored-program blocks currently open ("BEGIN", "IF", ...).
    # A transaction "BEGIN" is not a block and is never pushed.
    block_stack: list[str] = []
    labels: set[str] = set()
    i = 0
    size = len(sql)

    def emit(end: int, kind: str, text: str | None = None) -> None:
        nonlocal start
        if text is not None:
            segments.append(DumpSegment(text=text.strip(), kind=kind))
            start = end
            return
        # Gaps between statements only contain comments/whitespace: they don't
        # occupy a statement slot
        if _is_ignorable(sql, start, end):
            start = end
            return
        # The trailing delimiter belongs to the dump framing, not the statement
        segment_text = sql[start:end].strip()
        if segment_text.endswith(delimiter):
            segment_text = segment_text[: -len(delimiter)].rstrip()
        if segment_text:
            segments.append(DumpSegment(text=segment_text, kind=kind))
        start = end

    while i < size:
        char = sql[i]

        # Whitespace
        if char in " \t\r\n":
            i += 1
            continue

        # String / identifier literals: scan over them without interpreting contents
        if char in ("'", '"', "`"):
            i = _scan_quoted(sql, i + 1, char)
            continue

        # Comments
        if sql.startswith("--", i) or char == "#":
            j = sql.find("\n", i)
            i = size if j == -1 else j + 1
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end == -1:
                # Unterminated comment: the remaining text is not splittable
                break
            end += 2

            if sql.startswith("/*!", i):
                # Executable comments are standalone statements (a version-gated
                # comment never wraps a multi-statement body in mysqldump); the
                # text before them is either another statement or plain comments
                if not _is_ignorable(sql, start, i):
                    segments.append(DumpSegment(text=sql[start:i].strip(), kind="sql"))
                start = i
                emit(end, "comment", text=sql[i:end])
                i = end
                continue

        # DELIMITER is a client directive, not SQL; it is only recognized on its
        # own line (leading whitespace allowed) and applies from the next line
        line_start = sql.rfind("\n", 0, i) + 1
        if not sql[line_start:i].strip():
            line_end = sql.find("\n", i)
            window_end = size if line_end == -1 else line_end
            match = _DELIMITER_RE.match(sql, i, window_end)
            if match:
                emit(i, "sql")
                emit(match.end(), "delimiter", text=sql[i : match.end()].strip())
                delimiter = match.group(1)
                i = match.end()
                block_stack.clear()
                labels.clear()
                continue

        # Words: BEGIN/END stack and label tracking
        word_match = _WORD_RE.match(sql, i)
        if word_match:
            word = word_match.group().upper()
            word_end = word_match.end()

            # Label definition, e.g. `my_loop: WHILE ...`
            if sql[word_end : word_end + 1] == ":":
                labels.add(word)
                i = word_end + 1
                continue

            if word == "BEGIN":
                if not sql[word_end:].lstrip(" \t\r\n").startswith(delimiter):
                    # A bare "BEGIN" immediately followed by the delimiter starts
                    # a transaction, not a stored-program block
                    block_stack.append("BEGIN")
            elif word == "IF" and _looks_ahead(sql, word_end, "THEN"):
                # A control-flow IF ... THEN, as opposed to the IF() function or
                # the DDL "IF EXISTS" / "IF NOT EXISTS" clauses
                block_stack.append("IF")
            elif (
                word == "CASE" and block_stack and _has_matching_end_case(sql, word_end, delimiter)
            ):
                # Inside a stored-program body a CASE statement is closed by
                # "END CASE"; a CASE expression uses a bare "END"
                block_stack.append("CASE")
            elif word in ("LOOP", "REPEAT", "WHILE"):
                block_stack.append(word)
            elif word == "END":
                tail = sql[word_end:].lstrip(" \t\r\n")
                tail_match = _WORD_RE.match(tail)
                tail_word = tail_match.group().upper() if tail_match else ""
                if block_stack and (
                    (not tail_word and block_stack[-1] == "BEGIN")
                    or tail_word == block_stack[-1]
                    or tail_word in labels
                ):
                    block_stack.pop()
                if tail_match and tail_word in labels | _BLOCK_OPENERS:
                    word_end += len(tail) - len(tail.lstrip(" \t\r\n")) + tail_match.end()
            i = word_end
            continue

        # Statement delimiter: inside a BEGIN ... END block it only terminates an
        # inner statement, so the outer segment must keep spanning it
        if sql.startswith(delimiter, i):
            if block_stack:
                i += len(delimiter)
                continue

            # A delimiter right after a standalone executable comment closes
            # that comment's statement instead of opening an empty one
            if segments and segments[-1].kind == "comment" and _is_ignorable(sql, start, i):
                start = i + len(delimiter)
            else:
                emit(i + len(delimiter), "sql")
            i += len(delimiter)
            continue

        i += 1

    emit(size, "sql")
    return segments


def _scan_quoted(sql: str, i: int, quote: str) -> int:
    size = len(sql)
    while i < size:
        current = sql[i]
        if current == "\\":
            i += 2
            continue
        if current == quote:
            if i + 1 < size and sql[i + 1] == quote:
                i += 2
                continue
            return i + 1
        i += 1
    return i


def _looks_ahead(sql: str, i: int, keyword: str) -> bool:
    """Whether `keyword` appears as the next word (ignoring whitespace/comments)."""
    match = _WORD_RE.search(sql, i)
    return bool(match) and match.group().upper() == keyword


def _has_matching_end_case(sql: str, i: int, delimiter: str) -> bool:
    """Whether a CASE starting at `i` is closed by an "END CASE" before the delimiter."""
    boundary = sql.find(delimiter, i)
    window = sql[i:] if boundary == -1 else sql[i:boundary]
    return bool(re.search(r"\bEND\s+CASE\b", window, re.IGNORECASE))


def _is_ignorable(sql: str, start: int, end: int) -> bool:
    """Whether the range only contains whitespace and (non-executable) comments."""
    i = start
    while i < end:
        char = sql[i]
        if char in " \t\r\n":
            i += 1
        elif sql.startswith("--", i) or char == "#":
            j = sql.find("\n", i, end)
            i = end if j == -1 else j + 1
        elif sql.startswith("/*", i):
            if sql.startswith("/*!", i):
                return False
            close = sql.find("*/", i + 2, end)
            if close == -1:
                return False
            i = close + 2
        else:
            return False
    return True


def is_executable_comment(text: str) -> bool:
    return bool(_EXECUTABLE_COMMENT_RE.match(text))


def strip_executable_comment(text: str) -> str:
    """Returns the SQL wrapped by a MySQL executable comment."""
    return _EXECUTABLE_COMMENT_RE.sub("", text)[:-2].strip()
