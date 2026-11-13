from __future__ import annotations

import string

from sqlglot.dialects.dialect import Dialect, DialectType
from sqlglot.errors import TokenError
from sqlglot.parser import Parser
from sqlglot.tokens import Token, TokenType

ALPHABET = string.ascii_lowercase
ALPHABET_SIZE = len(ALPHABET)
ANONYMIZED_TYPES = {
    TokenType.BIT_STRING,
    TokenType.BYTE_STRING,
    TokenType.HEX_STRING,
    TokenType.HEREDOC_STRING,
    TokenType.IDENTIFIER,
    TokenType.NATIONAL_RAW_STRING,
    TokenType.NATIONAL_STRING,
    TokenType.NUMBER,
    TokenType.RAW_STRING,
    TokenType.STRING,
    TokenType.UNICODE_STRING,
    TokenType.VAR,
}
QUOTED_TYPES = ANONYMIZED_TYPES - {TokenType.NUMBER, TokenType.VAR}
REWRITTEN_TYPES = {TokenType.HINT, TokenType.UNKNOWN}


class _Anonymizer:
    """Shared state behind `anonymize` and `anonymize_batch`.

    A single instance aliases every token stream it is given, so a token with the same
    text gets the same alias no matter which statement it appears in. `known` lets a batch
    pre-assign every alias up front (in a stable order); standalone callers discover keys in
    encounter order instead.
    """

    def __init__(
        self,
        dialect: Dialect,
        known: dict[tuple[bool, str], str] | None = None,
    ) -> None:
        self.dialect = dialect
        self.tokenizer_class = dialect.tokenizer_class
        self.parser_class = dialect.parser_class
        self.hint_start = self.tokenizer_class.HINT_START
        self.hint_end = self.tokenizer_class._COMMENTS.get(self.hint_start)
        self.nested = self.tokenizer_class.NESTED_COMMENTS
        self.seen: dict[tuple[bool, str], str] = known or {}
        self.counter = len(self.seen)

    def anonymize(self, tokens: list[Token]) -> list[Token]:
        for i, token in enumerate(tokens):
            token.comments = [_blank(comment) for comment in token.comments]

            if token.token_type == TokenType.HINT:
                # A hint's text is the whole /*+ ... */ comment, so its body is blanked as well
                text, stop = _blank_comment(
                    token.text, 0, self.hint_start, self.hint_end, self.nested
                )
                token.text = text + _blank(token.text[stop:])
                continue

            if self._is_known_function(tokens, i):
                continue
            if token.token_type not in ANONYMIZED_TYPES or not token.text:
                continue

            is_number = token.token_type == TokenType.NUMBER
            key = (is_number, token.text)
            alias = self.seen.get(key)
            if alias is None:
                alias = (
                    _number_alias(self.counter, token.text)
                    if is_number
                    else _alias(self.counter, token.text)
                )
                self.seen[key] = alias
                self.counter += 1
            token.text = alias

        return tokens

    def _is_known_function(self, tokens: list[Token], i: int) -> bool:
        token = tokens[i]
        if token.token_type != TokenType.VAR or i + 1 >= len(tokens):
            return False
        if tokens[i + 1].token_type != TokenType.L_PAREN:
            return False
        # A function name can live in either registry, e.g. JSON_OBJECT is only in
        # FUNCTION_PARSERS. They're consulted separately to avoid building their union
        name = token.text.upper()
        return name in self.parser_class.FUNCTIONS or name in self.parser_class.FUNCTION_PARSERS


def anonymize(
    sql_or_tokens: list[Token] | str,
    dialect: DialectType = None,
) -> list[Token]:
    """Replaces sensitive tokens (identifiers, strings, numbers) with fixed-width,
    length-preserving, consistent aliases, and blanks out comments and hint bodies. When a
    SQL string is given, it is tokenized with `dialect` first; any un-tokenized remainder
    (e.g. an unterminated literal) is appended as a blanked UNKNOWN token. Mutates and
    returns `sql_or_tokens`.

    Args:
        sql_or_tokens: The SQL string to anonymize, or its token list.
        dialect: The dialect used to tokenize a SQL string.
    """
    dialect = Dialect.get_or_raise(dialect)
    errored = False

    if isinstance(sql_or_tokens, str):
        sql = sql_or_tokens
        tokenizer = dialect.tokenizer()
        try:
            tokens = tokenizer.tokenize(sql)
        except TokenError:
            tokens = tokenizer.tokens
            errored = True
    else:
        tokens = sql_or_tokens
        sql = None

    _Anonymizer(dialect).anonymize(tokens)

    if sql is not None:
        _append_unknown_tail(tokens, sql, errored)

    return tokens


def anonymize_batch(
    sqls: list[str],
    dialect: DialectType = None,
) -> list[list[Token]]:
    """Anonymizes several SQL statements against one shared, order-independent alias table.

    The same identifier, string literal, or number always maps to the same alias across the
    whole batch, whether it is written bare or quoted, and regardless of statement order:
    aliases are assigned after every statement is tokenized, with the distinct sensitive
    texts sorted, so shuffling the inputs (or running the batch in another process) leaves
    each statement's output unchanged. Returns one token list per input, in the same order
    and of the same length as `sqls`.

    Args:
        sqls: The SQL strings to anonymize as one batch.
        dialect: The dialect used to tokenize the SQL strings.
    """
    dialect = Dialect.get_or_raise(dialect)

    tokenized: list[tuple[list[Token], bool]] = []
    keys: set[tuple[bool, str]] = set()
    for sql in sqls:
        tokenizer = dialect.tokenizer()
        try:
            tokens = tokenizer.tokenize(sql)
        except TokenError:
            tokens = tokenizer.tokens
            errored = True
        else:
            errored = False
        tokenized.append((tokens, errored))
        _collect_keys(tokens, dialect.parser_class, keys)

    known = _build_aliases(sorted(keys))
    anonymizer = _Anonymizer(dialect, known)

    results = []
    for (tokens, errored), sql in zip(tokenized, sqls):
        anonymizer.anonymize(tokens)
        _append_unknown_tail(tokens, sql, errored)
        results.append(tokens)

    return results


def _collect_keys(
    tokens: list[Token],
    parser_class: type[Parser],
    keys: set[tuple[bool, str]],
) -> None:
    for i, token in enumerate(tokens):
        if token.token_type not in ANONYMIZED_TYPES or not token.text:
            continue
        if (
            token.token_type == TokenType.VAR
            and i + 1 < len(tokens)
            and tokens[i + 1].token_type == TokenType.L_PAREN
        ):
            # A function name can live in either registry, e.g. JSON_OBJECT is only in
            # FUNCTION_PARSERS. They're consulted separately to avoid building their union
            name = token.text.upper()
            if name in parser_class.FUNCTIONS or name in parser_class.FUNCTION_PARSERS:
                continue
        keys.add((token.token_type == TokenType.NUMBER, token.text))


def _build_aliases(keys: list[tuple[bool, str]]) -> dict[tuple[bool, str], str]:
    aliases: dict[tuple[bool, str], str] = {}
    for counter, (is_number, text) in enumerate(keys):
        aliases[(is_number, text)] = (
            _number_alias(counter, text) if is_number else _alias(counter, text)
        )
    return aliases


def _append_unknown_tail(tokens: list[Token], sql: str, errored: bool) -> list[Token]:
    if not errored:
        return tokens

    start = tokens[-1].end + 1 if tokens else 0
    length = len(sql)
    while start < length and sql[start].isspace():
        start += 1
    if start < length:
        # The first two characters are kept so that the delimiter the tokenizer choked
        # on is still visible, e.g. 'u, /*, $$, `u
        tokens.append(
            Token(
                TokenType.UNKNOWN,
                sql[start : start + 2] + "." * (length - start - 2),
                start=start,
                end=length - 1,
                line=sql.count("\n", 0, start) + 1,
                col=start - sql.rfind("\n", 0, start),
            )
        )
    return tokens


def render(sql: str, tokens: list[Token], dialect: DialectType = None) -> str:
    """Recreates the (anonymized) SQL string from the original `sql` and token positions.

    Every token is rendered over its own source span, so the result is always as long as
    `sql`: a token that wasn't anonymized is emitted verbatim, keeping the spelling the
    tokenizer normalized away, and an anonymized one has its alias fitted between the
    quotes of its span. The gaps between tokens hold only whitespace and comments, so
    they're redacted rather than reconstructed: comment markers and whitespace survive,
    everything else is blanked. That covers anything the tokenizer didn't reach as well,
    which is a trailing gap whenever `anonymize` wasn't the one to tokenize `sql`.

    Args:
        sql: The original SQL string.
        tokens: The anonymized tokens to render.
        dialect: The dialect used to identify comments and quotes in `sql`.
    """
    tokenizer_class = Dialect.get_or_raise(dialect).tokenizer_class
    comments = sorted(tokenizer_class._COMMENTS.items(), key=lambda c: len(c[0]), reverse=True)
    nested = tokenizer_class.NESTED_COMMENTS
    quotes = sorted(
        {
            **tokenizer_class._QUOTES,
            **{start: end for start, (end, _) in tokenizer_class._FORMAT_STRINGS.items()},
            **tokenizer_class._IDENTIFIERS,
        }.items(),
        key=lambda quote: (len(quote[0]), len(quote[1])),
        reverse=True,
    )

    result = []
    prev = 0

    for token in tokens:
        result.append(_redact(sql[prev : token.start], comments, nested))
        prev = token.end + 1
        span = sql[token.start : prev]
        if token.token_type in REWRITTEN_TYPES:
            # Blanked in place by `anonymize`, or synthesized by it, so already span-shaped
            result.append(token.text)
        elif token.token_type in ANONYMIZED_TYPES:
            result.append(_fit(span, token.text, quotes, token.token_type))
        else:
            result.append(span)

    result.append(_redact(sql[prev:], comments, nested))

    return "".join(result)


def _alias(counter: int, text: str) -> str:
    digits = []
    while counter:
        counter, digit = divmod(counter, ALPHABET_SIZE)
        digits.append(ALPHABET[digit])

    letters = "".join(reversed(digits)).rjust(sum(not char.isspace() for char in text), "a")

    alias = []
    i = 0
    for char in text:
        if char.isspace():
            alias.append(char)
        else:
            alias.append(letters[i])
            i += 1

    return "".join(alias)


def _number_alias(counter: int, text: str) -> str:
    if len(text) > 4000:
        digits_seen = False
        blanked = []
        for char in text:
            if char.isdigit():
                blanked.append("0" if digits_seen else "1")
                digits_seen = True
            else:
                blanked.append(char)
        return "".join(blanked)

    sep = "e" if "e" in text else ("E" if "E" in text else "")
    mantissa, _, exponent = text.partition(sep) if sep else (text, "", "")
    sign = ""
    if exponent.startswith(("-", "+")):
        sign, exponent = exponent[0], exponent[1:]
    exponent_length = len(exponent)

    integer, dot, fraction = mantissa.partition(".")
    integer_length = len(integer)
    digits = integer_length + len(fraction)
    mantissa_value = 10 ** (digits - 1) + counter % (9 * 10 ** (digits - 1))
    result = str(mantissa_value)
    if dot:
        result = result[:integer_length] + "." + result[integer_length:]
    if sep:
        # The exponent marker is kept even when there are no digits after it, e.g. 1e
        result += sep + sign
        if exponent_length:
            exponent_value = 10 ** (exponent_length - 1) + (counter // (9 * 10 ** (digits - 1))) % (
                9 * 10 ** (exponent_length - 1)
            )
            result += str(exponent_value)

    return result


def _fit(span: str, alias: str, quotes: list[tuple[str, str]], token_type: TokenType) -> str:
    """Fits `alias` into the quoted region of `span`, so the two are always the same length."""
    start = end = 0

    if token_type in QUOTED_TYPES:
        for open_quote, close_quote in quotes:
            if (
                len(span) >= len(open_quote) + len(close_quote)
                and span.startswith(open_quote)
                and span.endswith(close_quote)
            ):
                start, end = len(open_quote), len(close_quote)

                if token_type == TokenType.HEREDOC_STRING:
                    # A heredoc's tag is part of its delimiter, e.g. $tag$body$tag$
                    open_end = span.find(close_quote, start)
                    close_start = span.rfind(open_quote, 0, len(span) - end)
                    if start <= open_end < close_start:
                        start, end = open_end + len(close_quote), len(span) - close_start

                break

    width = len(span) - start - end
    pad = "0" if token_type == TokenType.NUMBER else "a"

    return span[:start] + alias[:width].rjust(width, pad) + span[len(span) - end :]


def _blank(sql: str) -> str:
    return "".join(char if char.isspace() else "." for char in sql)


def _blank_comment(sql: str, i: int, start: str, end: str | None, nested: bool) -> tuple[str, int]:
    """Blanks the body of the comment at `i`, returning its text and the index past it."""
    body = i + len(start)

    if not end:
        stop = sql.find("\n", body)
        stop = len(sql) if stop == -1 else stop
        return start + _blank(sql[body:stop]), stop

    depth = 1
    j = body
    while j < len(sql):
        if nested and sql.startswith(start, j):
            depth += 1
            j += len(start)
        elif sql.startswith(end, j):
            j += len(end)
            depth -= 1
            if not depth:
                return start + _blank(sql[body : j - len(end)]) + end, j
        else:
            j += 1

    return start + _blank(sql[body:]), len(sql)


def _redact(sql: str, comments: list[tuple[str, str | None]], nested: bool) -> str:
    if not sql or sql.isspace():
        return sql

    result = []
    i = 0
    length = len(sql)

    while i < length:
        for start, end in comments:
            if sql.startswith(start, i):
                text, i = _blank_comment(sql, i, start, end, nested)
                result.append(text)
                break
        else:
            char = sql[i]
            result.append(char if char.isspace() else ".")
            i += 1

    return "".join(result)
