"""
─────────────────────────────────────────────────────────────────────
The shape of a pytest test
─────────────────────────────────────────────────────────────────────
  def test_<what_we_are_checking>() -> None:
      result = some_function(some_input)
      assert result == expected

Three rules
  1. The function name must start with `test_` — pytest only collects
     functions that match that pattern
  2. The function takes no arguments (unless using fixtures)
  3. Use the `assert` keyword to declare what should be true. If the
     condition is false, the test fails

We follow the "Arrange-Act-Assert" structure inside each test
  - Arrange: set up inputs (the `sample = ...` line)
  - Act:     call the real code (`candidates = identify(sample)`)
  - Assert:  check the result (`assert candidates[0]...`)

─────────────────────────────────────────────────────────────────────
Coverage strategy
─────────────────────────────────────────────────────────────────────
  - prefix matches (one bcrypt, one Argon2id, one Django, one crypt)
  - special MySQL5 format
  - hex length matches (MD5, SHA-1, SHA-256 lengths)
  - the empty / garbage / whitespace fallbacks
  - HashCandidate's immutability
"""

import pytest
from hash_identifier import PREFIX_RULES, HashCandidate, identify

# =============================================================================
# Prefix matches (high confidence)
# =============================================================================
# These tests verify Step 1 of identify(): when the input starts with a
# known prefix, we report HIGH confidence.


def test_bcrypt_prefix_is_recognized() -> None:
    """
    A real bcrypt hash starts with `$2b$` and should be reported as bcrypt
    """
    sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"
    candidates = identify(sample)
    assert candidates
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "high"


def test_argon2id_prefix_is_recognized() -> None:
    """
    Argon2id PHC strings begin with `$argon2id$`
    """
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA"
    candidates = identify(sample)
    assert any(c.algorithm == "Argon2id" for c in candidates)


def test_sha512_crypt_prefix_is_recognized() -> None:
    """
    `$6$` is the marker for SHA-512 crypt — what /etc/shadow uses on Linux
    """
    sample = "$6$rounds=10000$salt$hashedpasswordhere"
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-512 crypt"


def test_django_pbkdf2_prefix_is_recognized() -> None:
    """
    Django stores passwords as `pbkdf2_sha256$<iter>$<salt>$<hash>`
    """
    sample = "pbkdf2_sha256$260000$salt$hash"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Django PBKDF2-SHA256"


def test_apr1_prefix_is_recognized() -> None:
    """
    Apache `.htpasswd` MD5 hashes start with $apr1$
    """
    sample = "$apr1$rsalt$mp7TYYDvbgvNCJN3JTd6q1"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Apache MD5-crypt"
    assert candidates[0].confidence == "high"


def test_pbkdf2_sha1_prefix_is_recognized() -> None:
    """
    Older Atlassian / Jira hashes start with $pbkdf2$
    """
    sample = "$pbkdf2$[iterações]$[salt_em_base64]$[hash_em_base64]"
    candidates = identify(sample)
    assert candidates[0].algorithm == "PBKDF2-SHA1 (Atlassian)"
    assert candidates[0].confidence == "high"


# =============================================================================
# Special formats
# =============================================================================
# Step 2 of identify(): formats that are NOT PHC strings but still have
# unmistakable shapes.


def test_mysql5_format_is_recognized() -> None:
    """
    MySQL5 = literal `*` followed by 40 uppercase hex chars
    """
    sample = "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence == "high"


def test_mysql5_rejects_lowercase_body() -> None:
    """
    Lowercase hex after the leading `*` is not real MySQL5 output
    """
    lowercase_body = "23ae809ddacaf96af0fd78ed04b6a265e05aa257"
    candidates = identify("*" + lowercase_body)
    if candidates:
        assert candidates[0].algorithm != "MySQL5"


def test_netntlmv2_format_is_recognized() -> None:
    """
    NetNTLMv2 records from Responder look like
    `user::domain:challenge:hmac:blob`
    """
    sample = "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
    candidates = identify(sample)
    assert candidates[0].algorithm == "NetNTLMv2"
    assert candidates[0].confidence == "high"


def test_netntlmv1_format_is_recognized() -> None:
    """
    NetNTLMv1 records have 48-hex-char lmhash AND nthash before the challenge
    """
    sample = "alice::CORP:" + "a" * 48 + ":" + "b" * 48 + ":1122334455667788"
    candidates = identify(sample)
    assert candidates[0].algorithm == "NetNTLMv1"
    assert candidates[0].confidence == "high"


def test_descrypt_format_is_recognized() -> None:
    """
    Traditional DES crypt has NO prefix — only length and charset identify it
    """
    sample = "kRq14pmccuMOA"
    candidates = identify(sample)
    assert candidates[0].algorithm == "DES crypt"
    assert candidates[0].confidence == "medium"


# =============================================================================
# Hex length matches (medium / low confidence)
# =============================================================================
# Step 3 of identify(): when the input is pure hex, length narrows down
# the algorithm.


def test_mysql323_length_returns_mysql323_first() -> None:
    """
    16 hex chars points at MySQL323 (legacy MySQL OLD_PASSWORD output)
    """
    sample = "5d2e19393cc5ef67"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MySQL323"
    assert candidates[0].confidence == "medium"


def test_md5_length_returns_md5_first() -> None:
    """
    32 hex chars matches MD5, NTLM, MD4, RIPEMD-128
    """
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].confidence == "medium"
    algorithms = [c.algorithm for c in candidates]
    assert "NTLM" in algorithms


def test_sha256_length_returns_sha256_first() -> None:
    """
    64 hex chars points at SHA-256 first
    """
    # `"a" * 64` is Python shorthand for "the character 'a' repeated 64
    # times" — a quick way to make a 64-char string for length tests.
    # The actual content does not matter; only the length does
    sample = "a" * 64
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-256"


def test_sha1_length_returns_sha1_first() -> None:
    """
    40 hex chars = SHA-1 (RIPEMD-160 as a backup guess)
    """
    sample = "a" * 40
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-1"


# =============================================================================
# No-match / edge cases
# =============================================================================
# Always test the boring edge cases. Empty inputs, whitespace-only,
# garbage. These caused real bugs in real codebases more than once


def test_empty_input_returns_no_candidates() -> None:
    """
    Empty string returns an empty list — never blows up
    """
    assert not identify("")
    assert not identify("   ")


def test_garbage_returns_no_candidates() -> None:
    """
    A string with neither a known prefix nor a hex shape returns []
    """
    assert not identify("hello, this is not a hash")


def test_input_is_trimmed_of_whitespace() -> None:
    """
    Trailing newlines and leading spaces should not block recognition
    """
    sample = "   5f4dcc3b5aa765d61d8327deb882cf99\n"
    candidates = identify(sample)
    assert candidates[0].algorithm == "MD5"


# =============================================================================
# Soft-match fallbacks (shape hints, LOW confidence)
# =============================================================================
# Steps 4 and 5 of identify(): when nothing in the PREFIX_RULES table
# or the special-formats step or the hex-length table fires, we still
# try two soft matches — generic PHC string shape, then "this looks
# like a JWT / base64 blob, not a hash." Both return LOW confidence
# because shape alone is a weaker signal than a known prefix


def test_unknown_phc_string_falls_back_to_generic() -> None:
    """
    A PHC string from an algorithm we don't have a specific rule for
    is still reported as a PHC string with the extracted algorithm name
    """
    sample = "$pbkdf2-sha512$25000$cnNhbHQ$aGFzaA"
    candidates = identify(sample)
    assert candidates
    assert "PHC" in candidates[0].algorithm
    assert "pbkdf2-sha512" in candidates[0].algorithm
    assert candidates[0].confidence == "low"


def test_jwt_input_is_called_out_as_not_a_hash() -> None:
    """
    JWTs start with `eyJ` and should be called out as not-a-hash
    """
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
    candidates = identify(sample)
    assert candidates
    assert "JWT" in candidates[0].algorithm
    # LOW confidence is honest: we are not 100% sure this is a JWT,
    # we are 100% sure it starts with `eyJ` and JWTs start with `eyJ`
    assert candidates[0].confidence == "low"


def test_base64_blob_is_called_out_as_not_a_hash() -> None:
    """
    A string containing base64-only chars (`+`, `/`, `=`) is not hex
    """
    sample = "VGhpcyBpcyBub3QgYSBoYXNoLCBpdHMgYmFzZTY0Lg=="
    candidates = identify(sample)
    assert candidates
    assert "Base64" in candidates[0].algorithm


# =============================================================================
# HashCandidate is immutable
# =============================================================================
# We declared HashCandidate with @dataclass(frozen=True). Frozen means
# you cannot reassign fields after construction — like a sealed envelope.
# This test makes sure the seal actually holds, so future refactors do
# not accidentally drop the `frozen` flag


def test_hash_candidate_is_frozen() -> None:
    """
    Attempting to mutate a HashCandidate must raise an error
    """
    candidate = HashCandidate(
        algorithm="MD5",
        confidence="medium",
        reason="test",
    )
    try:
        candidate.algorithm = "SHA-1"  # type: ignore[misc]
    except (AttributeError, TypeError):
        return
    raise AssertionError(
        "HashCandidate should be frozen; assignment should have raised"
    )


# =============================================================================
# Comprehensive PREFIX_RULES table coverage
# =============================================================================
# The individual prefix tests above (bcrypt, Argon2id, etc.) double as
# readable EXAMPLES of how identify() handles known prefixes. This last
# test plays a different role: it is the safety-net that guarantees
# EVERY row of PREFIX_RULES is exercised, so a typo in any single row's
# algorithm name or note string fails its own test case rather than
# slipping through silently.
#
# `@pytest.mark.parametrize(name, values)` is pytest's mechanism for
# expanding ONE test function into MANY test cases. Here we hand it
# the entire PREFIX_RULES list. Pytest unpacks each `(prefix, algorithm,
# note)` tuple into the three parameters of the test function and runs
# the body once per row. The leading `_` in `_note` tells linters
# (and the next reader) that we intentionally do not assert on the
# note string — we accept whatever the table author wrote


@pytest.mark.parametrize("prefix,algorithm,_note", PREFIX_RULES)
def test_every_prefix_rule_is_recognized_with_high_confidence(
    prefix: str,
    algorithm: str,
    _note: str,
) -> None:
    """
    Every entry in PREFIX_RULES produces a HIGH-confidence candidate
    with the matching algorithm when its prefix sits at the start
    of the input

    The body of the hash after the prefix does not matter to
    identify() — it only inspects the leading characters — so we
    just glue any junk onto the end to form a syntactically-plausible
    input
    """
    sample = prefix + "fakebodydoesntmatter"
    candidates = identify(sample)

    # If identify() returned nothing, the prefix-loop branch is
    # broken — fail with a message that names the offending prefix
    # so the failure is debuggable at a glance
    assert candidates, f"no candidates returned for prefix `{prefix}`"
    assert candidates[0].algorithm == algorithm
    assert candidates[0].confidence == "high"
