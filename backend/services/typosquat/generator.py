"""
Domain Typosquatting & Look-Alike Generator — AegisShield
==========================================================
Generates high-risk domain mutations targeting corporate brands and resolves
active DNS infrastructure (A and MX records) with bounded timeouts.
"""

import logging
from typing import List, Dict, Any, Tuple
import tldextract

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None

logger = logging.getLogger(__name__)

# Common homoglyph mappings (Latin -> Cyrillic/Greek look-alikes)
HOMOGLYPH_MAP = {
    "a": "а",  # Cyrillic small letter a (U+0430)
    "c": "с",  # Cyrillic small letter es (U+0441)
    "e": "е",  # Cyrillic small letter ie (U+0435)
    "i": "і",  # Cyrillic small letter byelorussian-ukrainian i (U+0456)
    "o": "о",  # Cyrillic small letter o (U+043E)
    "p": "р",  # Cyrillic small letter er (U+0440)
    "s": "ѕ",  # Cyrillic small letter dze (U+0455)
    "x": "х",  # Cyrillic small letter ha (U+0445)
    "y": "у",  # Cyrillic small letter u (U+0443)
}

COMMON_TLDS = ["net", "org", "co", "io", "xyz", "info", "top", "online", "app"]
DECEPTIVE_KEYWORDS = ["login", "secure", "verify", "support", "help", "auth", "portal"]


def extract_domain_parts(domain_str: str) -> Tuple[str, str]:
    """Extracts base name and suffix using tldextract."""
    ext = tldextract.extract(domain_str)
    domain_name = ext.domain
    suffix = ext.suffix or "com"
    return domain_name, suffix


def generate_lookalikes(domain_str: str, max_candidates: int = 40) -> List[Dict[str, str]]:
    """
    Generates algorithmic domain mutations across 5 key categories:
    1. Homoglyphs (Punycode / IDN)
    2. Omissions (Dropped characters)
    3. Transpositions (Swapped adjacent characters)
    4. Hyphenations & Keyword Append (Deceptive trust tokens)
    5. TLD Swapping (Alternate top-level domains)
    """
    domain_name, suffix = extract_domain_parts(domain_str)
    if not domain_name:
        return []

    candidates: List[Dict[str, str]] = []
    seen = set([f"{domain_name}.{suffix}".lower()])

    def _add(cand_domain: str, mutation_type: str, severity_base: float):
        clean = cand_domain.lower()
        if clean not in seen and len(candidates) < max_candidates:
            seen.add(clean)
            candidates.append({
                "domain": clean,
                "mutation_type": mutation_type,
                "base_score": severity_base,
            })

    # 1. Homoglyphs (IDN Punycode)
    for char, glyph in HOMOGLYPH_MAP.items():
        if char in domain_name:
            mutated = domain_name.replace(char, glyph, 1)
            # Encode as punycode
            try:
                puny = mutated.encode("idna").decode("ascii")
                _add(f"{puny}.{suffix}", "HOMOGLYPH_IDN", 65.0)
            except Exception:
                pass

    # 2. Character Omission
    for i in range(len(domain_name)):
        omitted = domain_name[:i] + domain_name[i+1:]
        if len(omitted) >= 3:
            _add(f"{omitted}.{suffix}", "CHARACTER_OMISSION", 45.0)

    # 3. Character Transposition
    for i in range(len(domain_name) - 1):
        transposed = (
            domain_name[:i]
            + domain_name[i+1]
            + domain_name[i]
            + domain_name[i+2:]
        )
        _add(f"{transposed}.{suffix}", "CHARACTER_TRANSPOSITION", 45.0)

    # 4. Hyphenation & Trust Keywords
    if len(domain_name) >= 4:
        split_pt = len(domain_name) // 2
        _add(f"{domain_name[:split_pt]}-{domain_name[split_pt:]}.{suffix}", "HYPHEN_INSERTION", 50.0)
    for kw in DECEPTIVE_KEYWORDS[:4]:
        _add(f"{domain_name}-{kw}.{suffix}", "DECEPTIVE_KEYWORD", 60.0)
        _add(f"{kw}-{domain_name}.{suffix}", "DECEPTIVE_KEYWORD", 60.0)

    # 5. TLD Swapping
    for tld in COMMON_TLDS:
        if tld != suffix:
            _add(f"{domain_name}.{tld}", "TLD_SWAP", 40.0)

    return candidates


def resolve_domain_dns(domain_name: str, timeout: float = 0.3) -> Dict[str, Any]:
    """
    Checks active DNS A-records (web servers) and MX-records (phishing mail servers).
    Strictly bounded by timeout (default 300ms) to prevent slow network hanging.
    """
    if dns is None:
        return {"resolved": False, "ip": None, "has_mx": False}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    resolved_ip = None
    has_mx = False

    # Check A record
    try:
        answers = resolver.resolve(domain_name, "A")
        if answers:
            resolved_ip = str(answers[0])
    except Exception:
        resolved_ip = None

    # Check MX record
    try:
        mx_answers = resolver.resolve(domain_name, "MX")
        if mx_answers:
            has_mx = True
    except Exception:
        has_mx = False

    return {
        "resolved": bool(resolved_ip),
        "ip": resolved_ip,
        "has_mx": has_mx,
    }
