"""
Perceptual Image Hash Utilities — Aegis
=======================================
Zero-dependency 64-bit difference hashing (dHash) using Pillow.
Eliminates heavy scipy / imagehash dependencies while maintaining
high accuracy for logo clone and visual tampering detection.
"""

from typing import Optional
from PIL import Image


def compute_image_hash(img: Image.Image) -> str:
    """Computes a 64-bit perceptual difference hash (16-character hex string)."""
    try:
        # Resize to 9x8 grayscale
        resized = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
        pixels = list(resized.getdata())
        diff = []
        for row in range(8):
            row_start = row * 9
            for col in range(8):
                diff.append("1" if pixels[row_start + col] > pixels[row_start + col + 1] else "0")
        decimal_val = int("".join(diff), 2)
        return f"{decimal_val:016x}"
    except Exception:
        return "0000000000000000"


def hamming_distance(hash_a: str, hash_b: str) -> int:
    """Computes bitwise Hamming distance between two 16-hex hashes [0-64]."""
    try:
        v1 = int(str(hash_a).strip(), 16)
        v2 = int(str(hash_b).strip(), 16)
        return bin(v1 ^ v2).count("1")
    except Exception:
        return 64


def logo_similarity(hash_a: Optional[str], hash_b: Optional[str]) -> float:
    """Returns visual similarity percentage [0.0 - 100.0]."""
    if not hash_a or not hash_b:
        return 0.0
    clean_a = str(hash_a).strip().lower()
    clean_b = str(hash_b).strip().lower()
    if clean_a == clean_b:
        return 100.0
    dist = hamming_distance(clean_a, clean_b)
    sim = max(0.0, (1.0 - (dist / 64.0)) * 100.0)
    return round(float(sim), 2)
