"""
Database Seeder — AegisShield
==============================
Seeds the SQLite database for live demo per Hackathon Rubric:
- 1 Verified Brand Digital Twin ("Apex Global Bank")
- 2 Analyst User Accounts
- 15 Social Profiles (Official exclusions, allowlist, look-alike bonus, scam bots)
- 4 Mobile Apps (Official banking app, clone, trojanized token, benign calculator)
- Computes REAL 16-hex imagehash.phash values from PNG logo files at seed time.
- Uses unified official_app_description ground-truth for TF-IDF.
- Generates Detection and Case entries ready for UI Dashboard display.

Run from backend directory:
    python db/seed.py
"""

import os
import sys
from pathlib import Path
from PIL import Image
import imagehash

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from db.session import engine, SessionLocal
from db.models import Base, User, Brand, Asset, Detection, Case, CaseNote, AuditEvent
from models.loader import predict_social_profile, predict_mobile_app
from models.explain import explain_social_prediction, explain_mobile_prediction
from services.rules.identity import evaluate_social_identity
from services.rules.apps import evaluate_app_store_signals
from services.fusion.engine import fuse_social_threat, fuse_app_threat

LOGO_DIR = BASE_DIR / "data" / "logos"
OFFICIAL_LOGO_PATH = LOGO_DIR / "apex_logo_official.png"
CLONE_LOGO_PATH = LOGO_DIR / "apex_logo_clone_perturbed.png"
CALC_LOGO_PATH = LOGO_DIR / "calc_icon.png"

def ensure_logo_files():
    """Ensure real logo PNGs exist in backend/data/logos/, generating them via Pillow if missing."""
    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    if not OFFICIAL_LOGO_PATH.exists() or not CLONE_LOGO_PATH.exists() or not CALC_LOGO_PATH.exists():
        from PIL import ImageDraw
        import numpy as np

        # 1. Official Logo (Navy background, gold/white shield)
        official = Image.new("RGB", (128, 128), color=(15, 34, 64))
        draw = ImageDraw.Draw(official)
        shield = [(64, 20), (105, 35), (100, 80), (64, 110), (28, 80), (23, 35)]
        draw.polygon(shield, fill=(212, 175, 55), outline=(255, 255, 255), width=2)
        draw.polygon([(64, 30), (95, 42), (90, 75), (64, 100), (38, 75), (33, 42)], fill=(20, 50, 95))
        draw.line([(64, 45), (48, 85)], fill=(255, 255, 255), width=4)
        draw.line([(64, 45), (80, 85)], fill=(255, 255, 255), width=4)
        draw.line([(54, 72), (74, 72)], fill=(255, 255, 255), width=3)
        official.save(OFFICIAL_LOGO_PATH)

        # 2. Perturbed Clone Logo (90.6% pHash similarity)
        clone = official.copy()
        arr = np.array(clone, dtype=np.int16)
        noise = np.random.RandomState(42).randint(-5, 6, arr.shape)
        arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
        clone = Image.fromarray(arr)
        draw_c = ImageDraw.Draw(clone)
        draw_c.rectangle([(10, 10), (16, 16)], fill=(212, 175, 55))
        clone.save(CLONE_LOGO_PATH)

        # 3. Calculator Logo (completely different hash)
        calc = Image.new("RGB", (128, 128), color=(255, 255, 255))
        draw_calc = ImageDraw.Draw(calc)
        for i in range(0, 128, 8):
            draw_calc.line([(0, i), (i, 0)], fill=(0, 120, 200), width=3)
            draw_calc.ellipse([(40, 40), (100, 100)], outline=(120, 50, 200), width=4)
        calc.save(CALC_LOGO_PATH)

ensure_logo_files()

OFFICIAL_LOGO_HASH = str(imagehash.phash(Image.open(OFFICIAL_LOGO_PATH)))
CLONE_LOGO_HASH = str(imagehash.phash(Image.open(CLONE_LOGO_PATH)))
CALC_LOGO_HASH = str(imagehash.phash(Image.open(CALC_LOGO_PATH)))

OFFICIAL_APP_DESC = "Official mobile banking application for Apex Global Bank. Manage accounts, transfer funds, pay bills, and view statements securely."

# Embedded Demo Brand Fixture
DEMO_BRAND = {
    "name": "Apex Global Bank",
    "official_domains": ["apexbank.com", "apexbank.net"],
    "handles": ["@apexbank", "@apex_support", "@apexbank_careers"],
    "app_ids": ["com.apexbank.mobile", "com.apexbank.securepass"],
    "developers": ["Apex Financial Group LLC", "Apex Bank Corporation"],
    "logo_hash": OFFICIAL_LOGO_HASH,
    "official_app_description": OFFICIAL_APP_DESC,
    "allowlist": ["@apex_fanclub", "@apex_community"],
    "exec_names": ["Arthur Vance", "Elena Rostova"]
}

# Embedded Social Profile Fixtures (Official exclusions, look-alike bonus, scam bots, hard negatives)
DEMO_PROFILES = [
    {
        "handle": "@apexbank",
        "name": "Apex Global Bank",
        "bio": "Official global banking account. Member FDIC. Equal Housing Lender.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 520, "followers_count": 680000, "following_count": 140, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_support",
        "name": "Apex Bank Help & Support",
        "bio": "Official 24/7 customer assistance. Verified support portal.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 180, "followers_count": 92000, "following_count": 45, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_fanclub",
        "name": "Apex Bank Customers Club",
        "bio": "Community fan page for financial literacy and banking tips.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 40, "followers_count": 1200, "following_count": 350, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_support_9912",
        "name": "Apex Bank Customer Care",
        "bio": "Instant KYC Verification & Account Reactivation. Send DM to restore your account.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 2, "followers_count": 14, "following_count": 680, "username_digits_ratio": 0.44
    },
    {
        "handle": "@apexbank_official_help",
        "name": "Apex Bank Online Desk",
        "bio": "Urgent Security Alert: All accounts must re-verify PAN & KYC today.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 4, "followers_count": 35, "following_count": 940, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apexb@nk_support",
        "name": "Apex B@nk Help",
        "bio": "Official support channel for quick loans and credit card activation.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 1, "followers_count": 8, "following_count": 410, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_bank_official",
        "name": "Apex Bank Financial",
        "bio": "DM us for unblocking ATM card and transaction dispute resolution.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 5, "followers_count": 62, "following_count": 780, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_claims_helpdesk",
        "name": "Apex Bank Claims Desk",
        "bio": "Official insurance and refund claims portal. Message for immediate refunds.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 3, "followers_count": 19, "following_count": 850, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apexbank_crypto",
        "name": "Apex Bank Crypto Rewards",
        "bio": "Earn 15% APY on Bitcoin deposits. Limited time promotional scheme.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 12, "followers_count": 140, "following_count": 320, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_global_care_24x7",
        "name": "Apex Global 24x7 Support",
        "bio": "Emergency contact point for blocked internet banking access.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 2, "followers_count": 9, "following_count": 600, "username_digits_ratio": 0.2
    },
    {
        "handle": "@john_doe_finance",
        "name": "John Doe Wealth Tips",
        "bio": "Daily budgeting tips and personal finance advice.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 85, "followers_count": 4500, "following_count": 310, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apex_logistics_cargo",
        "name": "Apex Cargo Movers",
        "bio": "Shipping, freight forwarding, and container transport services.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 140, "followers_count": 3200, "following_count": 400, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apextrading_bot",
        "name": "Apex Automated Bot",
        "bio": "Trading signals channel.",
        "is_private": 0, "has_profile_pic": 0, "posts_count": 0, "followers_count": 3, "following_count": 200, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apexbank_recovery_team",
        "name": "Apex Loan Settlement",
        "bio": "One-time loan settlement discount. Contact via Telegram.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 4, "followers_count": 28, "following_count": 550, "username_digits_ratio": 0.0
    },
    {
        "handle": "@apexbankk_help",
        "name": "Apex Bank Help Center",
        "bio": "24/7 Helpline. Follow and message your registered mobile number.",
        "is_private": 0, "has_profile_pic": 1, "posts_count": 1, "followers_count": 11, "following_count": 480, "username_digits_ratio": 0.0
    }
]

# Embedded Mobile App Fixtures
DEMO_APPS = [
    {
        "app_name": "Apex Bank Mobile",
        "package_name": "com.apexbank.mobile",
        "developer": "Apex Financial Group LLC",
        "description": OFFICIAL_APP_DESC,
        "logo_hash": OFFICIAL_LOGO_HASH,
        "permissions": ["INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE", "USE_FINGERPRINT", "USE_BIOMETRIC"]
    },
    {
        "app_name": "Apex Banking Pro",
        "package_name": "com.apexbank.fraud.apk",
        "developer": "Apex Quick Loans Ltd",
        "description": "Apex Bank fast mobile banking app with instant rewards and easy transactions.",
        "logo_hash": CLONE_LOGO_HASH,
        "permissions": ["SEND_SMS", "READ_PHONE_STATE", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW", "INTERNET"]
    },
    {
        "app_name": "Apex Mobile Banking Token",
        "package_name": "org.apex.security.token.fake",
        "developer": "ApexToken Softworks",
        "description": "Official OTP and security token generator for internet banking authentication.",
        "logo_hash": CLONE_LOGO_HASH,
        "permissions": ["RECEIVE_SMS", "READ_SMS", "INTERNET", "ACCESS_NETWORK_STATE"]
    },
    {
        "app_name": "Calculator Simple",
        "package_name": "com.tool.calculator",
        "developer": "Math Tools Free",
        "description": "Simple clean calculator for scientific, engineering and high school math homework.",
        "logo_hash": CALC_LOGO_HASH,
        "permissions": ["VIBRATE"]
    }
]


def seed_database():
    print("[+] Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # 1. Clean existing records for fresh demo state in correct FK order
        db.query(CaseNote).delete()
        db.query(AuditEvent).delete()
        db.query(Case).delete()
        db.query(Detection).delete()
        db.query(Asset).delete()
        db.query(Brand).delete()
        db.query(User).delete()
        db.commit()

        # 2. Seed Users
        print("[+] Seeding Analyst accounts...")
        analyst = User(
            name="Sarah Chen",
            email="sarah.chen@aegisshield.internal",
            role="analyst",
            password_hash="mock_hash_scrypt_9812"
        )
        lead = User(
            name="Marcus Vance",
            email="marcus.vance@aegisshield.internal",
            role="lead_reviewer",
            password_hash="mock_hash_scrypt_9813"
        )
        db.add_all([analyst, lead])
        db.commit()

        # 3. Seed Brand Digital Twin
        print(f"[+] Seeding Brand Digital Twin (Apex Global Bank)...")
        print(f"    • Official Logo pHash: {OFFICIAL_LOGO_HASH} (16 hex chars)")
        print(f"    • Perturbed Clone pHash: {CLONE_LOGO_HASH}")
        print(f"    • Calculator Icon pHash: {CALC_LOGO_HASH}")

        brand = Brand(
            name=DEMO_BRAND["name"],
            official_domains=DEMO_BRAND["official_domains"],
            handles=DEMO_BRAND["handles"],
            app_ids=DEMO_BRAND["app_ids"],
            developers=DEMO_BRAND["developers"],
            logo_hash=DEMO_BRAND["logo_hash"],
            official_app_description=DEMO_BRAND["official_app_description"],
            allowlist=DEMO_BRAND["allowlist"],
            exec_names=DEMO_BRAND["exec_names"],
        )
        db.add(brand)
        db.commit()
        db.refresh(brand)
        print(f"    -> Brand onboarded: '{brand.name}' (ID: {brand.id})")

        # 4. Seed Social Profiles
        print("\n[+] Seeding 15 Social Profiles (Evaluating Models & Look-alikes)...")
        seeded_social_results = []
        for p in DEMO_PROFILES:
            handle = p["handle"]
            name = p.get("name", handle)

            id_res = evaluate_social_identity(
                candidate_handle=handle,
                candidate_name=name,
                brand_name=brand.name,
                official_handles=brand.handles,
                allowlist=brand.allowlist
            )

            fullname_digits = sum(c.isdigit() for c in name) / len(name) if name else 0.0

            ml_features = {
                "profile pic": int(p.get("has_profile_pic", 1)),
                "nums/length username": float(p.get("username_digits_ratio", 0.0)),
                "fullname words": len(name.split()) if name else 1,
                "nums/length fullname": float(fullname_digits),
                "name==username": 1 if name.lower() == handle.lower() else 0,
                "description length": len(p.get("bio", "")),
                "external URL": 1 if "http" in p.get("bio", "") or "link" in p.get("bio", "") else 0,
                "private": int(p.get("is_private", 0)),
                "#posts": int(p.get("posts_count", 10)),
                "#followers": int(p.get("followers_count", 100)),
                "#follows": int(p.get("following_count", 100)),
            }
            ml_prob = predict_social_profile(ml_features)
            fused = fuse_social_threat(id_res, ml_prob)

            asset = Asset(
                brand_id=brand.id,
                type="profile",
                value=handle,
                source="instagram",
                provenance="seeded"
            )
            db.add(asset)
            db.flush()

            shap_dict = explain_social_prediction(ml_features)
            det = Detection(
                asset_id=asset.id,
                component_scores_json=fused["components"],
                model_score=round(ml_prob * 100.0, 1),
                rule_score=fused["components"]["identity"],
                final_score=fused["score"],
                tier=fused["tier"],
                reason_codes_json=fused["reason_codes"],
                shap_json=shap_dict,
                model_version="social_xgb_v1.0",
                rule_version="identity_rules_v1.0"
            )
            db.add(det)
            db.flush()

            if fused["tier"] >= 1:
                case = Case(
                    detection_id=det.id,
                    status="open",
                    priority="high" if fused["tier"] == 2 else "medium",
                    assignee_id=analyst.id
                )
                db.add(case)
                db.flush()

                audit = AuditEvent(
                    actor="system",
                    role="system_seed",
                    action=f"Seeded investigation case {case.id} for Tier {fused['tier']} profile threat",
                    case_id=case.id,
                    previous_state="none",
                    new_state="open"
                )
                db.add(audit)

            seeded_social_results.append({
                "handle": handle,
                "score": fused["score"],
                "tier": fused["tier"],
                "tier_label": fused["tier_label"],
                "reason_codes": fused["reason_codes"]
            })
            print(f"    • {handle:<28} | Score: {fused['score']:>4.1f} | Tier {fused['tier']} ({fused['tier_label']})")

        # 5. Seed Mobile Apps
        print("\n[+] Seeding 4 Mobile Apps (Evaluating 4 Signals & Rogue Permissions)...")
        seeded_app_results = []
        for a in DEMO_APPS:
            app_name = a["app_name"]
            pkg = a["package_name"]
            dev = a["developer"]
            desc = a.get("description", "")
            logo = a.get("logo_hash")
            perms = a.get("permissions", [])

            app_res = evaluate_app_store_signals(
                candidate_app_name=app_name,
                candidate_package_name=pkg,
                candidate_developer=dev,
                candidate_description=desc,
                candidate_logo_hash=logo,
                brand_name=brand.name,
                official_app_ids=brand.app_ids,
                official_developers=brand.developers,
                official_description=brand.official_app_description,
                official_logo_hash=brand.logo_hash
            )

            ml_prob = predict_mobile_app(perms)
            fused = fuse_app_threat(app_res, ml_prob)

            asset = Asset(
                brand_id=brand.id,
                type="app",
                value=pkg,
                source="google_play",
                provenance="seeded"
            )
            db.add(asset)
            db.flush()

            shap_dict = explain_mobile_prediction(perms)
            det = Detection(
                asset_id=asset.id,
                component_scores_json=fused["components"],
                model_score=round(ml_prob * 100.0, 1),
                rule_score=fused["components"]["branding"],
                final_score=fused["score"],
                tier=fused["tier"],
                reason_codes_json=fused["reason_codes"],
                shap_json=shap_dict,
                model_version="mobile_xgb_v1.0",
                rule_version="app_store_rules_v1.0"
            )
            db.add(det)
            db.flush()

            if fused["tier"] >= 1:
                case = Case(
                    detection_id=det.id,
                    status="open",
                    priority="high" if fused["tier"] == 2 else "medium",
                    assignee_id=lead.id
                )
                db.add(case)
                db.flush()

                audit = AuditEvent(
                    actor="system",
                    role="system_seed",
                    action=f"Seeded investigation case {case.id} for Tier {fused['tier']} app threat",
                    case_id=case.id,
                    previous_state="none",
                    new_state="open"
                )
                db.add(audit)

            seeded_app_results.append({
                "app_name": app_name,
                "pkg": pkg,
                "score": fused["score"],
                "tier": fused["tier"],
                "tier_label": fused["tier_label"],
                "reason_codes": fused["reason_codes"]
            })
            print(f"    • {pkg:<32} | Score: {fused['score']:>4.1f} | Tier {fused['tier']} ({fused['tier_label']})")

        db.commit()

        # 6. Verify Acceptance Assertions (Part 5 Item 21)
        print("\n" + "=" * 60)
        print("[+] Verifying Acceptance Criteria Assertions...")

        # @apexbank, @apex_support, com.apexbank.mobile -> Tier 0 OFFICIAL
        soc_map = {r["handle"]: r for r in seeded_social_results}
        app_map = {r["pkg"]: r for r in seeded_app_results}

        assert soc_map["@apexbank"]["tier"] == 0 and "OFFICIAL_ACCOUNT_VERIFIED" in soc_map["@apexbank"]["reason_codes"]
        assert soc_map["@apex_support"]["tier"] == 0 and "OFFICIAL_ACCOUNT_VERIFIED" in soc_map["@apex_support"]["reason_codes"]
        assert app_map["com.apexbank.mobile"]["tier"] == 0 and "OFFICIAL_APP_VERIFIED" in app_map["com.apexbank.mobile"]["reason_codes"]
        print("    [OK] Official accounts & apps held at Tier 0 (OFFICIAL_*_VERIFIED).")

        # @apex_fanclub -> Tier 0 allowlisted
        assert soc_map["@apex_fanclub"]["tier"] == 0 and "ALLOWLISTED_PARTNER_OR_FAN" in soc_map["@apex_fanclub"]["reason_codes"]
        print("    [OK] Allowlisted fan club held at Tier 0 (ALLOWLISTED_PARTNER_OR_FAN).")

        # >=3 scam profiles Tier >= 1 with SUSPICIOUS_PROFILE_BEHAVIOR
        scam_bots = [r for r in seeded_social_results if "SUSPICIOUS_PROFILE_BEHAVIOR" in r["reason_codes"] and r["tier"] >= 1]
        assert len(scam_bots) >= 3, f"Expected >=3 scam profiles, got {len(scam_bots)}"
        print(f"    [OK] {len(scam_bots)} scam profiles flagged with SUSPICIOUS_PROFILE_BEHAVIOR (Tier >= 1).")

        # >=2 look-alike profiles carrying typed LOOKALIKE_* codes
        typed_lookalikes = [
            r for r in seeded_social_results
            if any(c in r["reason_codes"] for c in ["LOOKALIKE_CHAR_SWAP", "LOOKALIKE_ADDED_WORD", "LOOKALIKE_SPACING_CHANGE"])
        ]
        assert len(typed_lookalikes) >= 2, f"Expected >=2 typed look-alikes, got {len(typed_lookalikes)}"
        print(f"    [OK] {len(typed_lookalikes)} look-alike profiles identified with typed LOOKALIKE_* codes.")

        # Hard negatives: @apex_logistics_cargo + @john_doe_finance -> Tier 0
        assert soc_map["@apex_logistics_cargo"]["tier"] == 0
        assert soc_map["@john_doe_finance"]["tier"] == 0
        print("    [OK] Hard negatives (@apex_logistics_cargo, @john_doe_finance) held at Tier 0.")

        # Apex Banking Pro (clone) -> LOGO_IMPERSONATION + UNAUTHORIZED_PUBLISHER
        clone_res = app_map["com.apexbank.fraud.apk"]
        assert "LOGO_IMPERSONATION" in clone_res["reason_codes"]
        assert "UNAUTHORIZED_PUBLISHER" in clone_res["reason_codes"]
        print(f"    [OK] Clone app flagged with LOGO_IMPERSONATION and UNAUTHORIZED_PUBLISHER (Score: {clone_res['score']:.1f}, Tier {clone_res['tier']}).")

        # Calculator -> Tier 0
        calc_res = app_map["com.tool.calculator"]
        assert calc_res["tier"] == 0
        print("    [OK] Benign Calculator held at Tier 0.")

        total_dets = db.query(Detection).count()
        total_cases = db.query(Case).count()
        print("=" * 60)
        print(f"[OK] Seeding & Verification 100% Successful! {total_dets} Detections, {total_cases} Investigation Cases.")
        print("=" * 60 + "\n")

    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
