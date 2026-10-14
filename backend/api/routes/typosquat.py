"""
Domain Typosquatting API — AegisShield
=======================================
Generates look-alike domain permutations targeting enterprise brands:
- Homoglyphs / IDN Punycode
- Omissions & Transpositions
- Hyphenation & Trust Keyword Deception
- TLD Swaps
Checks active DNS resolution (A and MX records) with bounded timeouts.
"""

import asyncio
from typing import Optional
from fastapi import APIRouter, Query

from services.typosquat.generator import generate_lookalikes, resolve_domain_dns
from services.enrichment.rdap import lookup_rdap_domain_age
from services.enrichment.certificates import lookup_crtsh_certificates
from services.enrichment.abuseipdb import check_ip_reputation
from services.enrichment.safebrowsing import check_google_safe_browsing
from services.enrichment.alienvault import check_alienvault_domain
from services.enrichment.virustotal import check_virustotal_domain

router = APIRouter()


@router.get("/typosquat/{domain}")
async def check_typosquats(
    domain: str,
    check_dns: bool = Query(True, description="Resolve active A and MX records via DNS"),
    check_rdap: bool = Query(True, description="Check domain registration age via tokenless ICANN RDAP"),
    check_certs: bool = Query(True, description="Check SSL/TLS Certificate Transparency logs via crt.sh"),
    check_threat_intel: bool = Query(True, description="Corroborate active hosts via AbuseIPDB, Safe Browsing, AlienVault, and VirusTotal"),
    limit: int = Query(25, ge=5, le=50, description="Maximum number of candidates to evaluate"),
):
    """
    Generate algorithmic look-alike domains and check active infrastructure,
    incorporating live tokenless ICANN RDAP domain age, crt.sh Certificate Transparency logs,
    and multi-feed Threat Intelligence (AbuseIPDB, Google Safe Browsing, AlienVault OTX, VirusTotal).
    """
    clean_domain = domain.strip().lower()
    raw_candidates = generate_lookalikes(clean_domain, max_candidates=limit)

    results = []
    active_count = 0
    mail_capable_count = 0
    newly_registered_count = 0
    active_cert_count = 0
    threat_intel_matches = 0

    # 1. Resolve DNS records concurrently
    if check_dns and raw_candidates:
        dns_tasks = [
            asyncio.to_thread(resolve_domain_dns, cand["domain"], 0.25)
            for cand in raw_candidates
        ]
        dns_infos = await asyncio.gather(*dns_tasks, return_exceptions=True)
    else:
        dns_infos = [{"resolved": False, "ip": None, "has_mx": False} for _ in raw_candidates]

    # 2. Enrich active/resolving candidates with RDAP, crt.sh, and Keyed Threat Feeds
    active_indices = [
        i for i, d in enumerate(dns_infos)
        if isinstance(d, dict) and d.get("resolved")
    ]
    # If fewer than 3 resolved, also inspect the top 3 highest-base-score candidates
    if len(active_indices) < 3:
        for idx in range(min(3, len(raw_candidates))):
            if idx not in active_indices:
                active_indices.append(idx)

    rdap_results = {}
    cert_results = {}
    abuseip_results = {}
    otx_results = {}
    vt_results = {}

    if check_rdap and active_indices:
        rdap_tasks = [
            asyncio.to_thread(lookup_rdap_domain_age, raw_candidates[idx]["domain"], 0.8)
            for idx in active_indices
        ]
        rdap_outs = await asyncio.gather(*rdap_tasks, return_exceptions=True)
        for idx, out in zip(active_indices, rdap_outs):
            if isinstance(out, dict):
                rdap_results[idx] = out

    if check_certs and active_indices:
        cert_tasks = [
            asyncio.to_thread(lookup_crtsh_certificates, raw_candidates[idx]["domain"], 1.0)
            for idx in active_indices
        ]
        cert_outs = await asyncio.gather(*cert_tasks, return_exceptions=True)
        for idx, out in zip(active_indices, cert_outs):
            if isinstance(out, dict):
                cert_results[idx] = out

    # Check Safe Browsing for all active candidate domains in one batch
    safe_browsing_matches = set()
    if check_threat_intel and active_indices:
        domains_to_check = [raw_candidates[idx]["domain"] for idx in active_indices]
        try:
            sb_res = await asyncio.to_thread(check_google_safe_browsing, domains_to_check, 1.2)
            if sb_res.get("blacklisted"):
                for m in sb_res.get("matches", []):
                    u = m.get("threat", {}).get("url", "")
                    for idx in active_indices:
                        if raw_candidates[idx]["domain"] in u:
                            safe_browsing_matches.add(idx)
        except Exception:
            pass

        # Query AbuseIPDB for resolved IPs concurrently
        ip_tasks = []
        ip_indices = []
        for idx in active_indices:
            dns_entry = dns_infos[idx] if idx < len(dns_infos) else None
            if isinstance(dns_entry, dict) and dns_entry.get("ip"):
                ip_indices.append(idx)
                ip_tasks.append(asyncio.to_thread(check_ip_reputation, dns_entry["ip"], 1.0))

        if ip_tasks:
            ip_outs = await asyncio.gather(*ip_tasks, return_exceptions=True)
            for idx, out in zip(ip_indices, ip_outs):
                if isinstance(out, dict) and out.get("checked"):
                    abuseip_results[idx] = out

        # Query AlienVault OTX and VirusTotal for top 2 active threats
        top_candidates = active_indices[:2]
        if top_candidates:
            otx_tasks = [
                asyncio.to_thread(check_alienvault_domain, raw_candidates[idx]["domain"], 1.0)
                for idx in top_candidates
            ]
            vt_tasks = [
                asyncio.to_thread(check_virustotal_domain, raw_candidates[idx]["domain"], 1.0)
                for idx in top_candidates
            ]
            otx_outs, vt_outs = await asyncio.gather(
                asyncio.gather(*otx_tasks, return_exceptions=True),
                asyncio.gather(*vt_tasks, return_exceptions=True),
            )
            for idx, out in zip(top_candidates, otx_outs):
                if isinstance(out, dict) and out.get("checked"):
                    otx_results[idx] = out
            for idx, out in zip(top_candidates, vt_outs):
                if isinstance(out, dict) and out.get("checked"):
                    vt_results[idx] = out

    # 3. Fuse DNS, RDAP, CT Logs, and Threat Feeds into final threat scoring
    for i, cand in enumerate(raw_candidates):
        cand_domain = cand["domain"]
        dns_info = dns_infos[i]
        if isinstance(dns_info, Exception) or not isinstance(dns_info, dict):
            dns_info = {"resolved": False, "ip": None, "has_mx": False}

        base_score = cand["base_score"]
        final_score = base_score
        reason_codes = [cand["mutation_type"]]

        if dns_info.get("resolved"):
            final_score += 25.0
            active_count += 1
            reason_codes.append("ACTIVE_A_RECORD_RESOLVED")

        if dns_info.get("has_mx"):
            final_score += 15.0
            mail_capable_count += 1
            reason_codes.append("ACTIVE_MAIL_SERVER_EXISTS")

        # Evaluate tokenless RDAP domain age
        rdap_info = rdap_results.get(i, {})
        age_days = rdap_info.get("age_days")
        if rdap_info.get("is_newly_registered"):
            final_score += 35.0
            newly_registered_count += 1
            reason_codes.append("NEWLY_REGISTERED_DOMAIN_RISK")
        elif rdap_info.get("is_suspicious_age"):
            final_score += 20.0
            reason_codes.append("SUSPICIOUS_DOMAIN_AGE")

        # Evaluate tokenless crt.sh Certificate Transparency logs
        cert_info = cert_results.get(i, {})
        has_tls = cert_info.get("has_tls_cert", False)
        if has_tls:
            final_score += 15.0
            active_cert_count += 1
            reason_codes.append("ACTIVE_TLS_CERTIFICATE_ISSUED")

        # Evaluate AbuseIPDB
        ip_intel = abuseip_results.get(i)
        if ip_intel and ip_intel.get("is_malicious"):
            final_score += 25.0
            threat_intel_matches += 1
            reason_codes.append("MALICIOUS_HOSTING_IP")

        # Evaluate Google Safe Browsing
        if i in safe_browsing_matches:
            final_score = max(final_score, 98.0)
            threat_intel_matches += 1
            reason_codes.append("GOOGLE_SAFE_BROWSING_BLACKLISTED")

        # Evaluate AlienVault OTX & VirusTotal
        otx_info = otx_results.get(i)
        if otx_info and otx_info.get("is_threat"):
            final_score += 20.0
            threat_intel_matches += 1
            reason_codes.append("ALIENVAULT_PULSE_MATCH")

        vt_info = vt_results.get(i)
        if vt_info and vt_info.get("is_flagged"):
            final_score += 25.0
            threat_intel_matches += 1
            reason_codes.append("VIRUSTOTAL_MALICIOUS_CONSENSUS")

        final_score = min(round(final_score, 1), 100.0)
        tier = 2 if final_score >= 75.0 else (1 if final_score >= 40.0 else 0)

        results.append({
            "domain": cand_domain,
            "mutation_type": cand["mutation_type"],
            "threat_score": final_score,
            "tier": tier,
            "tier_label": "Escalate (Critical)" if tier == 2 else ("Review (Suspicious)" if tier == 1 else "Observe (Benign)"),
            "resolved": bool(dns_info.get("resolved")),
            "ip_address": dns_info.get("ip"),
            "has_mx": bool(dns_info.get("has_mx")),
            "domain_age_days": age_days,
            "registration_date": rdap_info.get("registration_date"),
            "has_tls_cert": has_tls,
            "cert_issuer": cert_info.get("latest_issuer"),
            "abuse_score": ip_intel.get("abuse_score") if ip_intel else None,
            "isp": ip_intel.get("isp") if ip_intel else None,
            "reason_codes": reason_codes,
        })

    # Sort results with active threats and highest scores first
    results.sort(key=lambda x: (x["resolved"], x["threat_score"]), reverse=True)

    return {
        "status": "success",
        "target_domain": clean_domain,
        "total_generated": len(results),
        "active_infrastructure_count": active_count,
        "mail_capable_count": mail_capable_count,
        "newly_registered_count": newly_registered_count,
        "active_cert_count": active_cert_count,
        "threat_intel_corroborated_count": threat_intel_matches,
        "lookalikes": results,
    }

