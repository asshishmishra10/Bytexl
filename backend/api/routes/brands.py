"""
Brand Digital Twin API Endpoints — AegisShield
================================================
Implements Brand Profile definition, validation, and storage per Hackathon Rubric (15%):
- POST /api/brands         — Onboard a verified brand with format validation
- GET  /api/brands         — List all onboarded brands
- GET  /api/brands/active  — Get the active brand profile guiding threat detection
- GET  /api/brands/{id}    — Retrieve a brand by ID
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.session import get_db
from db.models import Brand
from schemas.brand import BrandCreate, BrandResponse
from services.enrichment.logo_fetcher import fetch_clearbit_logo_hash

router = APIRouter()


@router.post("/brands", response_model=BrandResponse, status_code=status.HTTP_201_CREATED)
async def create_brand(brand_in: BrandCreate, db: Session = Depends(get_db)):
    """
    Onboard a Brand Digital Twin with legitimate enterprise assets.
    Validates handle and package formats, and auto-derives official logo pHash via tokenless Clearbit.
    """
    derived_logo_hash = brand_in.logo_hash
    if not derived_logo_hash and brand_in.official_domains:
        for domain in brand_in.official_domains:
            derived = fetch_clearbit_logo_hash(domain, timeout=1.2)
            if derived:
                derived_logo_hash = derived
                break

    # Check if a brand with this exact name already exists
    existing = db.query(Brand).filter(Brand.name.ilike(brand_in.name)).first()
    if existing:
        # Update existing brand assets safely
        if brand_in.official_domains:
            existing.official_domains = brand_in.official_domains
        if brand_in.handles:
            existing.handles = brand_in.handles
        if brand_in.app_ids:
            existing.app_ids = brand_in.app_ids
        if brand_in.developers:
            existing.developers = brand_in.developers
        if derived_logo_hash or brand_in.logo_hash:
            existing.logo_hash = derived_logo_hash or brand_in.logo_hash
        if brand_in.official_app_description:
            existing.official_app_description = brand_in.official_app_description
        if brand_in.allowlist:
            existing.allowlist = brand_in.allowlist
        if brand_in.exec_names:
            existing.exec_names = brand_in.exec_names
        db.commit()
        db.refresh(existing)
        return existing

    brand = Brand(
        name=brand_in.name,
        official_domains=brand_in.official_domains,
        handles=brand_in.handles,
        app_ids=brand_in.app_ids,
        developers=brand_in.developers,
        logo_hash=derived_logo_hash,
        official_app_description=brand_in.official_app_description,
        allowlist=brand_in.allowlist,
        exec_names=brand_in.exec_names,
    )
    db.add(brand)
    db.commit()
    db.refresh(brand)
    return brand


@router.get("/brands", response_model=List[BrandResponse])
async def list_brands(db: Session = Depends(get_db)):
    """List all onboarded Brand Digital Twins."""
    return db.query(Brand).order_by(Brand.id.asc()).all()


@router.get("/brands/active", response_model=BrandResponse)
async def get_active_brand(db: Session = Depends(get_db)):
    """Retrieve the primary active Brand Digital Twin used for detection."""
    brand = db.query(Brand).first()
    if not brand:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Brand Digital Twin has been onboarded yet. Please onboard via POST /api/brands."
        )
    return brand


@router.get("/brands/{brand_id}", response_model=BrandResponse)
async def get_brand(brand_id: int, db: Session = Depends(get_db)):
    """Retrieve a specific Brand Digital Twin by ID."""
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Brand with ID {brand_id} not found."
        )
    return brand


@router.get("/brands/{brand_id}/github")
async def monitor_brand_github(brand_id: int, db: Session = Depends(get_db)):
    """Search GitHub for repositories impersonating or referencing this brand using GITHUB_PAT."""
    from services.enrichment.github_monitor import search_github_brand_repos
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Brand with ID {brand_id} not found."
        )
    return search_github_brand_repos(brand.name)
