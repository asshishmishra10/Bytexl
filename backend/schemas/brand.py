"""
Brand Profile Pydantic Schemas & Validators — AegisShield
==========================================================
Validates Brand Digital Twin onboarding per Hackathon Rubric (15%):
- Legitimate company name
- Handles validation (starts with @, alphanumeric, underscores)
- App ID / Package Name validation (reverse-DNS format: com.company.app)
- Official developers and publishers list
- Allowlisted affiliate/fan assets
"""

import re
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict


PACKAGE_NAME_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$"
)
HANDLE_REGEX = re.compile(r"^@[A-Za-z0-9_.]+$")


class BrandBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=150, description="Company / Brand Name")
    official_domains: Optional[List[str]] = Field(default_factory=list, description="Official domain names")
    handles: List[str] = Field(default_factory=list, description="Official verified social media handles")
    app_ids: List[str] = Field(default_factory=list, description="Official Android package names / app IDs")
    developers: List[str] = Field(default_factory=list, description="Official developer or publisher entities")
    logo_hash: Optional[str] = Field(None, description="Perceptual hash or identifier of official brand logo")
    official_app_description: Optional[str] = Field(None, description="Official app description used as TF-IDF ground-truth baseline")
    allowlist: Optional[List[str]] = Field(default_factory=list, description="Allowlisted partner, fan or community assets")
    exec_names: Optional[List[str]] = Field(default_factory=list, description="Key executive names for impersonation defense")

    @field_validator("handles")
    @classmethod
    def validate_and_normalize_handles(cls, v: List[str]) -> List[str]:
        cleaned = []
        for handle in v:
            h = handle.strip()
            if not h:
                continue
            if not h.startswith("@"):
                h = "@" + h
            if not HANDLE_REGEX.match(h):
                raise ValueError(
                    f"Invalid social handle format: '{handle}'. Must contain only alphanumeric characters, dots, or underscores."
                )
            cleaned.append(h.lower())
        return cleaned

    @field_validator("app_ids")
    @classmethod
    def validate_app_ids(cls, v: List[str]) -> List[str]:
        cleaned = []
        for app_id in v:
            pkg = app_id.strip()
            if not pkg:
                continue
            if not PACKAGE_NAME_REGEX.match(pkg):
                raise ValueError(
                    f"Invalid Android package name: '{pkg}'. Must follow reverse-DNS format (e.g. 'com.example.bank')."
                )
            cleaned.append(pkg.lower())
        return cleaned


class BrandCreate(BrandBase):
    pass


class BrandResponse(BrandBase):
    id: int
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

