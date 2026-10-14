"""
SQLAlchemy ORM Models — AegisShield Data Model
================================================
Production core models mapped to the Challenge 03 Evaluation Rubric:
- users: SOC analysts and reviewers
- brands: Brand Digital Twin assets (domains, handles, app IDs, developers, logo pHash, official app description)
- assets: Target candidate entities (handles, package names, etc.)
- detections: Corroborated threat detection records with component scores and reason codes
- cases: Investigation cases for Tier 1 and Tier 2 threats
- case_notes: Analyst investigation commentary
- audit_events: Immutable audit log of status transitions
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime,
    ForeignKey, JSON,
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    role = Column(String(50), nullable=False, default="analyst")  # analyst | reviewer | manager | admin
    password_hash = Column(String(255), nullable=False)


class Brand(Base):
    __tablename__ = "brands"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    official_domains = Column(JSON)                 # list of strings
    handles = Column(JSON)                           # social handles
    app_ids = Column(JSON)                           # package names
    developers = Column(JSON)                        # developer names
    logo_hash = Column(String(128))                  # 16-character 64-bit pHash
    official_app_description = Column(Text, nullable=True) # Unified ground-truth description for TF-IDF
    embeddings_ref = Column(String(500))             # path or key for stored embeddings
    exec_names = Column(JSON)
    allowlist = Column(JSON)                         # parody / fan / partner domains & handles
    created_at = Column(DateTime, default=datetime.utcnow)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    brand_id = Column(Integer, ForeignKey("brands.id"))
    type = Column(String(50))                        # url | profile | app | domain
    value = Column(Text, nullable=False)
    source = Column(String(100))
    provenance = Column(String(50))                  # synthetic | seeded | public | live
    first_seen = Column(DateTime, default=datetime.utcnow)

    brand = relationship("Brand", backref="assets")


class Detection(Base):
    __tablename__ = "detections"
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    component_scores_json = Column(JSON)             # {identity, visual, semantic, link, context, correlation}
    model_score = Column(Float)
    rule_score = Column(Float)
    final_score = Column(Float)
    tier = Column(Integer)                           # 0=Observe, 1=Review, 2=Escalate
    reason_codes_json = Column(JSON)
    shap_json = Column(JSON)
    model_version = Column(String(50))
    rule_version = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", backref="detections")


class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_id = Column(Integer, ForeignKey("detections.id"))
    status = Column(String(50), default="open")      # open | reviewing | escalated | closed
    priority = Column(String(20), default="medium")
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    detection = relationship("Detection", backref="cases")
    assignee = relationship("User", backref="assigned_cases")


class CaseNote(Base):
    __tablename__ = "case_notes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    text = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(120))
    role = Column(String(50))
    action = Column(String(100))
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    previous_state = Column(String(50))
    new_state = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
