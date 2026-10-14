"""
AegisShield Backend — FastAPI Application Entry Point
=====================================================
Multi-signal brand protection and impersonation detection platform.
Hosts identity evaluation, behavioral models, multi-feed threat
intelligence enrichment, Tree SHAP explainability, SOC case management,
and real-time WebSocket alert streaming.
"""

import sys
import os
from pathlib import Path

# Ensure backend root is always at index 0 of sys.path for serverless runtimes
BASE_DIR = str(Path(__file__).resolve().parent)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mangum import Mangum
import uvicorn

from api.routes import (
    brands,
    analyze,
    detections,
    cases,
    campaigns,
    feedback,
    typosquat,
    blocklist,
    websocket_feed,
)
from db.session import engine, SessionLocal
from db.models import Base, Brand

# --------------- App Setup ---------------
app = FastAPI(
    title="Aegis Digital Risk Protection API",
    version="1.0.0",
    description="Aegis — Social & App Impersonation Monitoring Engine",
)

# Robust CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------- Database Initialization & Auto-Seed ---------------
try:
    Base.metadata.create_all(bind=engine)
    # Ensure default Brand exists if running in fresh serverless /tmp
    with SessionLocal() as db:
        if not db.query(Brand).first():
            default_brand = Brand(
                name="Apex Global Bank",
                official_domains=["apexbank.com", "apexbank.net"],
                handles=["@apexbank", "@apex_support", "@apexbank_careers"],
                app_ids=["com.apexbank.mobile", "com.apexbank.securepass"],
                developers=["Apex Global Financial Services Ltd", "Apex Bank Corp"],
                official_app_description="Official Apex Global Bank mobile banking application for secure retail account access.",
                allowlist=["apex-partner-portal.com", "secure-apexpay.com"],
                exec_names=["John C. Miller", "Sarah Jenkins", "Robert Sterling"],
            )
            db.add(default_brand)
            db.commit()
except Exception as e:
    print(f"[Aegis] Warning during table initialization or auto-seeding: {e}")

# --------------- Register Routers ---------------
app.include_router(brands.router, prefix="/api", tags=["Brands"])
app.include_router(analyze.router, prefix="/api", tags=["Analyzer"])
app.include_router(detections.router, prefix="/api", tags=["Detections"])
app.include_router(cases.router, prefix="/api", tags=["Cases"])
app.include_router(campaigns.router, prefix="/api", tags=["Campaigns"])
app.include_router(feedback.router, prefix="/api", tags=["Feedback"])
app.include_router(typosquat.router, prefix="/api", tags=["Typosquat"])
app.include_router(blocklist.router, prefix="/api", tags=["Blocklist"])
app.include_router(websocket_feed.router, tags=["WebSocket"])


@app.get("/")
async def root():
    return {
        "service": "Aegis Digital Risk Intelligence API",
        "status": "operational",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    return {"status": "ok", "platform": "Aegis", "version": "1.0.0"}


# Serverless AWS Lambda / Vercel Handler via Mangum
handler = Mangum(app, lifespan="off")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
