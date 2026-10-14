# 🛡️ Aegis — Digital Risk Protection Platform
### Autonomous Brand Impersonation, Social & Mobile App Defense

> **ByteXL Hackathon — Challenge 03: Digital Risk Protection (Social & App Monitoring)**  
> **Production Release:** `v1.0.0-production`  
> **Platform Engine:** Hybrid Deterministic Heuristics + XGBoost Machine Learning + Tree-SHAP Explainability

---

## 🌟 Executive Overview

**Aegis** is an enterprise-grade Digital Risk Protection platform built to detect, triage, and counter brand impersonations operating outside the organizational perimeter across social media ecosystems, public domain namespaces, and mobile application marketplaces.

Built strictly against the Challenge 03 evaluation rubric and real-world cybersecurity requirements, Aegis combines:
1. **Brand Digital Twin Ground Truth**: Strict baseline defining legitimate corporate handles, package IDs, publishers, logos, and authorized partner exceptions.
2. **0% False Positive Exclusion Gate**: Mathematical set-membership short-circuit ensuring verified enterprise assets (`@apexbank`, `com.apexbank.mobile`) are never flagged to analysts or users.
3. **Social Media Impersonation Monitoring (30% weight)**: RapidFuzz token matching coupled with an 11-feature behavioral XGBoost classifier (**92.50% accuracy**, **98.36% ROC-AUC**).
4. **Mobile App Store Monitoring (30% weight)**: 4-pillar detection evaluating similar app names, rogue publishers, TF-IDF description plagiarism, 64-bit perceptual logo hashes, and a 215-permission XGBoost malware model (**97.91% accuracy**).
5. **Bonus Look-alike Name Detection (5–10 pts)**: Character swaps (`0`→`o`, `@`→`a`), trust keyword stripping, and punctuation collapse with residual fuzz defense preventing over-flagging on legitimate third parties.
6. **Account & Persona Management**: Complete workspace settings panel (`/app/account`) with profile customization, session audits, notification toggles, and Supabase RBAC integration.

---

## 📁 Production Directory Structure

```text
Aegisshield_Production/
├── api/
│   └── index.py               # Vercel Serverless Function entry point (ASGI bridge)
├── backend/
│   ├── api/routes/            # FastAPI REST endpoints (analyzer, brands, cases, etc.)
│   ├── data/                  # Reference datasets & baseline assets
│   ├── db/                    # SQLAlchemy models & session manager
│   ├── models/                # Trained XGBoost models (.json) & Tree-SHAP attributions
│   ├── schemas/               # Pydantic v2 validation contracts
│   ├── services/              # Exclusion gate, RapidFuzz, pHash, TF-IDF, live feeds
│   ├── utils/                 # Threat scoring, normalization, and helpers
│   ├── aegis.db               # Pre-seeded SQLite demo database
│   ├── main.py                # FastAPI application entry point
│   ├── requirements.txt       # Backend dependencies
│   ├── vercel.json            # Standalone backend Vercel configuration
│   └── .env.example           # Backend environment variables template
├── frontend/
│   ├── public/                # Static assets and favicons
│   ├── src/
│   │   ├── AccountPage.tsx    # Interactive account & preferences workspace
│   │   ├── account.ts         # Account state, default profiles, storage helpers
│   │   ├── account-theme.css  # Space Grotesk / Inter cyber typography
│   │   ├── account.css        # Account panel layouts, toggles, and modals
│   │   ├── App.tsx            # Main application router and console views
│   │   ├── AuthPage.tsx       # Supabase authentication & 1-click test accounts
│   │   ├── data.ts            # REST API client & live WebSocket subscriber
│   │   ├── supabase.ts        # Supabase JS client and session cache
│   │   ├── index.css          # Cyber-radar design system (#080C0C, #B3F4CE)
│   │   └── main.tsx           # React DOM root entry point
│   ├── index.html             # HTML5 template with SEO & meta tags
│   ├── package.json           # Frontend dependencies & scripts
│   ├── vite.config.ts         # Vite bundler configuration
│   ├── vercel.json            # Standalone frontend Vercel configuration (SPA rewrites)
│   └── .env.example           # Frontend environment variables template
├── .env.example               # Root unified environment variables template
├── .gitignore                 # Production ignore rules
├── requirements.txt           # Root requirements for Vercel Python runtime
├── vercel.json                # Root unified fullstack Vercel deployment config
├── VERCEL_DEPLOYMENT.md       # Step-by-step Vercel deployment runbook
└── README.md                  # This documentation
```

---

## 🚀 Quick Start (Local Run)

### 1. Backend Service
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python main.py
# Server runs on: http://localhost:8000 (Docs: http://localhost:8000/docs)
```

### 2. Frontend Console
```bash
cd frontend
npm install
npm run dev
# Vite runs on: http://localhost:5173
```

---

## ☁️ Vercel Deployment

Aegis is architected for zero-friction deployment to Vercel. You can deploy it in two ways:

1. **Option A (Recommended — Monorepo / Unified)**:
   Deploy the root `Aegisshield_Production` directory directly to Vercel. The root `vercel.json` compiles the React frontend to `frontend/dist` and routes `/api/(.*)` to the Python Serverless Function in `api/index.py`.
2. **Option B (Separate Deployments)**:
   Deploy `frontend/` as a static Vite project on Vercel, and deploy `backend/` either to Vercel Python or an external container host (e.g. Render, Railway, AWS ECS).

👉 **For step-by-step instructions with environment variable configs, see [VERCEL_DEPLOYMENT.md](file:///d:/BYTEXL_HACKATHON/Whole_Project/ByteXl/Aegisshield_Production/VERCEL_DEPLOYMENT.md).**

---

## 🔒 Security & Evaluation Compliance

| Requirement | Implementation | Measured Outcome |
| :--- | :--- | :--- |
| **0% Official False Positives** | Set-membership exclusion gate before any scoring | **0.00% FP** on official handles/APKs |
| **Social Media Impersonation** | RapidFuzz token matching + 11-feature XGBoost | **92.50% Accuracy** (98.36% ROC-AUC) |
| **Mobile App Store Monitoring** | 4-Pillar audit: name, logo pHash, TF-IDF desc, permissions | **97.91% Accuracy** on 3,008 APKs |
| **Look-alike Variations (Bonus)** | Leetspeak tables, trust word stripping, separator collapse | Full reason code audit trail |
| **Explainable AI** | Zero-dependency Tree-SHAP native booster contributions | Real-time top-5 feature attributions |
| **Authentication & RBAC** | Supabase Auth with session persistence & quick-fills | 4 role tiers with audit logging |

---

## 📄 License
Enterprise MIT License — ByteXL Hackathon 2026.
