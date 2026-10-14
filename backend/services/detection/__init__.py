"""
Detection service — hybrid risk engine.
Orchestrates model scoring + rule engine + embeddings → fusion → tiering.

Risk = w1·Identity + w2·Visual + w3·Semantic + w4·Link + w5·Context + w6·Correlation
Each component in [0,1], mapped to 0–100.
Link = 0.6·model + 0.4·rules (tunable).

Tier rules (spec Section 6.3):
  Tier 0 (Observe):  weak / single-signal
  Tier 1 (Review):   2+ signals or one strong signal
  Tier 2 (Escalate): strong corroboration across independent families
  Visual-only or identity-only → never Tier 2
  Allowlisted → capped at Tier 0
"""

# TODO: Implement the full detection pipeline
