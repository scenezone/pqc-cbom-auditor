SEVERITY_CATEGORIES = [("Critical",90,100),("High",70,89),("Medium",40,69),("Low",0,39)]
WEIGHTS = {"quantum_risk":40,"business_impact":25,"cryptographic_risk":20,"data_lifetime":15}
CRITICALITY = {"Low":10,"Moderate":30,"High":55,"Very High":75,"Critical":95}
SENSITIVITY = {"Public":5,"Internal":30,"Confidential":65,"Restricted":90}
EXPOSURE = {"Internal":15,"Partner":45,"Public":80}
RETENTION = {"Less than 1 year":10,"1-3 years":30,"3-7 years":55,"7-15 years":80,"More than 15 years":95}
CONFIDENCE = {"High":1.0,"Medium":0.75,"Low":0.5}

def _lookup(mapping, val, default=30):
    if not val:
        return default
    if val in mapping:
        return mapping[val]
    val_lower = str(val).strip().lower()
    for k, v in mapping.items():
        if k.lower() == val_lower:
            return v
    return default

class SeverityEngine:
    def score(self, finding, context):
        if context is None:
            context = {}
        classification = finding.get("quantum_classification", "Unknown / Needs Review")
        operation = finding.get("crypto_operation","")
        purpose = finding.get("cryptographic_purpose","")
        quantum = 100 if classification == "Quantum Vulnerable" else (50 if classification == "Unknown / Needs Review" else 15)
        business = (0.45*_lookup(CRITICALITY, context.get("business_criticality"), 30)
                    + 0.35*_lookup(SENSITIVITY, context.get("data_sensitivity"), 30)
                    + 0.20*_lookup(EXPOSURE, context.get("external_exposure"), 15))
        key_est = operation in {"key_exchange","key_encapsulation"} or purpose == "key_establishment"
        tls_certificate_authentication = (
            finding.get("evidence_type") == "tls_probe"
            and finding.get("detection_rule_id") == "TLS-CERTIFICATE-ALGORITHM"
        )
        crypto = 80 if key_est else 50
        if finding.get("detection_confidence") == "Low":
            crypto = min(crypto, 40)
        lifetime = _lookup(RETENTION, context.get("data_retention_horizon"), 30)
        if key_est and classification == "Quantum Vulnerable":
            dlr = lifetime
        elif tls_certificate_authentication and classification == "Quantum Vulnerable":
            # A future quantum forgery can undermine live authentication, but
            # it does not decrypt traffic recorded today (unlike key exchange).
            dlr = 0
        elif classification == "Quantum Vulnerable":
            dlr = lifetime * 0.4
        else:
            dlr = lifetime * 0.15
        raw = (WEIGHTS["quantum_risk"]*quantum/100 + WEIGHTS["business_impact"]*business/100
               + WEIGHTS["cryptographic_risk"]*crypto/100 + WEIGHTS["data_lifetime"]*dlr/100)
        cf = CONFIDENCE.get(finding.get("detection_confidence","Medium"), 0.75)
        score = round(min(100, max(0, raw * (0.85 + 0.15*cf))))
        category = next((n for n, lo, hi in SEVERITY_CATEGORIES if lo <= score <= hi), "Low")
        risk_horizon = (
            "harvest_now_decrypt_later"
            if key_est and classification == "Quantum Vulnerable"
            else "future_live_authentication_forgery"
            if tls_certificate_authentication and classification == "Quantum Vulnerable"
            else "general_quantum_exposure"
        )
        return {"severity_score": score, "severity_category": category,
                "score_explanation": {"quantum_risk": quantum, "business_impact": round(business,1),
                                      "cryptographic_risk": crypto, "data_lifetime_risk": round(dlr,1),
                                      "risk_horizon": risk_horizon,
                                      "confidence_factor": cf, "weights": WEIGHTS}}
