from app.classification.nist_rules import CLASSIFICATION_RULES
from app.scanner.normalizer import algorithm_family

QUANTUM_VULNERABLE = "Quantum Vulnerable"
QUANTUM_RESISTANT = "Quantum Resistant Under Current Knowledge"
NEEDS_REVIEW = "Unknown / Needs Review"

class QuantumClassifier:
    def classify(self, finding):
        algorithm = finding.get("algorithm", "Unknown")
        family = algorithm_family(algorithm)
        for rule in CLASSIFICATION_RULES:
            if algorithm in rule["aliases"] or family == rule["algorithm_family"]:
                return {"quantum_classification": rule["classification"],
                        "classification_reason": rule["reasoning"],
                        "classification_reference": rule["reference"],
                        "classification_rule_id": rule["rule_id"],
                        "algorithm_family": family,
                        "is_standardized_pqc": family.startswith("PQC")}
        return {"quantum_classification": NEEDS_REVIEW,
                "classification_reason": "Scanner could not confidently identify a recognized algorithm family; manual review required.",
                "classification_reference": "Internal conservative classification policy",
                "classification_rule_id": "QR-UNKNOWN-001",
                "algorithm_family": family, "is_standardized_pqc": False}
