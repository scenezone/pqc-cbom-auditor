from fastapi import APIRouter
from app.classification.nist_rules import CLASSIFICATION_RULES

router = APIRouter(prefix="/api/classification", tags=["Classification"])

@router.get("/algorithms")
async def algorithms():
    return CLASSIFICATION_RULES

@router.get("/methodology")
async def methodology():
    return {"primary_categories": ["Quantum Vulnerable","Quantum Resistant Under Current Knowledge","Unknown / Needs Review"],
            "standards": ["NIST FIPS 203 - ML-KEM","NIST FIPS 204 - ML-DSA","NIST FIPS 205 - SLH-DSA",
                          "NIST IR 8547 - Transition to Post-Quantum Cryptography Standards"],
            "limitations": ["Static analysis identifies evidence within supported scan scope only.",
                            "Dynamic algorithm selection may require manual review.",
                            "Quantum resistance does not establish implementation security."]}
