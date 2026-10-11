"""Structured payload, entropy, schema and optional local NLP detection."""

import json
import math
import re
from collections import Counter

SCHEMA_TYPES = {
    "patient_name": "PATIENT_NAME",
    "patient_id": "MRN",
    "mrn": "MRN",
    "medical_record_number": "MRN",
    "dob": "DOB",
    "birth_date": "DOB",
    "date_of_birth": "DOB",
    "ssn": "SSN",
    "email": "EMAIL",
    "phone": "PHONE_NUMBER",
    "address": "ADDRESS",
    "diagnosis": "DIAGNOSIS",
    "icd10": "DIAGNOSIS",
    "treatment": "TREATMENT",
    "medication": "MEDICATION",
    "prescription": "MEDICATION",
    "lab_result": "LAB_RESULT",
    "imaging_metadata": "IMAGING",
    "appointment": "APPOINTMENT",
    "member_id": "HEALTH_PLAN_ID",
    "claim_number": "HEALTH_PLAN_ID",
    "insurance": "HEALTH_PLAN_ID",
    "passport": "PASSPORT",
    "drivers_license": "DRIVERS_LICENSE",
    "device_id": "DEVICE_ID",
    "employee_id": "EMPLOYEE_ID",
    "customer_id": "CUSTOMER_ID",
    "credit_card": "CREDIT_CARD",
    "bank_account": "BANK_ACCOUNT",
    "biometric": "BIOMETRIC",
    "latitude": "LOCATION",
    "longitude": "LOCATION",
    "authorization": "AUTHORIZATION",
    "cookie": "AUTHORIZATION",
    "session_token": "SECRET",
    "access_token": "SECRET",
    "refresh_token": "SECRET",
    "api_key": "SECRET",
}


def schema_type(name):
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower().replace("-", "_")
    return SCHEMA_TYPES.get(name)


def entropy(value):
    return (
        -sum(
            (count / len(value)) * math.log2(count / len(value))
            for count in Counter(value).values()
        )
        if value
        else 0
    )


def structured_types(text):
    """Inspect JSON field names, never return their raw values."""
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return []
    types = set()

    def visit(node, depth=0):
        if depth > 20:
            return
        if isinstance(node, dict):
            for key, item in node.items():
                label = schema_type(key)
                if label and item not in [None, "", "[REDACTED]"]:
                    types.add(label)
                visit(item, depth + 1)
        elif isinstance(node, list):
            for item in node[:1000]:
                visit(item, depth + 1)

    visit(value)
    return sorted(types)


def entropy_redact(text):
    types = []

    def substitute(match):
        token = match.group(0)
        if (
            entropy(token) >= 4.5
            and re.search("[a-zA-Z]", token)
            and re.search("[0-9]", token)
        ):
            types.append("HIGH_ENTROPY_SECRET")
            return "[HIGH_ENTROPY_SECRET_REDACTED]"
        return token

    return re.sub(r"(?<![\w])[A-Za-z0-9+/=_-]{32,256}(?![\w])", substitute, text), types


def nlp_types(text, model):
    """Optional installed spaCy model; no runtime model download or remote calls."""
    import spacy

    pipeline = spacy.load(model)
    return sorted(
        {
            "PERSON" if e.label_ == "PERSON" else "LOCATION"
            for e in pipeline(text).ents
            if e.label_ in ["PERSON", "GPE", "LOC"]
        }
    )
