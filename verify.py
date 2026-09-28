#!/usr/bin/env python3
"""
ScamShield Automated Verification Suite (verify.py)
==================================================
Programmatically verifies core backend functionality, threat intelligence schema,
GovTech CSV logging with formula injection mitigation, multimodal vision without OCR,
in-memory voice warnings, Rahul honeypot persona, and Hinglish dataset sampling.

Usage:
    python verify.py

Exit Codes:
    0: All verification checks passed (PASS)
    1: One or more checks failed (FAIL)
"""

import csv
import io
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Guarantee deterministic offline test execution when no live Gemini API key is configured
if "SCAMSHIELD_MOCK_MODE" not in os.environ and not os.getenv("GEMINI_API_KEY"):
    os.environ["SCAMSHIELD_MOCK_MODE"] = "1"

# Base directory setup
BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE_DIR))

# Import the core backend module under test
try:
    import backend
except ImportError as import_err:
    print(f"[FATAL] Failed to import backend module from {BASE_DIR}: {import_err}")
    print("\n" + "=" * 70)
    print("VERIFICATION RESULT: FAIL (backend import error)")
    print("=" * 70)
    print("FAIL")
    sys.exit(1)


# ===========================================================================
# Test 1: Threat Analysis JSON Schema and Contract Verification
# ===========================================================================

def test_analyze_threat_json_structure() -> Tuple[bool, str]:
    """
    Verifies that backend.analyze_threat returns a valid dictionary strictly matching
    the PROJECT.md schema with all required keys, valid value types, and accurate threat metrics.
    """
    required_keys = [
        "risk_level",
        "confidence_score",
        "scam_category",
        "red_flags",
        "psychological_tactics",
        "extracted_identifiers",
        "recommended_action",
        "hindi_warning_text",
    ]

    # 1. Test with a known high-risk Indian banking scam message
    scam_text = (
        "Ji namaskar Aapka SBI bank account 2 ghante mein block ho jayega KYC pending hone ke karan. "
        "Abhi apna OTP share kijiye is number par: 9876543210 ya fir is link par click karein: http://sbi-kyc-update.com"
    )

    res = backend.analyze_threat(text=scam_text)

    if not isinstance(res, dict):
        return False, f"analyze_threat must return a dict, got {type(res).__name__}"

    # Verify all required keys are present
    missing_keys = [key for key in required_keys if key not in res]
    if missing_keys:
        return False, f"Missing required keys in analyze_threat response: {missing_keys}"

    # Verify risk_level contract
    if res["risk_level"] not in ("High", "Medium", "Low"):
        return False, f"Invalid risk_level: '{res['risk_level']}'. Expected 'High', 'Medium', or 'Low'"
    if res["risk_level"] != "High":
        return False, f"Expected risk_level 'High' for known banking scam, got '{res['risk_level']}'"

    # Verify confidence_score contract
    if not isinstance(res["confidence_score"], (int, float)):
        return False, f"confidence_score must be float, got {type(res['confidence_score']).__name__}"
    if not (0.0 <= res["confidence_score"] <= 1.0):
        return False, f"confidence_score must be between 0.0 and 1.0, got {res['confidence_score']}"

    # Verify scam_category contract
    if not isinstance(res["scam_category"], str) or not res["scam_category"].strip():
        return False, "scam_category must be a non-empty string"
    if not any(k in res["scam_category"].lower() for k in ["kyc", "bank", "account"]):
        return False, f"scam_category does not reflect banking scam: '{res['scam_category']}'"

    # Verify red_flags and psychological_tactics lists
    if not isinstance(res["red_flags"], list) or len(res["red_flags"]) == 0:
        return False, "red_flags must be a non-empty list of strings for high-risk threat"
    if not all(isinstance(rf, str) and rf.strip() for rf in res["red_flags"]):
        return False, "All items in red_flags must be non-empty strings"

    if not isinstance(res["psychological_tactics"], list) or len(res["psychological_tactics"]) == 0:
        return False, "psychological_tactics must be a non-empty list of strings for high-risk threat"
    if not all(isinstance(pt, str) and pt.strip() for pt in res["psychological_tactics"]):
        return False, "All items in psychological_tactics must be non-empty strings"

    # Verify extracted_identifiers structure
    identifiers = res.get("extracted_identifiers")
    if not isinstance(identifiers, dict):
        return False, f"extracted_identifiers must be a dict, got {type(identifiers).__name__}"

    for sub_key in ("phone_numbers", "upi_ids", "urls"):
        if sub_key not in identifiers:
            return False, f"Missing '{sub_key}' in extracted_identifiers"
        if not isinstance(identifiers[sub_key], list):
            return False, f"extracted_identifiers['{sub_key}'] must be a list"

    # Check extracted IoCs match the input message
    phone_found = any("9876543210" in p for p in identifiers["phone_numbers"])
    url_found = any("sbi-kyc-update.com" in u for u in identifiers["urls"])
    if not phone_found:
        return False, f"Expected phone number '9876543210' not found in extracted_identifiers: {identifiers['phone_numbers']}"
    if not url_found:
        return False, f"Expected URL 'sbi-kyc-update.com' not found in extracted_identifiers: {identifiers['urls']}"

    # Verify recommended action and Hindi warning text
    if not isinstance(res["recommended_action"], str) or not res["recommended_action"].strip():
        return False, "recommended_action must be a non-empty string"
    if not isinstance(res["hindi_warning_text"], str) or not res["hindi_warning_text"].strip():
        return False, "hindi_warning_text must be a non-empty string"

    # 2. Test safe/legitimate text
    safe_text = "Hello beta ghar aa gaya hoon, dinner ready hai darwaza khol do."
    safe_res = backend.analyze_threat(text=safe_text)
    if safe_res.get("risk_level") != "Low":
        return False, f"Expected Low risk for benign message, got {safe_res.get('risk_level')}"
    if len(safe_res.get("red_flags", [])) != 0:
        return False, "Safe message must have empty red_flags list"

    # 3. Test empty input handling
    empty_res = backend.analyze_threat()
    if empty_res.get("risk_level") != "Low" or empty_res.get("confidence_score") != 0.0:
        return False, "Empty input must return Low risk and 0.0 confidence"

    return True, "Valid JSON structure, types, and schema compliance confirmed for High, Low, and Empty inputs"


# ===========================================================================
# Test 2: Threat Logging and CSV Formula Injection Neutralization
# ===========================================================================

def test_threat_logging_csv_and_injection() -> Tuple[bool, str]:
    """
    Verifies that backend.log_threat:
    1. Creates/appends to CSV with proper header columns.
    2. Neutralizes CSV formula injection attacks (CWE-1236) by escaping =, +, -, @.
    3. Successfully appends multiple threat events without re-creating headers.
    4. Ignores/skips Low-risk messages.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        test_csv_path = Path(tmpdir) / "verify_threat_log.csv"

        # Construct malicious threat data designed to trigger formula injection
        malicious_threat = {
            "risk_level": "High",
            "scam_category": "=cmd|'/C calc'!A0",
            "extracted_identifiers": {
                "phone_numbers": ["+91 9876543210", "-cmd|'/C calc'!A0"],
                "urls": ["@SUM(A1:B1)", "http://secure-phish.in/login"],
                "upi_ids": ["=DDE(\"cmd\";\"/C calc\";\"!A0\")", "@fraud_upi"],
            },
        }

        # 1. Log high-risk threat
        result = backend.log_threat(malicious_threat, file_path=test_csv_path)

        if not result:
            return False, "log_threat returned falsy result on High-risk threat"
        if result != True:
            return False, "ThreatLogResult must evaluate equal to True"
        if not isinstance(result, list):
            return False, f"Expected ThreatLogResult list subclass, got {type(result).__name__}"
        if len(result) < 5:
            return False, f"Expected at least 5 logged identifiers, got {len(result)}"

        # 2. Check physical CSV content on disk
        if not test_csv_path.exists():
            return False, f"Target CSV file was not created at {test_csv_path}"

        with open(test_csv_path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\r\n") for line in f.readlines()]

        if not lines:
            return False, "Created CSV file is empty"

        # Check header
        expected_header = "timestamp,risk_level,scam_category,identifier_type,identifier_value"
        if lines[0] != expected_header:
            return False, f"Invalid CSV header. Expected '{expected_header}', got '{lines[0]}'"

        content = "\n".join(lines)

        # Check formula injection neutralization
        # Values starting with =, +, -, @ must be prepended with single quote (')
        required_escapes = [
            ("Category '=cmd'", "'=cmd|'/C calc'!A0"),
            ("Phone '+91'", "'+91 9876543210"),
            ("Phone '-cmd'", "'-cmd|'/C calc'!A0"),
            ("URL '@SUM'", "'@SUM(A1:B1)"),
            ("UPI '=DDE'", "'=DDE(\"cmd\";\"/C calc\";\"!A0\")"),
            ("UPI '@fraud'", "'@fraud_upi"),
        ]

        for desc, escaped_token in required_escapes:
            if escaped_token not in content and escaped_token.replace('"', '""') not in content:
                return False, f"Formula injection defense failure: {desc} not found escaped as '{escaped_token}' in CSV"

        # Ensure benign URL was not mangled with unnecessary prefix
        if "http://secure-phish.in/login" not in content:
            return False, "Benign URL was not properly preserved in CSV"

        initial_row_count = len(lines)

        # 3. Test appending additional threat record
        second_threat = {
            "risk_level": "Medium",
            "scam_category": "Parcel Delivery Fraud",
            "extracted_identifiers": {
                "phone_numbers": ["9123456780"],
                "urls": ["http://fake-courier.com"],
                "upi_ids": [],
            },
        }

        second_result = backend.log_threat(second_threat, file_path=test_csv_path)
        if not second_result:
            return False, "log_threat returned falsy result on Medium-risk threat"

        with open(test_csv_path, "r", encoding="utf-8") as f:
            updated_lines = [line.rstrip("\r\n") for line in f.readlines()]

        if len(updated_lines) <= initial_row_count:
            return False, "Subsequent log_threat did not append rows to CSV"

        # Ensure header was NOT duplicated
        headers = [line for line in updated_lines if line == expected_header]
        if len(headers) != 1:
            return False, f"Expected exactly 1 header line in CSV after append, found {len(headers)}"

        # 4. Verify Low-risk messages are NOT logged to CSV
        low_threat = {
            "risk_level": "Low",
            "scam_category": "Legitimate / Safe Communication",
            "extracted_identifiers": {
                "phone_numbers": ["9999999999"],
                "urls": [],
                "upi_ids": [],
            },
        }
        low_result = backend.log_threat(low_threat, file_path=test_csv_path)
        if low_result:
            return False, "log_threat must return empty/falsy result for Low-risk messages"
        if low_result != False:
            return False, "Empty ThreatLogResult must evaluate equal to False"

        with open(test_csv_path, "r", encoding="utf-8") as f:
            final_lines = [line.rstrip("\r\n") for line in f.readlines()]

        if len(final_lines) != len(updated_lines):
            return False, "Low-risk message was erroneously appended to CSV"

    return True, "CSV file creation, appending, header preservation, and formula neutralization verified"


# ===========================================================================
# Test 3: Multimodal Vision and Zero OCR Dependency
# ===========================================================================

def test_multimodal_vision_zero_ocr() -> Tuple[bool, str]:
    """
    Verifies that:
    1. pytesseract is strictly NOT used, NOT imported, and TESSERACT_AVAILABLE is False.
    2. analyze_threat ingests image screenshots directly (multimodal vision).
    3. extract_text_from_image returns the migration deprecation notice safely.
    """
    # 1. Zero OCR checks
    if getattr(backend, "TESSERACT_AVAILABLE", True):
        return False, "backend.TESSERACT_AVAILABLE must be False (zero pytesseract policy)"

    if "pytesseract" in sys.modules:
        return False, "pytesseract is currently loaded in sys.modules (violates zero OCR policy)"

    if "pytesseract" in dir(backend):
        return False, "backend module exposes pytesseract in its namespace"

    # Legacy stub check
    stub_msg = backend.extract_text_from_image("dummy_test.png")
    if "[Notice]" not in stub_msg:
        return False, f"extract_text_from_image legacy stub did not return notice: {stub_msg}"

    # 2. Multimodal image analysis check
    sample_images = [
        BASE_DIR / "test_images" / "kbc_lottery_scam.png",
        BASE_DIR / "test_images" / "electricity_scam.png",
        BASE_DIR / "test_images" / "part_time_job_scam.png",
    ]

    tested_image = False
    for img_path in sample_images:
        if img_path.exists():
            res = backend.analyze_threat(image=str(img_path))
            if not isinstance(res, dict):
                return False, f"analyze_threat(image=...) did not return a dict for {img_path.name}"
            if res.get("risk_level") not in ("High", "Medium"):
                return False, f"Expected High or Medium risk for screenshot {img_path.name}, got {res.get('risk_level')}"
            if not res.get("scam_category"):
                return False, f"Missing scam_category in multimodal analysis for {img_path.name}"
            tested_image = True
            break

    if not tested_image:
        # Fallback: test with an in-memory synthetic PIL Image if test_images are absent
        try:
            from PIL import Image
            synthetic_img = Image.new("RGB", (200, 200), color=(255, 255, 255))
            res = backend.analyze_threat(image=synthetic_img)
            if not isinstance(res, dict):
                return False, "analyze_threat failed to process in-memory PIL image"
        except ImportError:
            return False, "PIL library is required for image ingestion"

    # Confirm pytesseract was still NOT loaded during image analysis
    if "pytesseract" in sys.modules:
        return False, "pytesseract was loaded into sys.modules during image analysis"

    return True, "Zero OCR dependency confirmed and multimodal image analysis executed cleanly"


# ===========================================================================
# Test 4: Accessible In-Memory Voice Warning Generation (gTTS)
# ===========================================================================

def test_in_memory_voice_warning() -> Tuple[bool, str]:
    """
    Verifies that backend.generate_voice_warning:
    1. Returns an in-memory io.BytesIO stream (no Windows file-lock errors).
    2. Stream position is rewound to 0 (seek(0)) for instant browser playback.
    3. Produces non-empty audio payload or handles offline status gracefully.
    4. Accepts both threat assessment dictionary and raw string inputs.
    """
    sample_hindi = "सावधान! यह एक फर्जी संदेश है। किसी को पैसे या ओटीपी न भेजें।"

    # Test with string input
    stream_str = backend.generate_voice_warning(sample_hindi)
    if stream_str is not None:
        if not isinstance(stream_str, io.BytesIO):
            return False, f"Expected io.BytesIO stream, got {type(stream_str).__name__}"
        if stream_str.tell() != 0:
            return False, f"Audio stream must be rewound to position 0 (seek(0)), got {stream_str.tell()}"
        audio_bytes = stream_str.read()
        if len(audio_bytes) < 50:
            return False, f"Generated audio stream contains suspiciously small payload ({len(audio_bytes)} bytes)"

    # Test with dictionary input
    threat_dict = {
        "risk_level": "High",
        "hindi_warning_text": "चेतावनी! बैंक खाता ब्लॉक होने का यह संदेश फर्जी है।",
    }
    stream_dict = backend.generate_voice_warning(threat_dict)
    if stream_dict is not None:
        if not isinstance(stream_dict, io.BytesIO):
            return False, f"Expected io.BytesIO stream from dict input, got {type(stream_dict).__name__}"
        if stream_dict.tell() != 0:
            return False, f"Dict-derived audio stream must be rewound to position 0, got {stream_dict.tell()}"

    # Alias check for UI backward compatibility
    if not hasattr(backend, "generate_warning_audio"):
        return False, "Missing backward-compatible alias backend.generate_warning_audio"

    return True, "In-memory voice warning synthesis returns valid io.BytesIO without disk file locks"


# ===========================================================================
# Test 5: Strike Mode Rahul Honeypot Persona & Anti-Exfiltration
# ===========================================================================

def test_rahul_honeypot_persona() -> Tuple[bool, str]:
    """
    Verifies that backend.generate_honeypot_reply:
    1. Generates authentic Hinglish replies in the Rahul persona (college student).
    2. Handles single message string and multi-turn chat history inputs.
    3. Implements anti-exfiltration defense (refuses to leak real credentials/PINs).
    """
    scammer_msg = (
        "Dear Customer, Your SBI account is blocked. Send OTP immediately to verify your account or police will visit."
    )

    # 1. Single message input test
    reply = backend.generate_honeypot_reply(scammer_msg)
    if not isinstance(reply, str) or not reply.strip():
        return False, f"generate_honeypot_reply must return a non-empty string, got: {reply}"

    reply_lower = reply.lower()

    # Check for Rahul persona markers (college student, anxiety, exams, hostel, naive stall)
    persona_markers = [
        "sir", "bhaiya", "exam", "college", "papa", "fees", "sharma",
        "phone", "hostel", "47", "student", "branch", "mess", "viva"
    ]
    if not any(marker in reply_lower for marker in persona_markers):
        return False, f"Reply did not exhibit Rahul persona characteristics: '{reply}'"

    # 2. Multi-turn chat history test
    chat_history = [
        {"role": "user", "content": "I am Cyber Inspector Sharma. Send ₹10,000 fine right now."},
        {"role": "assistant", "content": "Arre sir please mere exams chal rahe hain papa ko mat batana."},
        {"role": "user", "content": "Send your Google Pay UPI PIN immediately!"},
    ]

    multi_reply = backend.generate_honeypot_reply(chat_history)
    if not isinstance(multi_reply, str) or len(multi_reply) < 10:
        return False, f"Multi-turn honeypot reply invalid: {multi_reply}"

    # 3. Anti-exfiltration check (must not reveal real credentials)
    leak_check = multi_reply.lower()
    for sensitive in ("my real password is", "my real pin is", "cvv is"):
        if sensitive in leak_check:
            return False, f"Honeypot leaked sensitive credential string: '{sensitive}'"

    return True, "Rahul honeypot persona, multi-turn dialogue, and anti-exfiltration boundaries verified"


# ===========================================================================
# Test 6: Hinglish Dataset Sampling and Dynamic Threat Simulation
# ===========================================================================

def test_load_sample_threats() -> Tuple[bool, str]:
    """
    Verifies that backend.load_sample_threats:
    1. Returns at least 5 distinct scam examples from the Hinglish dataset.
    2. Covers distinct scam categories (e.g. Banking, Electricity, Lottery, Job, etc.).
    3. Each sample contains non-empty 'category', 'message', and 'source'.
    """
    samples = backend.load_sample_threats(n=5)

    if not isinstance(samples, list):
        return False, f"load_sample_threats must return a list, got {type(samples).__name__}"

    if len(samples) < 5:
        return False, f"Expected at least 5 threat samples, got {len(samples)}"

    categories = set()
    for idx, sample in enumerate(samples):
        if not isinstance(sample, dict):
            return False, f"Sample #{idx} is not a dict: {sample}"

        for key in ("category", "message", "source"):
            if key not in sample:
                return False, f"Missing key '{key}' in sample #{idx}"
            if not isinstance(sample[key], str) or not sample[key].strip():
                return False, f"Empty or non-string '{key}' in sample #{idx}"

        categories.add(sample["category"].strip())

    if len(categories) < 5:
        return False, f"Expected at least 5 distinct categories, found {len(categories)}: {categories}"

    return True, f"Loaded {len(samples)} distinct threat samples across {len(categories)} categories"


# ===========================================================================
# Main Verification Runner
# ===========================================================================

def main() -> None:
    """Runs all verification checks, prints report, and exits with 0 on PASS or 1 on FAIL."""
    print("=" * 75)
    print("ScamShield Programmatic Verification Suite (verify.py)")
    print("=" * 75)
    print(f"Backend location : {backend.__file__}")
    print(f"Deterministic mode: {'ON (SCAMSHIELD_MOCK_MODE=1)' if os.getenv('SCAMSHIELD_MOCK_MODE') == '1' else 'OFF'}")
    print("-" * 75)

    test_suite = [
        ("Threat Analysis JSON Schema (R1, R2)", test_analyze_threat_json_structure),
        ("GovTech Threat Logging & Formula Defense (R4)", test_threat_logging_csv_and_injection),
        ("Multimodal Vision & Zero OCR (R1)", test_multimodal_vision_zero_ocr),
        ("In-Memory Hindi Voice Warning (R2)", test_in_memory_voice_warning),
        ("Rahul Honeypot Persona & Anti-Exfiltration (R3)", test_rahul_honeypot_persona),
        ("Hinglish Dataset Dynamic Sampling (R1)", test_load_sample_threats),
    ]

    passed_tests = 0
    failed_tests = 0
    failures: List[Tuple[str, str]] = []

    for name, test_fn in test_suite:
        try:
            success, msg = test_fn()
            if success:
                print(f"[PASS] {name}")
                print(f"       Details: {msg}")
                passed_tests += 1
            else:
                print(f"[FAIL] {name}")
                print(f"       Error  : {msg}")
                failed_tests += 1
                failures.append((name, msg))
        except Exception as exc:
            err_trace = traceback.format_exc().strip()
            print(f"[FAIL] {name} (Uncaught Exception)")
            print(f"       Exception: {exc}")
            failed_tests += 1
            failures.append((name, f"Exception: {exc}\n{err_trace}"))

    print("-" * 75)
    total_tests = passed_tests + failed_tests
    print(f"Summary: {passed_tests}/{total_tests} test suites passed ({failed_tests} failed)")
    print("=" * 75)

    if failed_tests == 0:
        print("VERIFICATION RESULT: ALL TESTS PASSED")
        print("=" * 75)
        print("PASS")
        sys.exit(0)
    else:
        print("VERIFICATION RESULT: ONE OR MORE TESTS FAILED")
        for fail_name, fail_msg in failures:
            print(f"  - {fail_name}: {fail_msg}")
        print("=" * 75)
        print("FAIL")
        sys.exit(1)


if __name__ == "__main__":
    main()
