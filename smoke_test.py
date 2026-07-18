"""Pruebas rápidas que no requieren PostgreSQL ni S3."""
from datetime import datetime, timedelta, timezone
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509.oid import NameOID
from reportlab.pdfgen import canvas

from cei_core.digital_sign import sign_pdf_with_pkcs12
from cei_core.domain import analyze_consent_text, summarize_review
from cei_core.security import generate_recovery_codes, generate_totp_secret
from cei_core.workflow import load_default_workflow, validate_workflow

workflow = load_default_workflow()
validate_workflow(workflow)
assert workflow["initial_stage"] in workflow["stages"]

secret = generate_totp_secret()
assert len(secret) >= 16
codes = generate_recovery_codes()
assert len(codes) == 10 and len(set(codes)) == 10

analysis = analyze_consent_text(
    "La participación es voluntaria. Puede retirarse. Se protegerá la confidencialidad."
)
assert analysis["word_count"] > 0

summary = summarize_review(
    [
        {
            "domain": "Riesgo y beneficio",
            "answer": "No cumple",
            "severity": "Crítica",
            "text": "Balance riesgo beneficio",
        }
    ]
)
assert summary["critical_open"]

# Firma PAdES con un certificado autofirmado de prueba.
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CEI Test Signer")])
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
    .sign(private_key, hashes.SHA256())
)
p12 = serialize_key_and_certificates(
    b"cei-test",
    private_key,
    certificate,
    None,
    serialization.BestAvailableEncryption(b"secret"),
)
pdf_buffer = BytesIO()
pdf_canvas = canvas.Canvas(pdf_buffer)
pdf_canvas.drawString(72, 720, "Dictamen de prueba")
pdf_canvas.save()
signature = sign_pdf_with_pkcs12(
    pdf_bytes=pdf_buffer.getvalue(),
    pkcs12_bytes=p12,
    passphrase="secret",
    field_name="TestSignature",
    reason="Prueba automatizada",
    location="Argentina",
)
assert signature.pdf_bytes.startswith(b"%PDF")
assert signature.signed_sha256 != signature.unsigned_sha256

print("OK - seguridad, workflow, reglas de evaluación y firma PDF.")
