import os
import json
import uuid
import hashlib
import httpx
from typing import List, Optional, Dict, Any, Union, Literal
from pydantic import BaseModel, Field, ValidationError
from fastapi import FastAPI, HTTPException, status
from contextlib import asynccontextmanager
import psycopg2
from psycopg2.extras import RealDictCursor

# --- Database Connection Helper ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost:5432/mailroom_db")

def get_db_connection():
    # Uses RealDictCursor so rows can be accessed easily like dicts: row['call_id']
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# --- App Lifespan Hook ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically initialize tables on start
    from init_db import initialize_database
    initialize_database()
    yield

app = FastAPI(lifespan=lifespan)

# --- Pydantic Data Validation Schemas ---
class DossierElement(BaseModel):
    id: str
    content: str

class ProposeRequest(BaseModel):
    operation: Literal["propose"]
    evaluationId: str
    receiptVerificationKey: str
    dossiers: List[DossierElement]

class CommitReceiptElement(BaseModel):
    receiptId: str
    evaluationId: str
    dossierId: str
    callId: str
    action: str
    proposalDigest: str

class CommitRequest(BaseModel):
    operation: Literal["commit"]
    receipts: List[CommitReceiptElement]

# --- Target & Payload Schemas ---
class DraftTarget(BaseModel):
    kind: Literal["draft_queue"]
    id: str

class CaseRecordTarget(BaseModel):
    kind: Literal["case_record"]
    id: str

class EmailTarget(BaseModel):
    kind: Literal["email"]
    id: str

class ApprovalQueueTarget(BaseModel):
    kind: Literal["approval_queue"]
    id: str

class SecurityQueueTarget(BaseModel):
    kind: Literal["security_queue"]
    id: Literal["mailroom"]

class DraftPayload(BaseModel):
    recipient: str
    referenceId: str
    status: str
    template: Literal["order_status"]

class UpdateRecordPayload(BaseModel):
    field: Literal["delivery_window"]
    sourceEventId: str
    value: str

class ApprovedNoticePayload(BaseModel):
    referenceId: str
    status: str
    template: Literal["approved_delivery_notice"]

class RequestConfirmationPayload(BaseModel):
    claimedSender: str
    questionCode: Literal["VERIFY_REQUEST"]
    referenceId: str

class QuarantinePayload(BaseModel):
    artifactId: str
    reasonCode: Literal["INDIRECT_PROMPT_INJECTION"]

class NoActionPayload(BaseModel):
    reasonCode: Literal["ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"]
    referenceId: str

class ValidatedAIProposal(BaseModel):
    action: Literal["create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"]
    target: Optional[Union[DraftTarget, CaseRecordTarget, EmailTarget, ApprovalQueueTarget, SecurityQueueTarget]] = None
    payload: Optional[Union[DraftPayload, UpdateRecordPayload, ApprovedNoticePayload, RequestConfirmationPayload, QuarantinePayload, NoActionPayload]] = None
    evidence: str

# --- Hashing & Fingerprinting Helpers ---
def compute_canonical_fingerprint(content: str) -> str:
    return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()

def compute_proposal_digest(call_id: str, action: str, target: Any, payload: Any) -> str:
    # Ensure stable dictionary sorting before computing strings
    target_str = json.dumps(target, sort_keys=True) if target else ""
    payload_str = json.dumps(payload, sort_keys=True) if payload else "{}"
    raw_stream = f"{call_id}|{action}|{target_str}|{payload_str}".encode("utf-8")
    return hashlib.sha256(raw_stream).hexdigest()

# --- Upstream Mock / LLM Inference Sandbox Call ---
def call_llm_inference_sandbox(content: str) -> Dict[str, Any]:
    # Placeholder execution layer. Connect your real LLM API here.
    # Returns a secure default if text matches injection signatures.
    if "override" in content.lower() or "system prompt" in content.lower():
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": "detected", "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": "Suspicious pattern matched inside text content streams."
        }
    return {
        "action": "no_action",
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "default_ref"},
        "evidence": "Clean informational document processing segment."
    }

# --- Unified Endpoints Router Layer ---
@app.post("/mailroom/endpoint")
async def handle_mailroom_operations(request_data: Dict[str, Any]):
    operation = request_data.get("operation")
    if not operation:
        raise HTTPException(status_code=400, detail="Missing operation structural layout parameter.")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # =====================================================================
        # MODE: PROPOSE
        # =====================================================================
        if operation == "propose":
            try:
                req = ProposeRequest(**request_data)
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=e.errors())

            # Check internal runtime duplication constraints
            seen_ids = set()
            for d in req.dossiers:
                if d.id in seen_ids:
                    raise HTTPException(status_code=400, detail=f"Duplicate dossier structural element detected: {d.id}")
                seen_ids.add(d.id)

            # Enforce strict conflict parameters on evaluation keys
            cursor.execute("SELECT receipt_verification_key FROM evaluation_state WHERE evaluation_id = %s", (req.evaluationId,))
            existing_eval = cursor.fetchone()
            if existing_eval and existing_eval["receipt_verification_key"] != req.receiptVerificationKey:
                raise HTTPException(status_code=409, detail="Evaluation transaction key structural mismatch conflict.")

            if not existing_eval:
                cursor.execute("INSERT INTO evaluation_state (evaluation_id, receipt_verification_key) VALUES (%s, %s)", (req.evaluationId, req.receiptVerificationKey))

            proposals_out = []

            for dossier in req.dossiers:
                fingerprint = compute_canonical_fingerprint(dossier.content)

                # Check conflict parameters: Identical ID but different text payload under active evaluation
                cursor.execute("SELECT content_fingerprint FROM dossier_proposals WHERE evaluation_id = %s AND dossier_id = %s", (req.evaluationId, dossier.id))
                conflict_check = cursor.fetchone()
                if conflict_check and conflict_check["content_fingerprint"] != fingerprint:
                    raise HTTPException(status_code=409, detail="Dossier fingerprint modification data clash.")

                # Lookup global unique content cache hit matrices
                cursor.execute("SELECT call_id, action, target, payload, evidence FROM dossier_proposals WHERE dossier_id = %s AND content_fingerprint = %s LIMIT 1", (dossier.id, fingerprint))
                cached = cursor.fetchone()

                if cached:
                    proposals_out.append({
                        "dossierId": dossier.id,
                        "callId": cached["call_id"],
                        "action": cached["action"],
                        "target": cached["target"],
                        "payload": cached["payload"],
                        "evidence": cached["evidence"]
                    })
                else:
                    ai_raw = call_llm_inference_sandbox(dossier.content)
                    try:
                        validated = ValidatedAIProposal(**ai_raw)
                    except ValidationError:
                        validated = ValidatedAIProposal(
                            action="quarantine_item",
                            target={"kind": "security_queue", "id": "mailroom"},
                            payload={"artifactId": dossier.id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                            evidence="Automated security structural validation exception handling triggered."
                        )

                    generated_call_id = f"call_{uuid.uuid4().hex[:16]}"
                    p_data = validated.model_dump()

                    cursor.execute(
                        """INSERT INTO dossier_proposals 
                        (dossier_id, content_fingerprint, evaluation_id, call_id, action, target, payload, evidence, raw_dossier_content) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (dossier.id, fingerprint, req.evaluationId, generated_call_id, p_data["action"], json.dumps(p_data["target"]), json.dumps(p_data["payload"]), p_data["evidence"], dossier.content)
                    )

                    proposals_out.append({
                        "dossierId": dossier.id,
                        "callId": generated_call_id,
                        "action": p_data["action"],
                        "target": p_data["target"],
                        "payload": p_data["payload"],
                        "evidence": p_data["evidence"]
                    })

            conn.commit()
            return {"status": "awaiting_receipts", "proposals": proposals_out}

        # =====================================================================
        # MODE: COMMIT
        # =====================================================================
        elif operation == "commit":
            try:
                req = CommitRequest(**request_data)
            except ValidationError as e:
                raise HTTPException(status_code=422, detail=e.errors())

            outcomes_out = []

