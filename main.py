import os
import json
import uuid
import hashlib
import sqlite3
from typing import List, Optional, Dict, Any, Union, Literal
from pydantic import BaseModel, Field, ValidationError
from fastapi import FastAPI, HTTPException, status
from contextlib import asynccontextmanager

def get_db_connection():
    conn = sqlite3.connect("mailroom.db")
    conn.row_factory = lambda cursor, row: {col: row[idx] for idx, col in enumerate(cursor.description)}
    return conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    from init_db import initialize_database
    initialize_database()
    yield

app = FastAPI(lifespan=lifespan)

# --- Pydantic Validation Schemas ---
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

# --- Target & Payload Layouts ---
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

def compute_canonical_fingerprint(content: str) -> str:
    return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()

def compute_proposal_digest(call_id: str, action: str, target: Any, payload: Any) -> str:
    target_str = json.dumps(target, sort_keys=True) if target else ""
    payload_str = json.dumps(payload, sort_keys=True) if payload else "{}"
    raw_stream = f"{call_id}|{action}|{target_str}|{payload_str}".encode("utf-8")
    return hashlib.sha256(raw_stream).hexdigest()

def call_llm_inference_sandbox(content: str) -> Dict[str, Any]:
    if "override" in content.lower() or "system prompt" in content.lower():
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": "detected", "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": "Suspicious input detected."
        }
    return {
        "action": "no_action",
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "default_ref"},
        "evidence": "Clean content parsing sequence completed."
    }

@app.post("/mailroom/endpoint")
async def handle_mailroom_operations(request_data: Dict[str, Any]):
    operation = request_data.get("operation")
    if not operation:
        raise HTTPException(status_code=400, detail="Missing operation parameter.")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if operation == "propose":
            try:
                req = ProposeRequest(**request_data)
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=e.errors())

            seen_ids = set()
            for d in req.dossiers:
                if d.id in seen_ids:
                    raise HTTPException(status_code=400, detail=f"Duplicate dossier structural element detected: {d.id}")
                seen_ids.add(d.id)

            cursor.execute("SELECT receipt_verification_key FROM evaluation_state WHERE evaluation_id = ?", (req.evaluationId,))
            existing_eval = cursor.fetchone()
            if existing_eval and existing_eval["receipt_verification_key"] != req.receiptVerificationKey:
                raise HTTPException(status_code=409, detail="Evaluation transaction key structural mismatch conflict.")

            if not existing_eval:
                cursor.execute("INSERT INTO evaluation_state (evaluation_id, receipt_verification_key) VALUES (?, ?)", (req.evaluationId, req.receiptVerificationKey))

            proposals_out = []

            for dossier in req.dossiers:
                fingerprint = compute_canonical_fingerprint(dossier.content)

                cursor.execute("SELECT content_fingerprint FROM dossier_proposals WHERE evaluation_id = ? AND dossier_id = ?", (req.evaluationId, dossier.id))
                conflict_check = cursor.fetchone()
                if conflict_check and conflict_check["content_fingerprint"] != fingerprint:
                    raise HTTPException(status_code=409, detail="Dossier fingerprint modification data clash.")

                cursor.execute("SELECT call_id, action, target, payload, evidence FROM dossier_proposals WHERE dossier_id = ? AND content_fingerprint = ? LIMIT 1", (dossier.id, fingerprint))
                cached = cursor.fetchone()

                if cached:
                    t_val = json.loads(cached["target"]) if isinstance(cached["target"], str) else cached["target"]
                    p_val = json.loads(cached["payload"]) if isinstance(cached["payload"], str) else cached["payload"]
                    proposals_out.append({
                        "dossierId": dossier.id,
                        "callId": cached["call_id"],
                        "action": cached["action"],
                        "target": t_val,
                        "payload": p_val,
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
                            evidence="Validation processing exception handling triggered."
                        )

                    generated_call_id = f"call_{uuid.uuid4().hex[:16]}"
                    p_data = validated.model_dump()

                    sql_ins = """INSERT INTO dossier_proposals 
                        (dossier_id, content_fingerprint, evaluation_id, call_id, action, target, payload, evidence, raw_dossier_content) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                    
                    cursor.execute(sql_ins, (dossier.id, fingerprint, req.evaluationId, generated_call_id, p_data["action"], json.dumps(p_data["target"]), json.dumps(p_data["payload"]), p_data["evidence"], dossier.content))

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

        elif operation == "commit":
            try:
                req = CommitRequest(**request_data)
            except ValidationError as e:
                raise HTTPException(status_code=422, detail=e.errors())

            outcomes_out = []

            for receipt in req.receipts:
                cursor.execute("SELECT 1 FROM evaluation_state WHERE evaluation_id = ?", (receipt.evaluationId,))
                if not cursor.fetchone():
                    raise HTTPException(status_code=400, detail="Unknown evaluation identifier execution.")

                cursor.execute("SELECT call_id, action, target, payload FROM dossier_proposals WHERE dossier_id = ? AND call_id = ?", (receipt.dossierId, receipt.callId))
                saved = cursor.fetchone()
                if not saved:
                    raise HTTPException(status_code=400, detail="Missing original historical state layout reference.")

                t_saved = json.loads(saved["target"]) if isinstance(saved["target"], str) else saved["target"]
                p_saved = json.loads(saved["payload"]) if isinstance(saved["payload"], str) else saved["payload"]

                expected_digest = compute_proposal_digest(saved["call_id"], saved["action"], t_saved, p_saved)
                if receipt.proposalDigest != expected_digest or receipt.action != saved["action"]:
