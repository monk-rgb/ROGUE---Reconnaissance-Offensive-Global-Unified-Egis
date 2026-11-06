"""Visual Forensics HTTP routes, dispatched from the ROUGE service Handler.

Reuses the existing session model: calls must carry an authorised officer session
(the same Bearer token + X-NSP headers used by every other ROUGE API route).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import sqlite3
import time
import uuid
from typing import Any

from early_warning_service import (
    DB_PATH, CASE_STAFF_TYPES, audit_event, clean_text,
)
import vf_image

VF_UPLOAD_LIMIT_BYTES = vf_image.VF_MAX_UPLOAD_BYTES
VF_ALLOWED_TYPES = {"/api/vf/upload"}
VF_JSON_TYPE_LIMIT = 256 * 1024


def _image_json(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0], "filename": row[1], "mime": row[2], "byteSize": row[3],
        "sha256": row[4], "width": row[5], "height": row[6], "format": row[7],
        "exif": json.loads(row[8]), "quality": json.loads(row[9]) if row[9] else None,
        "metadataFlags": json.loads(row[10]) if row[10] else None,
        "uploadedBy": row[11], "uploadedAt": int(row[12] * 1000), "caseRef": row[13],
    }


def _finding_json(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0], "imageId": row[1], "category": row[2], "title": row[3],
        "description": row[4], "box": json.loads(row[5]), "method": row[6], "source": row[7],
        "confidence": row[8], "confidenceLabel": row[9], "limitations": row[10],
        "alternatives": row[11], "reviewStatus": row[12],
        "analystNotes": json.loads(row[13]), "createdAt": int(row[14] * 1000),
        "updatedAt": int(row[15] * 1000), "updatedBy": row[16],
    }


def _derivative_json(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0], "imageId": row[1], "kind": row[2], "settings": json.loads(row[3]),
        "sha256": row[4], "byteSize": row[5], "width": row[6], "height": row[7],
        "createdBy": row[8], "createdAt": int(row[9] * 1000),
    }


def _annotation_json(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0], "imageId": row[1], "kind": row[2], "label": row[3], "note": row[4],
        "box": json.loads(row[5]), "createdBy": row[6], "createdAt": int(row[7] * 1000),
    }


def _get_image_row(image_id: str, who: str | None = None) -> tuple[Any, ...] | None:
    """Fetch an image record. When `who` is None the caller has already been authenticated."""
    connection = sqlite3.connect(DB_PATH, timeout=5)
    try:
        return connection.execute(
            "SELECT id, filename, mime, byte_size, sha256, width, height, format, exif_json, "
            "quality_json, metadata_flags_json, uploaded_by, uploaded_epoch, case_ref "
            "FROM vf_images WHERE id=? AND (? IS NULL OR uploaded_by=?)", (image_id, who, who)).fetchone()
    finally:
        connection.close()


def _save_image_record(who: str, filename: str, mime: str, sha256: str, width: int,
                       height: int, fmt: str, exif: dict[str, Any], quality: dict[str, Any],
                       flags: dict[str, Any], case_ref: str) -> dict[str, Any]:
    image_id = f"VF-{uuid.uuid4().hex[:10].upper()}"
    now = time.time()
    with vf_image._VF_LOCK:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            existing = connection.execute(
                "SELECT id FROM vf_images WHERE sha256=? AND uploaded_by=?", (sha256, who)).fetchone()
            if existing:
                image_id = existing[0]
            else:
                connection.execute(
                    """INSERT INTO vf_images (id, filename, mime, byte_size, sha256, width, height,
                       format, exif_json, quality_json, metadata_flags_json, uploaded_by,
                       uploaded_epoch, case_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (image_id, filename, mime, vf_image._evidence_dir().joinpath(f"{sha256}.bin").stat().st_size,
                     sha256, width, height, fmt, json.dumps(exif, ensure_ascii=False),
                     json.dumps(quality), json.dumps(flags), who, now, case_ref))
            connection.commit()
        finally:
            connection.close()
    return {"id": image_id, "filename": filename, "mime": mime, "byteSize":
            vf_image._evidence_dir().joinpath(f"{sha256}.bin").stat().st_size,
            "sha256": sha256, "width": width, "height": height, "format": fmt,
            "exif": exif, "quality": quality, "metadataFlags": flags,
            "uploadedBy": who, "uploadedAt": int(now * 1000), "caseRef": case_ref}


def _reject(handler, status: int, message: str) -> None:
    handler._json(status, {"error": message})


def _parse_upload_body(handler) -> tuple[list[dict[str, Any]] | None, str]:
    content_type = handler.headers.get("Content-Type", "")
    boundary_token = None
    if "multipart/form-data" in content_type:
        boundary = content_type.split("boundary=")[-1].strip('"').encode("latin-1")
        length = int(handler.headers.get("Content-Length", "0"))
        if length <= 0 or length > VF_UPLOAD_LIMIT_BYTES + 4096:
            return None, f"Upload exceeds the {VF_UPLOAD_LIMIT_BYTES // (1024*1024)} MB per-request limit."
        body = handler.rfile.read(length)
        parts = body.split(b"--" + boundary)
        files: list[dict[str, Any]] = []
        case_ref = "—"
        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            headers_blob, _, content = part.partition(b"\r\n\r\n")
            content = content.rstrip(b"\r\n")
            disposition = headers_blob.decode("latin-1", "replace")
            name_field = "name=\""
            if 'name="caseRef"' in disposition:
                case_ref = clean_text(content.decode("utf-8", "replace"), 100) or "—"
                continue
            filename_start = disposition.find('filename="')
            if filename_start == -1:
                continue
            filename = disposition[filename_start + 10:disposition.find('"', filename_start + 10)]
            files.append({"filename": filename, "data": content})
        return {"files": files, "caseRef": case_ref}, ""
    return None, "Upload must use multipart/form-data."


def handle_vf_get(handler, path: str) -> bool:
    """Return True if the path was handled."""
    if handler._require_case_staff() is None:
        return True
    query = handler.path
    if path == "/api/vf/images":
        who = handler._who()
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            rows = connection.execute(
                "SELECT id, filename, mime, byte_size, sha256, width, height, format, exif_json, "
                "quality_json, metadata_flags_json, uploaded_by, uploaded_epoch, case_ref "
                "FROM vf_images WHERE uploaded_by=? ORDER BY uploaded_epoch DESC", (who,)).fetchall()
        finally:
            connection.close()
        handler._json(200, {"images": [_image_json(row) for row in rows]})
        return True

    image_id = None
    suffix = ""
    for prefix in ("/api/vf/image/", "/api/vf/findings/", "/api/vf/derivatives/", "/api/vf/annotations/"):
        if path.startswith(prefix):
            image_id = path[len(prefix):]
            suffix = prefix
            break
    if image_id is None:
        return False

    if "/" in image_id:
        image_id, action = image_id.split("/", 1)
    else:
        action = ""

    # The analyst identity must come from the authenticated session: for <img> loads the
    # service number arrives only as a ?token= query parameter, so handler._who() would
    # be "UNKNOWN" and every viewer request would miss its own record.
    session_official = handler._session_official()
    who = session_official[0] if session_official else handler._who()
    row = _get_image_row(image_id)
    if row is None:
        _reject(handler, 404, "No forensic image with that ID for this analyst.")
        return True

    if suffix == "/api/vf/image/" and action == "":
        # Serve the immutable original with correct MIME.
        try:
            data = vf_image.load_evidence(row[4])
        except (ValueError, OSError) as exc:
            _reject(handler, 500, f"Evidence read failed: {exc}")
            return True
        handler.send_response(200)
        handler.send_header("Content-Type", row[2])
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header("X-VF-SHA256", row[4])
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(data)
        return True

    if suffix == "/api/vf/findings/" and action == "":
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            rows = connection.execute(
                "SELECT id, image_id, category, title, description, box_json, method, source, "
                "confidence, confidence_label, limitations, alternatives, review_status, "
                "analyst_notes_json, created_epoch, updated_epoch, updated_by "
                "FROM vf_findings WHERE image_id=? ORDER BY created_epoch ASC, rowid ASC", (image_id,)).fetchall()
        finally:
            connection.close()
        handler._json(200, {"findings": [_finding_json(item) for item in rows]})
        return True

    if suffix == "/api/vf/derivatives/":
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            rows = connection.execute(
                "SELECT id, image_id, kind, settings_json, sha256, byte_size, width, height, "
                "created_by, created_epoch FROM vf_derivatives WHERE image_id=? AND created_by=? "
                "ORDER BY created_epoch DESC", (image_id, who)).fetchall()
        finally:
            connection.close()
        if action.startswith("serve/"):
            derivative_id = action.removeprefix("serve/")
            data = None
            for item in rows:
                if item[0] == derivative_id:
                    data = vf_image.load_evidence(item[4])
                    break
            if data is None:
                _reject(handler, 404, "No such derivative.")
                return True
            handler.send_response(200)
            handler.send_header("Content-Type", "image/png")
            handler.send_header("Content-Length", str(len(data)))
            handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            handler.wfile.write(data)
            return True
        handler._json(200, {"derivatives": [_derivative_json(item) for item in rows]})
        return True

    if suffix == "/api/vf/annotations/" and action == "":
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            rows = connection.execute(
                "SELECT id, image_id, kind, label, note, box_json, created_by, created_epoch "
                "FROM vf_annotations WHERE image_id=? ORDER BY created_epoch DESC", (image_id,)).fetchall()
        finally:
            connection.close()
        handler._json(200, {"annotations": [_annotation_json(item) for item in rows]})
        return True

    _reject(handler, 404, "Unknown Visual Forensics route.")
    return True


def handle_vf_post(handler, path: str, payload: dict[str, Any] | None) -> bool:
    if handler._require_case_staff() is None:
        return True
    session_official = handler._session_official()
    who = session_official[0] if session_official else handler._who()
    reason = clean_text(str((payload or {}).get("reason", "Visual forensics analysis")), 400)
    case_ref = clean_text(str((payload or {}).get("caseRef", "—")), 100) or "—"

    if path == "/api/vf/upload":
        parsed, error = _parse_upload_body(handler)
        if error:
            _reject(handler, 400 if "limit" in error else 415, error)
            return True
        assert parsed is not None
        files = parsed["files"]
        if not files:
            _reject(handler, 400, "No image file was included in the upload.")
            return True
        if len(files) > 1:
            _reject(handler, 400, "Only one picture can be analysed at a time. Upload a single image.")
            return True
        results, errors = [], []
        for item in files[:1]:
            filename = clean_text(item["filename"], 200) or "untitled"
            data = item["data"]
            if not data:
                errors.append(f"{filename}: file is empty.")
                continue
            if len(data) > VF_UPLOAD_LIMIT_BYTES:
                errors.append(f"{filename}: file exceeds the {VF_UPLOAD_LIMIT_BYTES // (1024*1024)} MB limit.")
                continue
            try:
                img = vf_image._decode_image(data)
            except ValueError as exc:
                errors.append(f"{filename}: {exc}")
                continue
            fmt = vf_image._format_ok(img)
            if not fmt:
                errors.append(f"{filename}: unsupported format {(img.format or 'unknown').upper()}. "
                              "JPEG, PNG, WebP and TIFF are accepted.")
                continue
            mime = vf_image.VF_MIME_BY_FORMAT[fmt]
            sha256, _ = vf_image.store_evidence(data)
            img_normalised = vf_image._normalise_orientation(img)
            metadata = vf_image.extract_metadata(data, img)
            quality = vf_image.quality_analysis(img_normalised)
            flags = vf_image.integrity_check(img_normalised, metadata)
            width, height = img.size
            record = _save_image_record(who, filename, mime, sha256, width, height, fmt,
                                        metadata, quality, flags, parsed["caseRef"])
            results.append(record)
            audit_event(who, "VISUAL FORENSICS UPLOAD",
                        reason, parsed["caseRef"],
                        {"imageId": record["id"], "sha256": sha256, "filename": filename,
                         "bytes": len(data), "dimensions": [width, height]})
        response: dict[str, Any] = {"images": results}
        if errors:
            response["errors"] = errors
        handler._json(201, response)
        return True

    if path.startswith("/api/vf/image/") and path.endswith("/delete"):
        image_id = path.removeprefix("/api/vf/image/").removesuffix("/delete")
        row = _get_image_row(image_id, who)
        if row is None:
            _reject(handler, 404, "No forensic image with that ID for this analyst.")
            return True
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            connection.execute("DELETE FROM vf_findings WHERE image_id=?", (image_id,))
            connection.execute("DELETE FROM vf_annotations WHERE image_id=?", (image_id,))
            connection.execute("DELETE FROM vf_derivatives WHERE image_id=?", (image_id,))
            connection.execute("DELETE FROM vf_images WHERE id=? AND uploaded_by=?", (image_id, who))
            connection.commit()
        finally:
            connection.close()
        audit_event(who, "VISUAL FORENSICS IMAGE REMOVED", reason, case_ref,
                    {"imageId": image_id, "filename": row[1], "sha256": row[4]})
        handler._json(200, {"ok": True, "imageId": image_id})
        return True

    if path.startswith("/api/vf/analyse/"):
        image_id = path.removeprefix("/api/vf/analyse/")
        row = _get_image_row(image_id, who)
        if row is None:
            _reject(handler, 404, "No forensic image with that ID for this analyst.")
            return True
        try:
            result = vf_image.run_full_analysis(row)
        except (ValueError, RuntimeError) as exc:
            _reject(handler, 500, f"Analysis failed: {exc}")
            return True
        except Exception as exc:  # unexpected detector errors must not fabricate results
            _reject(handler, 500, f"Analysis failed unexpectedly: {exc}")
            return True
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            connection.execute("UPDATE vf_images SET quality_json=?, metadata_flags_json=? WHERE id=?",
                               (json.dumps(result["quality"]), json.dumps(vf_image.integrity_check(
                                   vf_image._normalise_orientation(vf_image._decode_image(
                                       vf_image.load_evidence(row[4]))), result["metadata"])), image_id))
            connection.commit()
        finally:
            connection.close()
        audit_event(who, "VISUAL FORENSICS ANALYSIS RUN", reason, case_ref,
                    {"imageId": image_id, "findings": len(result["findings"])})
        handler._json(200, result)
        return True

    if path.startswith("/api/vf/findings/") and path.endswith("/review"):
        image_id = path.removeprefix("/api/vf/findings/").removesuffix("/review")
        image_id, _, finding_id = image_id.rpartition("/")
        row = _get_image_row(image_id, who)
        if row is None:
            _reject(handler, 404, "No forensic image with that ID for this analyst.")
            return True
        status = clean_text(str(payload.get("reviewStatus", "")), 40)
        note = clean_text(str(payload.get("note", "")), 800)
        if status not in vf_image.VF_REVIEW_STATUSES:
            _reject(handler, 400, f"reviewStatus must be one of {sorted(vf_image.VF_REVIEW_STATUSES)}.")
            return True
        if status == "Confirmed observation" and not note:
            _reject(handler, 400, "Confirming an observation requires a note recording what you verified.")
            return True
        if status in {"Rejected", "Inconclusive"} and not note:
            _reject(handler, 400, "Rejecting or marking inconclusive requires the reason.")
            return True
        now = time.time()
        with vf_image._VF_LOCK:
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                existing = connection.execute(
                    "SELECT review_status, analyst_notes_json FROM vf_findings WHERE id=? AND image_id=?",
                    (finding_id, image_id)).fetchone()
                if not existing:
                    _reject(handler, 404, "Finding not found.")
                    return True
                notes = json.loads(existing[1])
                notes.append({"by": who, "at": int(now * 1000), "note": note,
                              "action": f"status → {status}"})
                connection.execute(
                    "UPDATE vf_findings SET review_status=?, analyst_notes_json=?, updated_epoch=?, updated_by=? "
                    "WHERE id=?", (status, json.dumps(notes, ensure_ascii=False), now, who, finding_id))
                connection.commit()
            finally:
                connection.close()
        audit_event(who, f"VISUAL FORENSICS FINDING {status.upper()}", note or reason,
                    case_ref, {"imageId": image_id, "findingId": finding_id})
        handler._json(200, {"ok": True, "findingId": finding_id, "reviewStatus": status})
        return True

    if path.startswith("/api/vf/findings/") and path.endswith("/note"):
        image_id = path.removeprefix("/api/vf/findings/").removesuffix("/note")
        image_id, _, finding_id = image_id.rpartition("/")
        row = _get_image_row(image_id, who)
        if row is None:
            _reject(handler, 404, "No forensic image with that ID for this analyst.")
            return True
        note = clean_text(str(payload.get("note", "")), 800)
        if not note:
            _reject(handler, 400, "A note is required.")
            return True
        now = time.time()
        with vf_image._VF_LOCK:
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                existing = connection.execute(
                    "SELECT analyst_notes_json FROM vf_findings WHERE id=? AND image_id=?",
                    (finding_id, image_id)).fetchone()
                if not existing:
                    _reject(handler, 404, "Finding not found.")
                    return True
                notes = json.loads(existing[0])
                notes.append({"by": who, "at": int(now * 1000), "note": note, "action": "comment"})
                connection.execute(
                    "UPDATE vf_findings SET analyst_notes_json=?, updated_epoch=?, updated_by=? WHERE id=?",
                    (json.dumps(notes, ensure_ascii=False), now, who, finding_id))
                connection.commit()
            finally:
                connection.close()
        audit_event(who, "VISUAL FORENSICS FINDING NOTE", note, case_ref,
                    {"imageId": image_id, "findingId": finding_id})
        handler._json(200, {"ok": True})
        return True

    if path.startswith("/api/vf/annotations/add/"):
        image_id = path.removeprefix("/api/vf/annotations/add/")
        row = _get_image_row(image_id, who)
        if row is None:
            _reject(handler, 404, "No forensic image with that ID for this analyst.")
            return True
        box = payload.get("box")
        label = clean_text(str(payload.get("label", "")), 120)
        note = clean_text(str(payload.get("note", "")), 600)
        kind = clean_text(str(payload.get("kind", "manual")), 30)
        if (not isinstance(box, list) or len(box) != 4
                or not all(isinstance(v, (int, float)) for v in box)):
            _reject(handler, 400, "box must be [x, y, width, height] in image coordinates.")
            return True
        if not label:
            _reject(handler, 400, "A label is required.")
            return True
        annotation_id = f"VA-{uuid.uuid4().hex[:10].upper()}"
        now = time.time()
        with vf_image._VF_LOCK:
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    "INSERT INTO vf_annotations (id, image_id, kind, label, note, box_json, created_by, created_epoch) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (annotation_id, image_id, kind, label, note, json.dumps(box), who, now))
                connection.commit()
            finally:
                connection.close()
        audit_event(who, "VISUAL FORENSICS ANNOTATION ADDED", note or label, case_ref,
                    {"imageId": image_id, "annotationId": annotation_id})
        handler._json(201, {"ok": True, "annotationId": annotation_id})
        return True

    if path.startswith("/api/vf/enhance/"):
        image_id = path.removeprefix("/api/vf/enhance/")
        row = _get_image_row(image_id, who)
        if row is None:
            _reject(handler, 404, "No forensic image with that ID for this analyst.")
            return True
        settings = payload.get("settings") or {}
        if not isinstance(settings, dict):
            _reject(handler, 400, "settings must be an object.")
            return True
        allowed = {"denoise", "sharpen", "brightness", "contrast", "shadows", "highlights",
                   "gamma", "upscale"}
        clean_settings = {}
        for key, value in settings.items():
            if key not in allowed:
                continue
            try:
                clean_settings[key] = max(-100.0, min(100.0, float(value)))
            except (TypeError, ValueError):
                continue
        clean_settings["upscale"] = int(max(1, min(4, clean_settings.get("upscale", 1))))
        for key in ("denoise", "sharpen"):
            clean_settings[key] = int(max(0, min(10, clean_settings.get(key, 0))))
        try:
            img = vf_image._normalise_orientation(vf_image._decode_image(vf_image.load_evidence(row[4])))
            enhanced, applied = vf_image.enhance(img, clean_settings)
        except (ValueError, RuntimeError) as exc:
            _reject(handler, 500, f"Enhancement failed: {exc}")
            return True
        buf = io.BytesIO()
        enhanced.save(buf, format="PNG")
        processed = buf.getvalue()
        processed_sha = hashlib.sha256(processed).hexdigest()
        vf_image.store_evidence(processed)
        derivative_id = f"VD-{uuid.uuid4().hex[:10].upper()}"
        now = time.time()
        with vf_image._VF_LOCK:
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    """INSERT INTO vf_derivatives (id, image_id, kind, settings_json, sha256,
                       byte_size, width, height, created_by, created_epoch)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (derivative_id, image_id, "enhanced", json.dumps({
                        **clean_settings, "applied": applied,
                        "superresolution": vf_image.superresolution_status(),
                        "warning": ("Enhancement does not recover information that was never captured. "
                                    "Reconstructed or AI-generated pixels are never written into the original evidence record."),
                    }), processed_sha, len(processed), enhanced.width, enhanced.height, who, now))
                connection.commit()
            finally:
                connection.close()
        audit_event(who, "VISUAL FORENSICS IMAGE ENHANCED", reason, case_ref,
                    {"imageId": image_id, "derivativeId": derivative_id,
                     "originalSha256": row[4], "processedSha256": processed_sha,
                     "settings": clean_settings})
        handler._json(201, {
            "derivativeId": derivative_id, "settings": clean_settings, "applied": applied,
            "originalSha256": row[4], "processedSha256": processed_sha,
            "width": enhanced.width, "height": enhanced.height,
            "processedImage": "data:image/png;base64," + base64.b64encode(processed).decode("ascii"),
            "superresolution": vf_image.superresolution_status(),
        })
        return True

    if path == "/api/vf/compare":
        ids = payload.get("imageIds")
        if not isinstance(ids, list) or len(ids) < 2 or not all(isinstance(v, str) for v in ids):
            _reject(handler, 400, "imageIds must list at least two images.")
            return True
        rows = []
        for image_id in ids[:4]:
            row = _get_image_row(image_id, who)
            if row is None:
                _reject(handler, 404, f"No forensic image with ID {image_id} for this analyst.")
                return True
            rows.append(row)
        details = [_image_json(row) for row in rows]
        # Metadata comparison
        comparison: dict[str, Any] = {"images": details, "metadataDiffs": []}
        fields = ["format", "width", "height", "sha256", "byteSize"]
        base = details[0]
        for detail in details[1:]:
            diffs = {}
            for field in fields:
                if base.get(field) != detail.get(field):
                    diffs[field] = [base.get(field), detail.get(field)]
            base_exif = base["exif"].get("exif", {})
            other_exif = detail["exif"].get("exif", {})
            for key in sorted(set(base_exif) | set(other_exif)):
                if base_exif.get(key) != other_exif.get(key):
                    diffs[f"exif.{key}"] = [base_exif.get(key), other_exif.get(key)]
            comparison["metadataDiffs"].append({"against": detail["id"], "diffs": diffs})
        audit_event(who, "VISUAL FORENSICS COMPARISON RUN", reason, case_ref,
                    {"imageIds": [detail["id"] for detail in details]})
        handler._json(200, comparison)
        return True

    if path == "/api/vf/report":
        ids = payload.get("imageIds")
        if not isinstance(ids, list) or not ids:
            _reject(handler, 400, "imageIds must list at least one image.")
            return True
        reviewer = clean_text(str(payload.get("reviewer", "")), 80)
        reviewer_notes = clean_text(str(payload.get("reviewerNotes", "")), 2000)
        rows = []
        for image_id in ids[:4]:
            row = _get_image_row(image_id, who)
            if row is None:
                _reject(handler, 404, f"No forensic image with ID {image_id} for this analyst.")
                return True
            rows.append(row)
        report_id = f"VFR-{uuid.uuid4().hex[:8].upper()}"
        sections = []
        for row in rows:
            image_id = row[0]
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                findings = connection.execute(
                    "SELECT id, image_id, category, title, description, box_json, method, source, "
                    "confidence, confidence_label, limitations, alternatives, review_status, "
                    "analyst_notes_json, created_epoch, updated_epoch, updated_by "
                    "FROM vf_findings WHERE image_id=? ORDER BY created_epoch ASC, rowid ASC", (image_id,)).fetchall()
                derivatives = connection.execute(
                    "SELECT id, image_id, kind, settings_json, sha256, byte_size, width, height, "
                    "created_by, created_epoch FROM vf_derivatives WHERE image_id=? AND created_by=?",
                    (image_id, who)).fetchall()
            finally:
                connection.close()
            sections.append({
                "image": _image_json(row),
                "findings": [_finding_json(item) for item in findings],
                "derivatives": [_derivative_json(item) for item in derivatives],
            })
        report_payload = {
            "reportId": report_id,
            "caseRef": case_ref,
            "analyst": who,
            "reviewer": reviewer or "(no separate reviewer recorded)",
            "generatedAt": int(time.time() * 1000),
            "sections": sections,
            "reviewerNotes": reviewer_notes,
            "limitationsStatement": (
                "This report combines automated processing output with human review. Findings marked "
                "'AI/processing' are algorithmic interpretations and are NOT forensic evidence. "
                "'Confirmed observation' means a human reviewer verified the stated visual observation; "
                "it does not prove any AI hypothesis. Missing metadata is not evidence of tampering. "
                "Metadata timestamps may be wrong and carry timezone uncertainty. Enhancement does not recover "
                "information that was never captured, and reconstructed pixels are never used as identity evidence. "
                "This prototype makes no claim of legal admissibility or chain-of-custody compliance."),
            "admissibility": "No legal-admissibility or chain-of-custody claim is made; no validated procedures are implemented for those purposes.",
        }
        with vf_image._VF_LOCK:
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    "INSERT INTO vf_reports (id, case_ref, analyst, image_ids_json, payload_json, created_epoch) "
                    "VALUES (?,?,?,?,?,?)",
                    (report_id, case_ref, who, json.dumps(ids[:4]),
                     json.dumps(report_payload, ensure_ascii=False), time.time()))
                connection.commit()
            finally:
                connection.close()
        audit_event(who, "VISUAL FORENSICS REPORT GENERATED", reason, case_ref,
                    {"reportId": report_id, "imageIds": ids[:4]})
        handler._json(201, {"report": report_payload})
        return True

    _reject(handler, 404, "Unknown Visual Forensics route.")
    return True
