"""Temporary video upload and license-plate OCR search."""

from __future__ import annotations

import base64
import email.policy
import email.parser
import math
import os
import re
import shutil
import tempfile
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from early_warning_service import audit_event

try:
    import cv2
except ImportError:  # pragma: no cover - capability is reported to the user
    cv2 = None

try:
    import pytesseract
except ImportError:  # pragma: no cover - capability is reported to the user
    pytesseract = None

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_VIDEO_SECONDS = 2 * 60 * 60
MAX_ANALYZED_FRAMES = 20_000
MAX_FRAME_PIXELS = 16_000_000
MAX_RESULTS = 5
JOB_TTL_SECONDS = 60 * 60
ALLOWED_EXTENSIONS = {
    ".264", ".avi", ".dav", ".h264", ".m4v", ".mkv", ".mov", ".mp4", ".mpeg", ".mpg", ".webm",
}
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.RLock()
_WORKERS = ThreadPoolExecutor(max_workers=1, thread_name_prefix="plate-search")
_PLATE_CASCADE: Any = None
_PLATE_CASCADE_CHECKED = False


def normalize_plate(value: str) -> str:
    """Remove separators commonly used in plate numbers."""
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def _capability() -> tuple[bool, str]:
    if cv2 is None:
        return False, "OpenCV is missing. Install the optional Visual Forensics dependencies."
    if pytesseract is None:
        return False, "The pytesseract Python package is missing. Install requirements-vf.txt."
    if not shutil.which("tesseract") and os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        installed_engine = Path(program_files) / "Tesseract-OCR" / "tesseract.exe"
        if installed_engine.is_file():
            pytesseract.pytesseract.tesseract_cmd = str(installed_engine)
    try:
        pytesseract.get_tesseract_version()
    except pytesseract.TesseractNotFoundError:
        return False, "The Tesseract OCR engine is not installed or is not on PATH."
    except (OSError, pytesseract.TesseractError) as exc:
        return False, f"Tesseract could not start: {exc}"
    return True, ""


def _get_plate_cascade() -> Any:
    global _PLATE_CASCADE, _PLATE_CASCADE_CHECKED
    if _PLATE_CASCADE_CHECKED:
        return _PLATE_CASCADE
    _PLATE_CASCADE_CHECKED = True
    if cv2 is None:
        return None
    cascade_path = Path(cv2.__file__).resolve().parent / "data" / "haarcascade_license_plate_rus_16stages.xml"
    if cascade_path.is_file():
        cascade = cv2.CascadeClassifier(str(cascade_path))
        if not cascade.empty():
            _PLATE_CASCADE = cascade
    return _PLATE_CASCADE


def _ocr_candidates(image: Any, target: str, psm: int) -> list[float]:
    config = (
        f"--oem 3 --psm {psm} "
        "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
    data = pytesseract.image_to_data(
        image, config=config, output_type=pytesseract.Output.DICT
    )
    texts = data.get("text", [])
    confidences = data.get("conf", [])
    groups: dict[tuple[str, str, str, str], list[tuple[str, float]]] = {}
    found: list[float] = []
    for index, raw_text in enumerate(texts):
        text = normalize_plate(str(raw_text))
        if not text:
            continue
        try:
            confidence = float(confidences[index])
        except (IndexError, TypeError, ValueError):
            confidence = -1
        if text == target:
            found.append(confidence)
        key = tuple(str(data.get(field, [""] * len(texts))[index])
                    for field in ("page_num", "block_num", "par_num", "line_num"))
        groups.setdefault(key, []).append((text, confidence))

    for words in groups.values():
        for start in range(len(words)):
            combined = ""
            group_confidence = 100.0
            for end in range(start, min(start + 3, len(words))):
                combined += words[end][0]
                group_confidence = min(group_confidence, words[end][1])
                if combined == target and end > start:
                    found.append(group_confidence)
    return found


def _frame_matches(frame: Any, target: str) -> list[float]:
    source_frame = frame
    height, width = frame.shape[:2]
    scale = min(1.0, 1920 / max(width, height))
    if scale < 1:
        frame = cv2.resize(frame, (round(width * scale), round(height * scale)),
                           interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    candidates = [frame]
    cascade = _get_plate_cascade()
    if cascade is not None:
        regions = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4,
                                           minSize=(40, 12))
        for x, y, region_width, region_height in regions[:20]:
            padding_x = max(4, round(region_width * 0.1))
            padding_y = max(4, round(region_height * 0.2))
            left = max(0, x - padding_x)
            top = max(0, y - padding_y)
            right = min(frame.shape[1], x + region_width + padding_x)
            bottom = min(frame.shape[0], y + region_height + padding_y)
            candidates.append(frame[top:bottom, left:right])

    matches: list[float] = []
    for index, candidate in enumerate(candidates):
        candidate_matches = _ocr_candidates(candidate, target, 11 if index == 0 else 7)
        if not candidate_matches and index == 0:
            candidate_matches = _ocr_candidates(candidate, target, 7)
        matches.extend(candidate_matches)
    if matches:
        return matches

    source_height, source_width = source_frame.shape[:2]
    tile_height = max(1, round(source_height * 0.55))
    tile_width = max(1, round(source_width * 0.55))
    top_positions = tuple(dict.fromkeys((0, source_height - tile_height)))
    left_positions = tuple(dict.fromkeys((0, source_width - tile_width)))
    for top in top_positions:
        for left in left_positions:
            tile = source_frame[top:top + tile_height, left:left + tile_width]
            tile_matches = _ocr_candidates(tile, target, 11)
            if not tile_matches:
                tile_matches = _ocr_candidates(tile, target, 7)
            if not tile_matches:
                enlarged = cv2.resize(
                    tile,
                    (tile.shape[1] * 2, tile.shape[0] * 2),
                    interpolation=cv2.INTER_CUBIC,
                )
                tile_matches = _ocr_candidates(enlarged, target, 11)
                if not tile_matches:
                    tile_matches = _ocr_candidates(enlarged, target, 7)
            if tile_matches:
                return tile_matches
    return []


def _job_snapshot(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": job["id"],
        "status": job["status"],
        "progress": job["progress"],
        "processedFrames": job["processedFrames"],
        "totalFrames": job["totalFrames"],
        "plate": job["plate"],
        "location": job["location"],
        "matches": job["matches"] if job["status"] == "complete" else [],
        "error": job["error"],
    }


def _scan_video(job_id: str, video_path: str) -> None:
    capture = None
    try:
        capture = cv2.VideoCapture(video_path)
        if not capture.isOpened():
            raise ValueError("The uploaded file could not be opened as a supported video.")
        fps = float(capture.get(cv2.CAP_PROP_FPS))
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
        if not math.isfinite(fps) or fps <= 0 or frame_count <= 0:
            raise ValueError("The video does not report a usable frame rate or frame count.")
        if width <= 0 or height <= 0 or width * height > MAX_FRAME_PIXELS:
            raise ValueError("Video frames must be no larger than 16 megapixels.")
        duration = frame_count / fps
        if duration > MAX_VIDEO_SECONDS:
            raise ValueError("Videos longer than two hours are not supported.")
        frame_step = max(1, math.ceil(fps / 4), math.ceil(frame_count / MAX_ANALYZED_FRAMES))
        total_samples = math.ceil(frame_count / frame_step)
        target = _JOBS[job_id]["normalizedPlate"]
        processed = 0
        next_allowed_match = -1.0
        matches: list[dict[str, Any]] = []
        index = 0
        with _JOBS_LOCK:
            _JOBS[job_id]["totalFrames"] = total_samples
            _JOBS[job_id]["status"] = "scanning"
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            if index % frame_step == 0:
                timestamp = index / fps
                confidences = _frame_matches(frame, target)
                processed += 1
                if confidences and timestamp >= next_allowed_match and len(matches) < MAX_RESULTS:
                    height, width = frame.shape[:2]
                    output_scale = min(1.0, 960 / max(width, height))
                    preview = frame
                    if output_scale < 1:
                        preview = cv2.resize(frame, (round(width * output_scale), round(height * output_scale)),
                                             interpolation=cv2.INTER_AREA)
                    encoded_ok, encoded = cv2.imencode(
                        ".jpg", preview, [int(cv2.IMWRITE_JPEG_QUALITY), 82]
                    )
                    matches.append({
                        "timestampSeconds": round(timestamp, 2),
                        "timestamp": time.strftime("%H:%M:%S", time.gmtime(timestamp)),
                        "ocrConfidence": round(max(0.0, max(confidences)), 1),
                        "frameJpeg": base64.b64encode(encoded.tobytes()).decode("ascii") if encoded_ok else "",
                    })
                    next_allowed_match = timestamp + 3
                with _JOBS_LOCK:
                    job = _JOBS[job_id]
                    job["processedFrames"] = processed
                    job["progress"] = min(99, round(index * 100 / frame_count))
                    job["matches"] = matches.copy()
            index += 1
        if index == 0:
            raise ValueError("The video contains no readable frames.")
        with _JOBS_LOCK:
            job = _JOBS[job_id]
            job["status"] = "complete"
            job["progress"] = 100
            job["processedFrames"] = processed
            job["totalFrames"] = total_samples
            job["matches"] = matches
            job["completedAt"] = time.time()
        audit_event(job["owner"], "NUMBER PLATE VIDEO SEARCH COMPLETED",
                    "Completed an authorized video OCR search", "—",
                    {"jobId": job_id, "matchCount": len(matches)})
    except Exception as exc:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job:
                job["status"] = "failed"
                job["error"] = str(exc)
                job["completedAt"] = time.time()
        if not isinstance(exc, ValueError):
            traceback.print_exc()
    finally:
        if capture is not None:
            capture.release()
        try:
            os.remove(video_path)
        except FileNotFoundError:
            pass
        except OSError:
            traceback.print_exc()
        expiry = threading.Timer(JOB_TTL_SECONDS, _expire_job, args=(job_id,))
        expiry.daemon = True
        expiry.start()


def _cleanup_jobs() -> None:
    cutoff = time.time() - JOB_TTL_SECONDS
    with _JOBS_LOCK:
        expired = [
            job_id for job_id, job in _JOBS.items()
            if job["status"] in {"complete", "failed"} and job["completedAt"] < cutoff
        ]
        for job_id in expired:
            _JOBS.pop(job_id, None)


def _expire_job(job_id: str) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job and job["status"] in {"complete", "failed"}:
            _JOBS.pop(job_id, None)


def _reject(handler: Any, status: int, message: str) -> None:
    handler._json(status, {"error": message})


class _MultipartStream:
    def __init__(self, handler: Any, content_length: int) -> None:
        self.handler = handler
        self.remaining = content_length
        self.buffer = bytearray()

    def _fill(self, minimum: int) -> None:
        while len(self.buffer) < minimum and self.remaining:
            chunk = self.handler.rfile.read(min(64 * 1024, self.remaining))
            if not chunk:
                raise ValueError("Upload ended before the multipart request was complete.")
            self.remaining -= len(chunk)
            self.buffer.extend(chunk)

    def _until(self, delimiter: bytes, max_bytes: int) -> bytes:
        while True:
            index = self.buffer.find(delimiter)
            if index >= 0:
                if index > max_bytes:
                    raise ValueError("Multipart headers exceed the allowed size.")
                result = bytes(self.buffer[:index])
                del self.buffer[:index + len(delimiter)]
                return result
            if len(self.buffer) > max_bytes or not self.remaining:
                raise ValueError("Multipart headers are invalid or exceed the allowed size.")
            self._fill(len(self.buffer) + 1)

    def _stream_part(self, marker: bytes, consume: Any) -> bool:
        while True:
            index = self.buffer.find(marker)
            if index >= 0:
                if index:
                    consume(bytes(self.buffer[:index]))
                del self.buffer[:index + len(marker)]
                self._fill(2)
                suffix = bytes(self.buffer[:2])
                del self.buffer[:2]
                if suffix == b"\r\n":
                    return False
                if suffix != b"--":
                    raise ValueError("Multipart boundary is malformed.")
                if bytes(self.buffer).strip(b"\r\n"):
                    raise ValueError("Unexpected content after the multipart closing boundary.")
                self.buffer.clear()
                while self.remaining:
                    chunk = self.handler.rfile.read(min(64 * 1024, self.remaining))
                    if not chunk:
                        raise ValueError("Upload ended before the multipart request was complete.")
                    self.remaining -= len(chunk)
                    if chunk.strip(b"\r\n"):
                        raise ValueError("Unexpected content after the multipart closing boundary.")
                return True

            safe_length = len(self.buffer) - len(marker) + 1
            if safe_length > 0:
                consume(bytes(self.buffer[:safe_length]))
                del self.buffer[:safe_length]
            if not self.remaining:
                raise ValueError("Multipart closing boundary was not found.")
            self._fill(len(self.buffer) + 1)


def _parse_video_multipart(
    handler: Any, content_length: int, boundary: str
) -> tuple[dict[str, str], str | None, str, str, int]:
    reader = _MultipartStream(handler, content_length)
    boundary_bytes = boundary.encode("latin-1")
    if not boundary_bytes or len(boundary_bytes) > 200:
        raise ValueError("Multipart boundary is invalid.")
    if reader._until(b"\r\n", 4096) != b"--" + boundary_bytes:
        raise ValueError("Multipart opening boundary is invalid.")

    fields: dict[str, str] = {}
    video_path: str | None = None
    filename = ""
    extension = ""
    video_size = 0
    parser = email.parser.BytesHeaderParser(policy=email.policy.default)
    final_boundary = False
    try:
        while not final_boundary:
            header_bytes = reader._until(b"\r\n\r\n", 16 * 1024)
            part_headers = parser.parsebytes(header_bytes + b"\r\n")
            name = part_headers.get_param("name", header="Content-Disposition")
            part_filename = part_headers.get_filename()
            if not isinstance(name, str):
                raise ValueError("An uploaded form field has no name.")

            file_handle = None
            field_bytes = bytearray()
            if part_filename is not None:
                if name != "video" or video_path is not None:
                    raise ValueError("Upload exactly one video file.")
                extension = Path(part_filename).suffix.casefold()
                if extension not in ALLOWED_EXTENSIONS:
                    raise ValueError("Choose MP4, MOV, AVI, MKV, MPEG, WebM, or Hikvision DAV/H.264 footage.")
                filename = Path(part_filename).name[:255]
                file_handle = tempfile.NamedTemporaryFile(
                    prefix="rouge-plate-", suffix=extension, delete=False
                )
                video_path = file_handle.name

            def consume(chunk: bytes) -> None:
                nonlocal video_size
                if file_handle is not None:
                    video_size += len(chunk)
                    if video_size > MAX_UPLOAD_BYTES:
                        raise ValueError("Video upload must be no larger than 200 MB.")
                    file_handle.write(chunk)
                elif name in {"plate", "location"}:
                    if len(field_bytes) + len(chunk) > 4096:
                        raise ValueError(f"The {name} field is too long.")
                    field_bytes.extend(chunk)

            try:
                final_boundary = reader._stream_part(b"\r\n--" + boundary_bytes, consume)
            finally:
                if file_handle is not None:
                    file_handle.close()
            if name in {"plate", "location"}:
                if name in fields:
                    raise ValueError(f"Provide the {name} field only once.")
                fields[name] = field_bytes.decode("utf-8", "replace").strip()
    except Exception:
        if video_path:
            try:
                os.remove(video_path)
            except FileNotFoundError:
                pass
        raise
    return fields, video_path, filename, extension, video_size


def handle_get(handler: Any, path: str) -> bool:
    if not path.startswith("/api/plate-search/"):
        return False
    if handler._require_case_staff() is None:
        return True
    if path == "/api/plate-search/capability":
        available, message = _capability()
        handler._json(200, {"available": available, "message": message})
        return True
    if path.startswith("/api/plate-search/jobs/"):
        job_id = path.removeprefix("/api/plate-search/jobs/")
        session_official = handler._session_official()
        if not session_official:
            _reject(handler, 401, "A valid officer session is required to view this search.")
            return True
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if not job:
                _reject(handler, 404, "Search job not found or expired.")
                return True
            if job["owner"] != session_official[0]:
                _reject(handler, 403, "This search job belongs to another officer.")
                return True
            snapshot = _job_snapshot(job)
        handler._json(200, {"job": snapshot})
        return True
    _reject(handler, 404, "Unknown number plate search route.")
    return True


def handle_post(handler: Any, path: str) -> bool:
    if path != "/api/plate-search":
        return False
    if handler._require_case_staff() is None:
        return True
    available, message = _capability()
    if not available:
        _reject(handler, 503, message)
        return True

    content_type = email.message.Message()
    content_type["Content-Type"] = handler.headers.get("Content-Type", "")
    boundary = content_type.get_param("boundary", header="Content-Type")
    if content_type.get_content_type() != "multipart/form-data" or not boundary:
        _reject(handler, 400, "Upload must use multipart/form-data.")
        return True
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        _reject(handler, 400, "Upload has an invalid Content-Length.")
        return True
    if length <= 0 or length > MAX_UPLOAD_BYTES + 1024 * 32:
        _reject(handler, 413, "Video upload must be no larger than 200 MB.")
        return True

    try:
        fields, video_path, filename, extension, video_size = _parse_video_multipart(
            handler, length, boundary
        )
    except ValueError as exc:
        status = 413 if "200 MB" in str(exc) else 400
        _reject(handler, status, str(exc))
        return True
    except OSError as exc:
        traceback.print_exc()
        _reject(handler, 500, f"Could not store the uploaded video temporarily: {exc}")
        return True

    def reject_upload(status: int, message: str) -> bool:
        if video_path:
            try:
                os.remove(video_path)
            except FileNotFoundError:
                pass
        _reject(handler, status, message)
        return True

    plate = fields.get("plate", "")
    location = fields.get("location", "")
    normalized_plate = normalize_plate(plate)
    if not 3 <= len(normalized_plate) <= 12 or not re.fullmatch(r"[A-Za-z0-9 -]+", plate):
        return reject_upload(400, "Enter a plate number containing 3 to 12 letters or digits.")
    if not location or len(location) > 160:
        return reject_upload(400, "Enter the footage location (up to 160 characters).")
    if not video_path or video_size <= 0:
        return reject_upload(400, "Choose a non-empty video file to search.")

    _cleanup_jobs()
    with _JOBS_LOCK:
        active_jobs = sum(job["status"] in {"queued", "scanning"} for job in _JOBS.values())
        if active_jobs >= 3:
            return reject_upload(429, "The video-search queue is full. Wait for a current search to finish.")
        job_id = f"PL-{uuid.uuid4().hex[:12].upper()}"
        who = handler._session_official()[0]
        now = time.time()
        _JOBS[job_id] = {
            "id": job_id, "owner": who, "plate": plate.strip(), "normalizedPlate": normalized_plate,
            "location": location, "status": "queued", "progress": 0, "processedFrames": 0,
            "totalFrames": 0, "matches": [], "error": "", "createdAt": now,
            "completedAt": 0,
        }

    try:
        audit_event(who, "NUMBER PLATE VIDEO SEARCH SUBMITTED",
                    "Submitted an authorized video OCR search", "—",
                    {"jobId": job_id, "videoBytes": video_size, "videoExtension": extension})
        _WORKERS.submit(_scan_video, job_id, video_path)
    except Exception as exc:
        with _JOBS_LOCK:
            _JOBS.pop(job_id, None)
        try:
            os.remove(video_path)
        except FileNotFoundError:
            pass
        traceback.print_exc()
        _reject(handler, 500, f"Could not queue the video search: {exc}")
        return True
    handler._json(202, {"job": {"id": job_id, "status": "queued"}})
    return True
