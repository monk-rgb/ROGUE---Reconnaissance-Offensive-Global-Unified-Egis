"""Visual Forensics backend: image intake, analysis pipeline, findings, reports.

Design notes:
- Original uploads are stored immutably in ``data/vf_evidence/<sha256>.bin``.
- Every analysis reads from the immutable original; enhanced copies are separate assets.
- Detector outputs carry a ``source`` ("model" / "processing" / "manual") and are
  labelled so the UI can distinguish observed features from algorithmic interpretation.
- Optional computer-vision backends (OpenCV Haar cascades, Tesseract OCR, Real-ESRGAN)
  are used when importable; every capability degrades to an explicit
  "capability unavailable" finding rather than a fabricated result.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import math
import os
import re
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import sqlite3

from early_warning_service import DB_PATH, audit_event, clean_text

try:
    import numpy as np
    from PIL import Image, ImageOps, ImageStat, ExifTags
    Image.MAX_IMAGE_PIXELS = 120_000_000
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[assignment]
    np = None  # type: ignore[assignment]

try:
    import cv2
    _CASCADE_DIR = None
    # Prefer the locally vendored cascade XMLs (see data/vf_models/README.md); fall back to
    # the OpenCV package's bundled directory when a full build ships the classic cascades.
    _LOCAL_CASCADE_DIR = Path(__file__).resolve().parent / "data" / "vf_models"
    if _LOCAL_CASCADE_DIR.is_dir() and any(_LOCAL_CASCADE_DIR.glob("haarcascade_*.xml")):
        _CASCADE_DIR = str(_LOCAL_CASCADE_DIR) + os.sep
    else:
        try:
            import cv2.data  # type: ignore[import-not-found]
            _CASCADE_DIR = cv2.data.haarcascades
        except Exception:
            pass
except ImportError:  # pragma: no cover
    cv2 = None  # type: ignore[assignment]

try:
    import pytesseract
except ImportError:
    pytesseract = None  # type: ignore[assignment]

VF_MAX_UPLOAD_BYTES = 24 * 1024 * 1024
VF_SUPPORTED_FORMATS = {"JPEG", "JPG", "PNG", "WEBP", "TIFF"}
VF_MIME_BY_FORMAT = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp", "TIFF": "image/tiff"}
VF_EVIDENCE_DIR = DB_PATH.parent / "vf_evidence" if not DB_PATH.is_absolute() else Path(__file__).resolve().parent / "data" / "vf_evidence"

VF_REVIEW_STATUSES = {"New", "Pending review", "Confirmed observation", "Inconclusive", "Rejected"}

_VF_LOCK = threading.RLock()
_CASCADE_CACHE: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

def initialise_forensics_tables() -> None:
    with _VF_LOCK:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS vf_images (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    mime TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL UNIQUE,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    format TEXT NOT NULL,
                    exif_json TEXT NOT NULL,
                    quality_json TEXT,
                    metadata_flags_json TEXT,
                    uploaded_by TEXT NOT NULL,
                    uploaded_epoch REAL NOT NULL,
                    case_ref TEXT NOT NULL DEFAULT '—'
                );
                CREATE INDEX IF NOT EXISTS vf_images_uploaded ON vf_images(uploaded_by, uploaded_epoch);
                CREATE TABLE IF NOT EXISTS vf_findings (
                    id TEXT PRIMARY KEY,
                    image_id TEXT NOT NULL REFERENCES vf_images(id),
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    box_json TEXT NOT NULL,
                    method TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL,
                    confidence_label TEXT,
                    limitations TEXT NOT NULL,
                    alternatives TEXT NOT NULL DEFAULT '',
                    review_status TEXT NOT NULL DEFAULT 'New',
                    analyst_notes_json TEXT NOT NULL DEFAULT '[]',
                    created_epoch REAL NOT NULL,
                    updated_epoch REAL NOT NULL,
                    updated_by TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS vf_findings_image ON vf_findings(image_id, created_epoch);
                CREATE TABLE IF NOT EXISTS vf_annotations (
                    id TEXT PRIMARY KEY,
                    image_id TEXT NOT NULL REFERENCES vf_images(id),
                    kind TEXT NOT NULL,
                    label TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    box_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_epoch REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vf_derivatives (
                    id TEXT PRIMARY KEY,
                    image_id TEXT NOT NULL REFERENCES vf_images(id),
                    kind TEXT NOT NULL,
                    settings_json TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    created_by TEXT NOT NULL,
                    created_epoch REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS vf_derivatives_image ON vf_derivatives(image_id, created_epoch);
                CREATE TABLE IF NOT EXISTS vf_reports (
                    id TEXT PRIMARY KEY,
                    case_ref TEXT NOT NULL,
                    analyst TEXT NOT NULL,
                    image_ids_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_epoch REAL NOT NULL
                );
            """)
            connection.commit()
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# Evidence storage
# ---------------------------------------------------------------------------

def _evidence_dir() -> Path:
    directory = Path(__file__).resolve().parent / "data" / "vf_evidence"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _immutability_guard(path: Path) -> None:
    # An evidence asset must already exist; writes happen exactly once at intake.
    if not path.exists():
        raise ValueError("Evidence asset not found.")


def store_evidence(data: bytes) -> tuple[str, Path]:
    """Write the immutable original once; repeated uploads are rejected by hash."""
    digest = hashlib.sha256(data).hexdigest()
    path = _evidence_dir() / f"{digest}.bin"
    if not path.exists():
        with _VF_LOCK:
            if not path.exists():
                path.write_bytes(data)
        os.chmod(path, 0o444)
    return digest, path


def load_evidence(sha256: str) -> bytes:
    clean_hash = str(sha256).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", clean_hash):
        raise ValueError("Invalid evidence hash.")
    path = _evidence_dir() / f"{clean_hash}.bin"
    _immutability_guard(path)
    try:
        os.chmod(path, 0o644)
        return path.read_bytes()
    finally:
        os.chmod(path, 0o444)


def _decode_image(data: bytes) -> Any:
    if Image is None:
        raise RuntimeError("Pillow is not installed; image analysis is unavailable.")
    try:
        return Image.open(io.BytesIO(data))
    except Exception as exc:
        raise ValueError(f"Image could not be decoded (corrupted or unsupported): {exc}") from exc


def _format_ok(img: Any) -> str | None:
    fmt = (img.format or "").upper()
    if fmt in VF_SUPPORTED_FORMATS:
        return "JPEG" if fmt == "JPG" else fmt
    return None


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------

_EXIF_TAG_NAMES = {
    0x010F: "make", 0x0110: "model", 0x0112: "orientation", 0x0132: "dateTime",
    0x9003: "dateTimeOriginal", 0x9004: "dateTimeDigitized", 0x829A: "exposureTime",
    0x829D: "fNumber", 0x8827: "iso", 0x920A: "focalLength", 0xA002: "pixelXDimension",
    0xA003: "pixelYDimension", 0x0131: "software", 0x9286: "userComment",
    0x8769: "exifIFD", 0x8825: "gpsIFD", 0xA430: "cameraOwnerName", 0xA433: "lensMake",
    0xA434: "lensModel", 0xA435: "lensSerial",
}


def extract_metadata(data: bytes, img: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "format": _format_ok(img), "dimensions": [img.width, img.height],
        "exifPresent": bool(getattr(img, "getexif", None) and img.getexif()),
        "exif": {}, "software": None, "camera": None, "timestamps": {},
        "timezoneUncertainty": "EXIF timestamps carry no reliable timezone; treat as unverified local device time.",
        "note": "Missing metadata is NOT evidence of tampering. Many cameras and exporters strip or omit EXIF.",
    }
    try:
        exif = img.getexif()
        for tag_id, value in exif.items():
            name = _EXIF_TAG_NAMES.get(tag_id) or f"tag_{tag_id:04X}"
            try:
                if isinstance(value, bytes):
                    value = value.decode("utf-8", "replace")
                metadata["exif"][str(name)] = str(value)[:300]
            except Exception:
                continue
        ifd = getattr(exif, "get_ifd", None)
        if callable(ifd):
            for ifd_id in (0x8769, 0x8825):
                try:
                    for tag_id, value in ifd(ifd_id).items():
                        name = _EXIF_TAG_NAMES.get(tag_id) or f"ifd{ifd_id:X}_tag{tag_id:04X}"
                        try:
                            metadata["exif"][str(name)] = str(value)[:300]
                        except Exception:
                            continue
                except Exception:
                    continue
    except Exception:
        pass
    for source_key, target in (("make", "make"), ("model", "model")):
        if source_key in metadata["exif"]:
            metadata["camera"] = f"{metadata['exif']['make']} {metadata['exif']['model']}".strip()
            break
    metadata["software"] = metadata["exif"].get("software")
    for key in ("dateTime", "dateTimeOriginal", "dateTimeDigitized"):
        if key in metadata["exif"]:
            metadata["timestamps"][key] = metadata["exif"][key]
    return metadata


def _normalise_orientation(img: Any) -> Any:
    try:
        return ImageOps.exif_transpose(img)
    except Exception:
        return img


# ---------------------------------------------------------------------------
# Image quality analysis (numpy/Pillow only)
# ---------------------------------------------------------------------------

def _to_gray(img: Any) -> Any:
    return img.convert("L")


def quality_analysis(img: Any) -> dict[str, Any]:
    gray = np.asarray(_to_gray(img), dtype=np.float64)
    small = gray if max(gray.shape) <= 1600 else np.asarray(
        _to_gray(img.resize((max(1, img.width // 2), max(1, img.height // 2)))), dtype=np.float64)
    hist, _ = np.histogram(small, bins=256, range=(0, 256), density=True)
    mean = float(small.mean())
    std = float(small.std())
    # Laplacian variance via numpy (sharpness proxy; not a calibrated score)
    lap_kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float64)
    padded = np.pad(small, 1, mode="edge")
    window = np.lib.stride_tricks.sliding_window_view(padded, (3, 3))
    lap = (window * lap_kernel).sum(axis=(-1, -2)) if window.ndim == 4 else np.array([0.0])
    sharpness = float(lap.var())
    noise_est = float(np.abs(np.diff(small, axis=1)).mean())
    hist = hist * 256
    return {
        "dimensions": [img.width, img.height],
        "megapixels": round(img.width * img.height / 1_000_000, 2),
        "brightness": {"value": round(mean, 1), "label": _brightness_label(mean),
                       "explanation": "Mean luminance 0–255. Low values mean dark scenes where small details may be unrecoverable."},
        "contrast": {"value": round(std, 1), "label": _contrast_label(std),
                     "explanation": "Standard deviation of luminance. Low contrast compresses detail; it does not by itself imply manipulation."},
        "sharpness": {"value": round(sharpness, 1), "label": _sharpness_label(sharpness),
                      "explanation": "Laplacian variance heuristic. Blur can come from defocus, motion, or resampling; a low score is an indicator, not proof of anything."},
        "noise": {"value": round(noise_est, 2), "label": _noise_label(noise_est),
                  "explanation": "Mean absolute horizontal difference, a rough noise/texture proxy. It varies with scene texture as well as sensor noise."},
        "exposureClipping": {
            "shadowPercent": round(float((small < 8).mean() * 100), 2),
            "highlightPercent": round(float((small > 247).mean() * 100), 2),
            "explanation": "Share of near-black (<8) and near-white (>247) pixels. Clipped pixels cannot be recovered by enhancement."},
        "histogram": [round(float(v), 3) for v in hist.tolist()],
        "note": "These are heuristic indicators, not calibrated probabilities of image quality or authenticity.",
    }


def _brightness_label(mean: float) -> str:
    if mean < 40: return "Very dark"
    if mean < 85: return "Dark"
    if mean > 215: return "Very bright"
    if mean > 170: return "Bright"
    return "Balanced"


def _contrast_label(std: float) -> str:
    if std < 25: return "Low contrast"
    if std > 75: return "High contrast"
    return "Moderate contrast"


def _sharpness_label(value: float) -> str:
    if value < 30: return "Likely soft/blurry"
    if value < 120: return "Moderate sharpness"
    return "Sharp"


def _noise_label(value: float) -> str:
    if value < 3: return "Low variation"
    if value > 25: return "High variation (texture/noise)"
    return "Typical"


def brightness_map_b64(img: Any) -> str:
    """Small grayscale illumination map as a data URI for overlay display."""
    w, h = 96, max(1, round(96 * img.height / max(1, img.width)))
    small = _to_gray(img.resize((w, h)))
    arr = np.asarray(small, dtype=np.uint8)
    encoded = Image.fromarray(arr).save_to_bytes if False else None
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


# ---------------------------------------------------------------------------
# Detector backends
# ---------------------------------------------------------------------------

def _cascade(name: str) -> Any:
    with _VF_LOCK:
        if name in _CASCADE_CACHE:
            return _CASCADE_CACHE[name]
        # OpenCV 5.x moved the classic cascade API out of the default namespace; when it is
        # unavailable we degrade to an explicit "capability unavailable" finding rather than crash.
        factory = getattr(cv2, "CascadeClassifier", None) if cv2 is not None else None
        if factory is None or not _CASCADE_DIR:
            _CASCADE_CACHE[name] = None
            return None
        path = _CASCADE_DIR + name
        try:
            classifier = factory(path)
            _CASCADE_CACHE[name] = None if classifier.empty() else classifier
        except Exception:
            _CASCADE_CACHE[name] = None
        return _CASCADE_CACHE[name]


def _to_cv(img: Any) -> Any:
    rgb = img.convert("RGB")
    return cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2BGR)


def _cv_gray(img: Any) -> Any:
    return cv2.cvtColor(np.asarray(img.convert("RGB")), cv2.COLOR_RGB2GRAY)


def _clip_boxes(boxes: list[list[int]], width: int, height: int) -> list[list[int]]:
    result = []
    for x, y, w, h in boxes:
        x0, y0 = max(0, int(x)), max(0, int(y))
        x1, y1 = min(width, int(x + w)), min(height, int(y + h))
        if x1 > x0 and y1 > y0:
            result.append([x0, y0, x1 - x0, y1 - y0])
    return result


def _scale_boxes(boxes: list[list[int]], scale: float, width: int, height: int) -> list[list[int]]:
    if abs(scale - 1.0) < 1e-6:
        return _clip_boxes(boxes, width, height)
    scaled = [[round(x / scale), round(y / scale), round(w / scale), round(h / scale)] for x, y, w, h in boxes]
    return _clip_boxes(scaled, width, height)


def detect_faces_and_eyes(img: Any) -> dict[str, Any]:
    """Haar-cascade face/eye detection. Returns model-labelled boxes or capability=False."""
    if cv2 is None:
        return {"available": False, "reason": "OpenCV is not installed in this environment."}
    face_cascade = _cascade("haarcascade_frontalface_default.xml")
    eye_cascade = _cascade("haarcascade_eye.xml")
    if face_cascade is None or eye_cascade is None:
        return {"available": False, "reason": "Face/eye cascade models are not available in this environment."}
    gray = _cv_gray(img)
    height, width = gray.shape[:2]
    scale = 1.0
    if max(height, width) > 1400:
        scale = max(height, width) / 1400
        gray_small = cv2.resize(gray, (round(width / scale), round(height / scale)))
    else:
        gray_small = gray
    faces = face_cascade.detectMultiScale(gray_small, scaleFactor=1.12, minNeighbors=5, minSize=(28, 28))
    faces = _scale_boxes([list(map(int, f)) for f in faces], scale, width, height)
    eyes_per_face = []
    for fx, fy, fw, fh in faces:
        margin_y = max(2, int(fh * 0.10))
        roi = gray[max(0, fy + margin_y): fy + int(fh * 0.62), fx: fx + fw]
        if roi.size == 0:
            eyes_per_face.append([])
            continue
        roi_scale = 1.0
        if roi.shape[0] < 60:
            roi_scale = 60 / roi.shape[0]
            roi = cv2.resize(roi, (round(roi.shape[1] * roi_scale), 60))
        eyes = eye_cascade.detectMultiScale(roi, scaleFactor=1.08, minNeighbors=4, minSize=(10, 10))
        eyes = [[fx + int(x / roi_scale), fy + margin_y + int(y / roi_scale),
                 int(w / roi_scale), int(h / roi_scale)] for x, y, w, h in map(list, eyes)]
        eyes_per_face.append(_clip_boxes(eyes, width, height)[:4])
    return {"available": True, "faces": faces, "eyesPerFace": eyes_per_face,
            "method": "OpenCV Haar cascades (frontal face, eye)",
            "limitations": "Haar cascades are sensitive to head pose, glasses, lighting, and resolution; non-frontal faces may be missed. Detection is not identity recognition."}


def _gaze_from_eye_crop(eye_gray: Any) -> dict[str, Any]:
    """Very rough apparent-gaze heuristic from iris darkness offset inside the eye crop."""
    height, width = eye_gray.shape[:2]
    if height < 8 or width < 8:
        return {"direction": "indeterminate", "confidence": 0.0,
                "reason": "Eye crop too small for a meaningful estimate."}
    dark = (eye_gray < 70).astype(np.uint8)
    if dark.sum() < 6:
        return {"direction": "indeterminate", "confidence": 0.0,
                "reason": "No clearly dark iris-like region found; eyelids, blur, or lighting may hide it."}
    ys, xs = np.nonzero(dark)
    cx, cy = xs.mean() / width, ys.mean() / height
    dx, dy = cx - 0.5, cy - 0.5
    confidence = max(0.0, min(0.55, 0.25 + 0.6 * (abs(dx) + abs(dy))))
    if abs(dx) < 0.06 and abs(dy) < 0.06:
        direction, confidence = "indeterminate", 0.15
    elif abs(dx) >= abs(dy):
        direction = "left" if dx < 0 else "right"
    else:
        direction = "upward" if dy < 0 else "downward"
    return {"direction": direction, "confidence": round(confidence, 2),
            "reason": "Heuristic centroid of dark pixels relative to the visible eye opening. Strongly affected by eyelid shape, glasses, blur, and lighting."}


def _specular_highlights(img: Any, box: list[int]) -> list[list[int]]:
    """Find small bright spots inside a region (candidate corneal reflections)."""
    x, y, w, h = box
    crop = np.asarray(img.convert("L").crop((x, y, x + w, y + h)), dtype=np.uint8)
    if crop.size == 0:
        return []
    threshold = max(int(crop.max()) - 12, 200)
    mask = (crop >= threshold).astype(np.uint8)
    if cv2 is not None:
        # connectedComponentsWithStats returns (retval, labels, stats, centroids).
        _labels, stats = cv2.connectedComponentsWithStats(mask, 8)[1:3]
        spots = []
        for index in range(1, stats.shape[0]):
            area = int(stats[index, cv2.CC_STAT_AREA])
            if 2 <= area <= max(20, mask.size // 400):
                spots.append([int(stats[index, cv2.CC_STAT_LEFT]), int(stats[index, cv2.CC_STAT_TOP]),
                              int(stats[index, cv2.CC_STAT_WIDTH]), int(stats[index, cv2.CC_STAT_HEIGHT])])
        return spots[:12]
    ys, xs = np.nonzero(mask)
    return [[int(xs.min()), int(ys.min()), 2, 2]] if xs.size else []


def analyse_eyes(img: Any) -> dict[str, Any]:
    detection = detect_faces_and_eyes(img)
    if not detection.get("available"):
        return {"available": False, "reason": detection.get("reason"),
                "faces": [], "finding": None}
    faces, eyes_per_face = detection["faces"], detection["eyesPerFace"]
    results = []
    width, height = img.width, img.height
    for face_index, face in enumerate(faces):
        eyes = eyes_per_face[face_index]
        face_result = {"faceBox": face, "eyes": []}
        for eye in eyes:
            x, y, w, h = eye
            crop = _cv_gray(img.crop((x, y, x + w, y + h))) if cv2 else None
            gaze = _gaze_from_eye_crop(crop) if crop is not None and crop.size else {
                "direction": "indeterminate", "confidence": 0.0, "reason": "Eye crop unavailable."}
            spots = _specular_highlights(img, eye)
            quality = {
                "blur": _sharpness_label(float(np.asarray(img.convert('L').crop((x, y, x + w, y + h))).var())) if crop is not None else "unknown",
                "small": w < 16 or h < 16,
                "occlusionSuspicion": bool(gaze.get("reason")),
            }
            face_result["eyes"].append({
                "box": eye, "gaze": gaze, "specularSpots": spots, "quality": quality,
                "note": "Apparent gaze is an estimate, not a measurement of attention. It cannot establish what a person actually looked at, and never implies intent.",
            })
        results.append(face_result)
    return {"available": True, "faces": results,
            "method": detection["method"], "limitations": detection["limitations"]}


def ocr_text(img: Any) -> dict[str, Any]:
    if pytesseract is None:
        return {"available": False,
                "reason": "Tesseract OCR is not installed; readable-text extraction is unsupported in this environment."}
    try:
        gray = img.convert("L")
        data = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT)
        words = []
        for index, text in enumerate(data["text"]):
            text = text.strip()
            if int(data["conf"][index]) > 40 and len(text) >= 3:
                words.append({"text": text, "box": [int(data["left"][index]), int(data["top"][index]),
                                                    int(data["width"][index]), int(data["height"][index])],
                              "confidence": int(data["conf"][index]) / 100.0})
        return {"available": True, "words": words[:120],
                "method": "Tesseract OCR",
                "limitations": "OCR misreads stylised, angled, low-resolution, or partially obscured text. Every extracted string should be checked against the magnified crop."}
    except Exception as exc:
        return {"available": False, "reason": f"OCR failed: {exc}"}


def detect_vehicles_like_regions(img: Any) -> dict[str, Any]:
    """Vehicle detection is not supported by bundled models; report capability honestly."""
    return {"available": False,
            "reason": "No vehicle-detection model is bundled with this prototype; vehicle detection is reported as unsupported rather than simulated."}


# ---------------------------------------------------------------------------
# Shadow / lighting analysis
# ---------------------------------------------------------------------------

def shadow_light_analysis(img: Any) -> dict[str, Any]:
    if np is None:
        return {"available": False, "reason": "numpy is not installed."}
    gray = np.asarray(_to_gray(img.resize((min(320, img.width), min(320, img.height)))), dtype=np.float64)
    height, width = gray.shape
    cell_h, cell_w = max(1, height // 8), max(1, width // 8)
    means = np.array([[gray[r * cell_h:(r + 1) * cell_h, c * cell_w:(c + 1) * cell_w].mean()
                       for c in range(width // cell_w or 1)] for r in range(height // cell_h or 1)])
    overall = float(gray.mean())
    brightest = np.unravel_index(np.argmax(means), means.shape)
    dark = means < overall - 45
    bright = means > 210
    # gradient direction: apparent light comes from brighter side
    gy, gx = np.gradient(means)
    gradient_mag = float(np.hypot(gx, gy).mean())
    direction = None
    if gradient_mag > 2.0:
        vx, vy = float(-gx.mean()), float(-gy.mean())
        angle = math.degrees(math.atan2(vy, vx))
        labels = ["right", "lower-right", "below", "lower-left", "left", "upper-left", "above", "upper-right"]
        direction = labels[int(((angle + 360) % 360 + 22.5) // 45) % 8]
    bright_map = brightness_map_b64(img)
    return {
        "available": True,
        "gridMean": [[round(float(v), 1) for v in row] for row in means],
        "illuminationMap": bright_map,
        "apparentLightDirection": direction,
        "lightDirectionConfidence": "Low" if gradient_mag < 4 else "Indicative",
        "unevenIllumination": bool(means.std() > 35),
        "shadowCellCount": int(dark.sum()),
        "glareCellCount": int(bright.sum()),
        "brightestCell": [int(brightest[0]), int(brightest[1])],
        "method": "Grid luminance statistics and mean gradient (processing, not a model)",
        "limitations": ("Shadow and light statistics are scene-level heuristics. Multiple light sources, "
                        "reflections, windows, perspective, and scene geometry produce legitimately inconsistent-looking shadows. "
                        "These outputs cannot establish that an image was manipulated."),
        "interpretation": ("Treat as a prompt for closer manual inspection, never as a manipulation verdict."),
    }


# ---------------------------------------------------------------------------
# Object / scene description
# ---------------------------------------------------------------------------

_SCENE_CUES = {
    "outdoor sky/bright overhead": lambda m, s, hi: hi > 8 and m > 150,
    "low-light / night scene": lambda m, s, hi: m < 60,
    "document-like light background": lambda m, s, hi: m > 190 and s < 35,
}


def scene_description(img: Any) -> list[dict[str, Any]]:
    gray = np.asarray(_to_gray(img.resize((128, 128))), dtype=np.float64)
    mean, std = float(gray.mean()), float(gray.std())
    hi = float((gray > 247).mean() * 100)
    descriptions = []
    for text, predicate in _SCENE_CUES.items():
        try:
            if predicate(mean, std, hi):
                descriptions.append(text)
        except Exception:
            continue
    return [{
        "category": "scene", "title": "Statistical scene cues",
        "description": (f"Luminance mean {mean:.0f}, contrast {std:.0f}, clipped-highlight share {hi:.1f}%. "
                        f"Cue-matched descriptions: {', '.join(descriptions) if descriptions else 'none'}"),
        "method": "Histogram statistics (processing)",
        "confidence": 0.3,
        "confidenceLabel": "Indicative statistics only",
        "limitations": "This is a statistical colour/brightness description, not a semantic scene understanding model. It may be wrong about any real-world content.",
    }]


def object_analysis(img: Any) -> dict[str, Any]:
    """Faces/eyes from cascades plus scene cues; a full generic object detector is not bundled."""
    detection = detect_faces_and_eyes(img)
    findings = []
    if detection.get("available") and detection["faces"]:
        findings.append({
            "category": "object", "title": f"{len(detection['faces'])} face-like region(s) detected",
            "description": ("Frontal face-like regions were detected by a Haar cascade model. "
                            "This is shape detection only; it does not and cannot identify any person."),
            "boxes": detection["faces"], "method": detection["method"],
            "confidence": None, "confidenceLabel": "Haar cascades do not provide calibrated confidence; treat locations as approximate.",
            "limitations": detection["limitations"],
        })
    for cue in scene_description(img):
        findings.append(cue)
    vehicles = detect_vehicles_like_regions(img)
    if not vehicles.get("available"):
        findings.append({
            "category": "capability", "title": "Vehicle detection unsupported",
            "description": f"No vehicle-detection model is bundled. {vehicles['reason']} Do not treat this as 'no vehicles present'.",
            "boxes": [], "method": "capability check", "confidence": None,
            "confidenceLabel": "N/A", "limitations": "Absence of a detector is not absence of vehicles.",
        })
    return {"findings": findings, "detection": detection}


# ---------------------------------------------------------------------------
# Integrity / anomaly heuristics
# ---------------------------------------------------------------------------

def integrity_check(img: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    observations = []
    gray = np.asarray(_to_gray(img.resize((min(256, img.width), min(256, img.height)))), dtype=np.float64)
    noise = float(np.abs(np.diff(gray, axis=1)).mean())
    if noise < 0.5 and img.width * img.height > 250_000:
        observations.append({
            "title": "Unusually low residual sensor noise",
            "description": "Horizontal noise estimate is near zero across the image. This can result from heavy compression, upscaling of clean graphics, export pipelines, or genuinely synthetic imagery — or simply a clean source. It is an observation, not a manipulation verdict.",
            "confidenceLabel": "Indicator only",
        })
    exif_present = metadata.get("exifPresent")
    if not exif_present:
        observations.append({
            "title": "No EXIF metadata present",
            "description": "The file carries no EXIF block. Messaging apps, exporters, and some cameras strip metadata; absence of metadata is NOT evidence of tampering.",
            "confidenceLabel": "Observation",
        })
    if metadata.get("software"):
        observations.append({
            "title": f"Software tag present: {metadata['software']}",
            "description": "The EXIF software field names an application. Many editing tools write it even for innocent crops/resizes; record it and consider alternative explanations.",
            "confidenceLabel": "Observation",
        })
    return {"observations": observations,
            "note": "No single automated detector can establish authenticity. Corroborate with multiple methods and human review."}


# ---------------------------------------------------------------------------
# Clarity / enhancement
# ---------------------------------------------------------------------------

def enhance(img: Any, settings: dict[str, Any]) -> tuple[Any, list[str]]:
    applied: list[str] = []
    out = img.convert("RGB")
    denoise = int(settings.get("denoise", 0))
    if denoise > 0 and cv2 is not None:
        arr = cv2.cvtColor(np.asarray(out), cv2.COLOR_RGB2BGR)
        strength = min(10, denoise)
        arr = cv2.fastNlMeansDenoisingColored(arr, None, strength, 7, 15)
        out = Image.fromarray(cv2.cvtColor(arr, cv2.COLOR_BGR2RGB))
        applied.append(f"denoise:{strength}")
    sharpen = int(settings.get("sharpen", 0))
    if sharpen > 0:
        amount = 1.0 + min(5, sharpen) * 0.35
        from PIL import ImageFilter
        out = out.filter(ImageFilter.UnsharpMask(radius=2, percent=int(amount * 100), threshold=3))
        applied.append(f"sharpen:{sharpen}")
    brightness = float(settings.get("brightness", 0))
    contrast = float(settings.get("contrast", 0))
    if brightness or contrast:
        if np is not None:
            arr = np.asarray(out, dtype=np.float64)
            arr = (arr - 128) * (1 + contrast / 100) + 128 + brightness * 2.55
            out = Image.fromarray(np.clip(arr, 0, 255).astype("uint8"))
        else:
            from PIL import ImageEnhance
            out = ImageEnhance.Contrast(out).enhance(1 + contrast / 100)
            out = ImageEnhance.Brightness(out).enhance(1 + brightness / 100)
        applied.append(f"brightness:{brightness};contrast:{contrast}")
    shadows = float(settings.get("shadows", 0))
    highlights = float(settings.get("highlights", 0))
    if shadows and np is not None:
        arr = np.asarray(out, dtype=np.float64)
        mask = 1 - arr.min(axis=2) / 255.0
        arr += shadows * 2.0 * mask[:, :, None]
        out = Image.fromarray(np.clip(arr, 0, 255).astype("uint8"))
        applied.append(f"shadows:+{shadows}")
    if highlights and np is not None:
        arr = np.asarray(out, dtype=np.float64)
        mask = arr.max(axis=2) / 255.0
        arr -= max(0.0, highlights) * 1.2 * mask[:, :, None]
        out = Image.fromarray(np.clip(arr, 0, 255).astype("uint8"))
        applied.append(f"highlights:-{highlights}")
    gamma = float(settings.get("gamma", 1.0))
    if abs(gamma - 1.0) > 0.01 and np is not None:
        arr = np.asarray(out, dtype=np.float64) / 255.0
        arr = np.power(arr, 1.0 / max(0.1, gamma))
        out = Image.fromarray((arr * 255).astype("uint8"))
        applied.append(f"gamma:{gamma}")
    upscale = int(settings.get("upscale", 1))
    if upscale > 1:
        out = out.resize((out.width * upscale, out.height * upscale), Image.LANCZOS)
        applied.append(f"resize:{upscale}x (resampling, NOT super-resolution: no new information is recovered)")
    return out, applied


def superresolution_status() -> dict[str, Any]:
    return {
        "available": False,
        "reason": ("Real-ESRGAN (or another generative super-resolution model) is not bundled in this prototype "
                   "because of model size, hardware, and licensing requirements. Lanczos upscaling is offered instead "
                   "and explicitly does not recover information that was never captured."),
        "substitute": "lanczos-upscale",
    }


# ---------------------------------------------------------------------------
# Finding helper
# ---------------------------------------------------------------------------

def make_finding(image_id: str, category: str, title: str, description: str,
                 box: list[int] | None = None, method: str = "", source: str = "model",
                 confidence: float | None = None, confidence_label: str | None = None,
                 limitations: str = "", alternatives: str = "") -> dict[str, Any]:
    box = box or [0, 0, 0, 0]
    now = time.time()
    return {
        "id": f"VF-{uuid.uuid4().hex[:10].upper()}", "imageId": image_id, "category": category,
        "title": title, "description": description, "box": box, "method": method, "source": source,
        "confidence": confidence, "confidenceLabel": confidence_label or (
            f"{int(confidence * 100)}%" if confidence is not None else "No calibrated confidence available"),
        "limitations": limitations, "alternatives": alternatives,
        "reviewStatus": "New", "analystNotes": [], "createdAt": int(now * 1000),
    }


def clear_findings(image_id: str) -> None:
    """Remove an image's auto-generated findings ahead of a regenerating analysis run."""
    with _VF_LOCK:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            connection.execute("DELETE FROM vf_findings WHERE image_id=?", (image_id,))
            connection.commit()
        finally:
            connection.close()


def insert_finding(finding: dict[str, Any]) -> None:
    with _VF_LOCK:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            connection.execute(
                """INSERT INTO vf_findings (id, image_id, category, title, description, box_json, method,
                   source, confidence, confidence_label, limitations, alternatives, review_status,
                   analyst_notes_json, created_epoch, updated_epoch, updated_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (finding["id"], finding["imageId"], finding["category"], finding["title"],
                 finding["description"], json.dumps(finding["box"]), finding["method"], finding["source"],
                 finding["confidence"], finding["confidenceLabel"], finding["limitations"],
                 finding.get("alternatives", ""), finding["reviewStatus"],
                 json.dumps(finding["analystNotes"]), finding["createdAt"] / 1000,
                 finding["createdAt"] / 1000, ""),
            )
            connection.commit()
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# Full analysis pipeline
# ---------------------------------------------------------------------------

def run_full_analysis(image_row: sqlite3.Row | dict[str, Any] | tuple[Any, ...]) -> dict[str, Any]:
    # Accept the tuple produced by vf_routes._get_image_row as well as a mapping.
    # Tuple layout: id, filename, mime, byte_size, sha256, width, height, format, ...
    if not isinstance(image_row, dict) and not hasattr(image_row, "keys"):
        image_row = {"id": image_row[0], "filename": image_row[1], "mime": image_row[2],
                     "byte_size": image_row[3], "sha256": image_row[4], "width": image_row[5],
                     "height": image_row[6], "format": image_row[7]}
    data = load_evidence(image_row["sha256"])
    img = _decode_image(data)
    img = _normalise_orientation(img)
    findings: list[dict[str, Any]] = []

    objects = object_analysis(img)
    for item in objects["findings"]:
        findings.append(make_finding(
            image_id=image_row["id"],
            category=item.get("category", "object"),
            title=item["title"], description=item["description"],
            box=item.get("boxes", [])[0] if item.get("boxes") else None,
            method=item.get("method", ""), source="model" if item.get("category") == "object" else "processing",
            confidence=item.get("confidence"), confidence_label=item.get("confidenceLabel"),
            limitations=item.get("limitations", ""),
        ))

    eyes = analyse_eyes(img)
    for face_index, face in enumerate(eyes.get("faces", [])):
        for eye in face["eyes"]:
            box = eye["box"]
            gaze = eye["gaze"]
            findings.append(make_finding(
                image_id=image_row["id"], category="eye",
                title=f"Eye region · apparent gaze: {gaze['direction']}",
                description=(f"Eye-region crop at {box}. Estimated apparent gaze direction "
                             f"'{gaze['direction']}' with heuristic confidence {gaze['confidence']:.2f}. "
                             f"{gaze['reason']} {eye['note']}"),
                box=box, method="dark-pixel centroid heuristic over Haar eye crop", source="processing",
                confidence=gaze.get("confidence"), confidence_label="Heuristic only — not a calibrated or validated measure",
                limitations=("Gaze direction is estimated from a tiny crop; eyelids, glasses, motion blur and lighting change the result. "
                             "It cannot establish attention, intent, or what a person actually looked at."),
                alternatives=("Closed eye, low contrast, reflections, or camera angle can each produce the same estimate."),
            ))
            if eye["specularSpots"]:
                findings.append(make_finding(
                    image_id=image_row["id"], category="eye",
                    title="Possible specular highlight(s) in eye region",
                    description=(f"{len(eye['specularSpots'])} bright spot(s) detected in the eye crop. These may be corneal "
                                 f"reflections or catchlights. Reflected structures, if any, are far too small to identify objects, "
                                 f"rooms, or devices from this evidence."),
                    box=box, method="threshold + connected components", source="processing",
                    confidence=None, confidence_label="Unverified candidate; manual inspection required",
                    limitations="Bright spots can be sensor bloom, dust, or light sources anywhere along the line of sight.",
                ))
            if eye["quality"]["small"]:
                findings.append(make_finding(
                    image_id=image_row["id"], category="eye",
                    title="Eye region below reliable resolution",
                    description="The detected eye region is very small (under ~16 px). Any gaze or reflection reading at this size is unreliable.",
                    box=box, method="size check", source="processing", confidence=None,
                    confidence_label="Capability limit",
                    limitations="Small eye crops cannot support meaningful gaze or reflection analysis.",
                ))
    if eyes.get("available") and not eyes.get("faces"):
        findings.append(make_finding(
            image_id=image_row["id"], category="capability",
            title="No frontal face detected — eye analysis unavailable",
            description="The face/eye detector found no frontal face; gaze and corneal-reflection examination is reported as unsupported for this image, not as 'no eyes present'.",
            method="Haar cascade", source="model", confidence=None,
            confidence_label="Capability limit",
            limitations="Non-frontal, occluded, or low-resolution faces are missed by the detector.",
        ))
    if not eyes.get("available"):
        findings.append(make_finding(
            image_id=image_row["id"], category="capability",
            title="Eye analysis unsupported",
            description=f"Eye examination unavailable: {eyes.get('reason')}",
            method="capability check", source="processing", confidence=None,
            confidence_label="Capability limit", limitations="Capability absent; no fabricated results are produced.",
        ))

    lighting = shadow_light_analysis(img)
    if lighting.get("available"):
        findings.append(make_finding(
            image_id=image_row["id"], category="lighting",
            title=f"Apparent light direction: {lighting['apparentLightDirection'] or 'indeterminate'}",
            description=(f"Grid luminance statistics give apparent light direction "
                         f"'{lighting['apparentLightDirection'] or 'indeterminate'}' ({lighting['lightDirectionConfidence']}). "
                         f"Uneven illumination: {'yes' if lighting['unevenIllumination'] else 'not flagged'}. "
                         f"{lighting['shadowCellCount']} dark cell(s), {lighting['glareCellCount']} overexposed cell(s)."),
            method=lighting["method"], source="processing", confidence=None,
            confidence_label=lighting["lightDirectionConfidence"],
            limitations=lighting["limitations"],
            alternatives="Multiple light sources, reflections, windows and scene geometry all change these statistics.",
        ))
        if lighting["unevenIllumination"]:
            findings.append(make_finding(
                image_id=image_row["id"], category="lighting",
                title="Uneven illumination flagged for manual review",
                description="Large brightness differences across the image grid. Common in real scenes with windows, lamps or mixed lighting; flagged only for closer inspection.",
                method=lighting["method"], source="processing", confidence=None,
                confidence_label="Prompt for manual review — not a manipulation verdict",
                limitations=lighting["limitations"],
            ))

    quality = quality_analysis(img)
    meta = extract_metadata(data, img)
    for observation in integrity_check(img, meta)["observations"]:
        findings.append(make_finding(
            image_id=image_row["id"], category="integrity",
            title=observation["title"], description=observation["description"],
            method="metadata + noise heuristics", source="processing", confidence=None,
            confidence_label=observation["confidenceLabel"],
            limitations="No single automated detector establishes authenticity.",
        ))

    # A full analysis regenerates the image's detector/processing findings. Replace the
    # previous auto-generated set so re-running does not stack duplicate findings; analyst
    # annotations and derivatives are untouched, and manual notes stay on their annotations.
    clear_findings(image_row["id"])
    for finding in findings:
        insert_finding(finding)
    return {"findings": findings, "quality": quality, "metadata": meta, "lighting": lighting,
            "eyes": {"available": eyes.get("available", False),
                     "faces": eyes.get("faces", []),
                     "reason": eyes.get("reason")}}
