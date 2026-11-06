"""End-to-end tests for the Visual Forensics API (real images, real analysis)."""

from __future__ import annotations

import io
import json
import sys
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import early_warning_service as service  # noqa: E402
import vf_image  # noqa: E402
import vf_routes  # noqa: E402

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    raise SystemExit("Pillow is required for the visual forensics tests.")


def make_test_jpeg(width=900, height=700, faces=True) -> bytes:
    """Render a deterministic test photo; a plain gradient plus text block."""
    image = Image.new("RGB", (width, height), (40, 60, 40))
    pixels = image.load()
    for y in range(height):
        for x in range(0, width, 4):
            v = int(255 * x / width)
            for dx in range(4):
                if x + dx < width:
                    pixels[x + dx, y] = (v // 3, v // 2, 40 + (y * 90) // max(1, height))
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=88)
    return buf.getvalue()


class VisualForensicsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        directory = Path(__file__).resolve().parent / "tmp"
        directory.mkdir(exist_ok=True)
        cls._db_patch = unittest.mock.patch.object(
            service, "DB_PATH", directory / "vf_test.sqlite3")
        cls._db_patch.start()
        vf_image.DB_PATH = service.DB_PATH
        vf_routes.DB_PATH = service.DB_PATH
        service.initialise_database()
        vf_image.initialise_forensics_tables()
        cls.server = service.ThreadingHTTPServer(("127.0.0.1", 0), service.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        # Seed an approved account, then sign in through the real auth route
        import hashlib as _hashlib
        import os
        import sqlite3
        import time
        salt = os.urandom(16)
        passcode_hash = _hashlib.pbkdf2_hmac("sha256", b"vf-test-pass", salt, service.PASSCODE_ITERATIONS).hex()
        connection = sqlite3.connect(service.DB_PATH, timeout=5)
        try:
            connection.execute(
                """INSERT INTO official_access (service_key, service_number, full_name, official_type,
                   agency_unit, passcode_salt, passcode_hash, photo_data, fingerprint_enrolled, status,
                   requested_epoch, reviewer, reviewed_epoch) VALUES (?,?,?,?,?,?,?,?,1,'approved',?,?,?)
                   ON CONFLICT(service_key) DO UPDATE SET passcode_salt=excluded.passcode_salt,
                   passcode_hash=excluded.passcode_hash, status='approved', fingerprint_enrolled=1""",
                ("vf-test-1", "VF-TEST-1", "Test Analyst", "Military intelligence", "Test unit",
                 salt.hex(), passcode_hash, "", time.time(), "test", time.time()))
            connection.commit()
        finally:
            connection.close()
        request = urllib.request.Request(
            cls.base + "/api/auth/login", method="POST",
            data=json.dumps({
                "serviceNumber": "VF-TEST-1", "officialType": "Military intelligence",
                "passcode": "vf-test-pass", "fingerprintVerified": True,
            }).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Login failed {exc.code}: {exc.read().decode()}")
        token = payload.get("sessionToken")
        if not token:
            raise RuntimeError(f"Login response missing sessionToken: {payload}")
        cls.headers = {
            "X-NSP-Official": "VF-TEST-1",
            "X-NSP-Official-Type": "Military intelligence",
            "Authorization": f"Bearer {token}",
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls._db_patch.stop()

    def request(self, path: str, method: str = "GET", data: bytes | None = None,
                content_type: str | None = None) -> tuple[int, dict | bytes]:
        headers = dict(self.headers)
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request) as response:
                body = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            body = exc.read()
            status = exc.code
        try:
            return status, json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return status, body

    def test_requires_officer_session(self) -> None:
        request = urllib.request.Request(self.base + "/api/vf/images")
        try:
            urllib.request.urlopen(request)
            self.fail("Expected 401")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 401)

    def test_upload_analyse_findings_enhance_report(self) -> None:
        jpeg = make_test_jpeg()
        boundary = "vfboundary123"
        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="caseRef"\r\n\r\nMP-TEST-0001\r\n')
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="files"; filename="scene.jpg"\r\n')
        body.write(b"Content-Type: image/jpeg\r\n\r\n")
        body.write(jpeg)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        status, response = self.request(
            "/api/vf/upload", "POST", body.getvalue(),
            f"multipart/form-data; boundary={boundary}")
        self.assertEqual(status, 201, response)
        images = response["images"]
        self.assertEqual(len(images), 1)
        image = images[0]
        self.assertEqual(image["caseRef"], "MP-TEST-0001")
        self.assertEqual(len(image["sha256"]), 64)
        self.assertEqual(image["format"], "JPEG")
        self.assertEqual(image["width"], 900)

        # re-upload same file is idempotent (same sha256)
        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="files"; filename="scene.jpg"\r\n')
        body.write(b"Content-Type: image/jpeg\r\n\r\n")
        body.write(jpeg)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        status, repeat = self.request(
            "/api/vf/upload", "POST", body.getvalue(),
            f"multipart/form-data; boundary={boundary}")
        self.assertEqual(status, 201)
        self.assertEqual(repeat["images"][0]["sha256"], image["sha256"])

        # serve original
        status, data = self.request(f"/api/vf/image/{image['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(len(data), len(jpeg))

        # full analysis
        status, analysis = self.request(f"/api/vf/analyse/{image['id']}", "POST",
                                        json.dumps({"reason": "test"}).encode(),
                                        "application/json")
        self.assertEqual(status, 200, analysis)
        self.assertIn("findings", analysis)
        self.assertIn("quality", analysis)
        self.assertIn("metadata", analysis)

        # findings listed
        status, findings = self.request(f"/api/vf/findings/{image['id']}")
        self.assertEqual(status, 200)
        finding_ids = [finding["id"] for finding in findings["findings"]]
        self.assertEqual(finding_ids, [finding["id"] for finding in analysis["findings"]])

        # review flow requires a note
        finding_id = finding_ids[0]
        status, error = self.request(
            f"/api/vf/findings/{image['id']}/{finding_id}/review", "POST",
            json.dumps({"reviewStatus": "Confirmed observation"}).encode(), "application/json")
        self.assertEqual(status, 400)
        status, ok = self.request(
            f"/api/vf/findings/{image['id']}/{finding_id}/review", "POST",
            json.dumps({"reviewStatus": "Confirmed observation",
                        "note": "Verified the stated visual feature myself."}).encode(),
            "application/json")
        self.assertEqual(status, 200, ok)

        # annotation
        status, ok = self.request(
            f"/api/vf/annotations/add/{image['id']}", "POST",
            json.dumps({"box": [10, 10, 40, 20], "label": "catchlight", "note": "manual"}).encode(),
            "application/json")
        self.assertEqual(status, 201, ok)

        # enhancement
        status, enhanced = self.request(
            f"/api/vf/enhance/{image['id']}", "POST",
            json.dumps({"settings": {"sharpen": 3, "brightness": 10, "upscale": 2}}).encode(),
            "application/json")
        self.assertEqual(status, 201, enhanced)
        self.assertNotEqual(enhanced["processedSha256"], image["sha256"])
        self.assertIn("processedImage", enhanced)

        # comparison needs two uploads
        jpeg2 = make_test_jpeg(640, 480, faces=False)
        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="files"; filename="scene2.jpg"\r\n')
        body.write(b"Content-Type: image/jpeg\r\n\r\n")
        body.write(jpeg2)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        status, upload2 = self.request(
            "/api/vf/upload", "POST", body.getvalue(),
            f"multipart/form-data; boundary={boundary}")
        image2 = upload2["images"][0]
        status, comparison = self.request(
            "/api/vf/compare", "POST",
            json.dumps({"imageIds": [image["id"], image2["id"]]}).encode(), "application/json")
        self.assertEqual(status, 200, comparison)
        self.assertEqual(len(comparison["metadataDiffs"]), 1)
        self.assertIn("width", comparison["metadataDiffs"][0]["diffs"])

        # report
        status, report = self.request(
            "/api/vf/report", "POST",
            json.dumps({"imageIds": [image["id"], image2["id"]],
                        "reviewer": "MZ-123", "reviewerNotes": "reviewed"}).encode(),
            "application/json")
        self.assertEqual(status, 201, report)
        self.assertEqual(len(report["report"]["sections"]), 2)
        self.assertIn("limitationsStatement", report["report"])

    def test_analysis_accepts_route_tuple_and_is_deterministic(self) -> None:
        """Regression: run_full_analysis must accept the tuple from _get_image_row."""
        jpeg = make_test_jpeg(640, 480)
        boundary = "vfboundary123"
        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="files"; filename="det.jpg"\r\n')
        body.write(b"Content-Type: image/jpeg\r\n\r\n")
        body.write(jpeg)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        status, upload = self.request(
            "/api/vf/upload", "POST", body.getvalue(),
            f"multipart/form-data; boundary={boundary}")
        self.assertEqual(status, 201, upload)
        image_id = upload["images"][0]["id"]

        # _get_image_row returns a plain tuple; run_full_analysis must handle it.
        row = vf_routes._get_image_row(image_id, "VF-TEST-1")
        self.assertIsInstance(row, tuple)
        result = vf_image.run_full_analysis(row)
        self.assertTrue(result["findings"])

        # Findings list order is deterministic and equals the analysis order.
        status, findings = self.request(f"/api/vf/findings/{image_id}")
        self.assertEqual(status, 200)
        self.assertEqual([f["id"] for f in findings["findings"]],
                         [f["id"] for f in result["findings"]])

        # Re-running replaces the automated findings instead of stacking duplicates.
        again = vf_image.run_full_analysis(row)
        status, findings2 = self.request(f"/api/vf/findings/{image_id}")
        self.assertEqual(len(findings2["findings"]), len(again["findings"]))

    def test_delete_removes_image_and_dependents(self) -> None:
        jpeg = make_test_jpeg(500, 400, faces=False)
        boundary = "vfboundary123"
        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="files"; filename="todelete.jpg"\r\n')
        body.write(b"Content-Type: image/jpeg\r\n\r\n")
        body.write(jpeg)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        status, upload = self.request(
            "/api/vf/upload", "POST", body.getvalue(),
            f"multipart/form-data; boundary={boundary}")
        self.assertEqual(status, 201, upload)
        image_id = upload["images"][0]["id"]

        # Give it dependent records so the cascade is exercised.
        status, _ = self.request(
            f"/api/vf/annotations/add/{image_id}", "POST",
            json.dumps({"box": [1, 1, 10, 10], "label": "x", "note": "n"}).encode(),
            "application/json")
        self.assertEqual(status, 201)

        status, deleted = self.request(
            f"/api/vf/image/{image_id}/delete", "POST",
            json.dumps({"reason": "test cleanup"}).encode(), "application/json")
        self.assertEqual(status, 200, deleted)
        self.assertTrue(deleted["ok"])

        # The image is gone from the analyst's list and cannot be served.
        status, listing = self.request("/api/vf/images")
        self.assertEqual(status, 200)
        self.assertNotIn(image_id, [img["id"] for img in listing["images"]])
        status, _ = self.request(f"/api/vf/image/{image_id}")
        self.assertEqual(status, 404)

        # Deleting a non-existent image reports 404.
        status, _ = self.request(
            "/api/vf/image/VF-DOESNOTEXIST/delete", "POST",
            json.dumps({"reason": "test"}).encode(), "application/json")
        self.assertEqual(status, 404)

    def test_face_eye_pipeline_when_available(self) -> None:
        """Regression: the eye/specular path must not crash when a face is detected."""
        if vf_image.cv2 is None or not vf_image._CASCADE_DIR:
            self.skipTest("OpenCV cascades unavailable in this environment.")
        try:
            import urllib.request as _u
            data = _u.urlopen(
                "https://raw.githubusercontent.com/opencv/opencv/4.x/samples/data/lena.jpg",
                timeout=20).read()
        except Exception:
            self.skipTest("Face test image unavailable offline.")
        img = Image.open(io.BytesIO(data)).convert("RGB")
        eyes = vf_image.analyse_eyes(img)
        self.assertTrue(eyes["available"])
        # If any eye is found, its crop/gaze/specular computation must succeed.
        for face in eyes.get("faces", []):
            for eye in face["eyes"]:
                self.assertIn("gaze", eye)
                self.assertIn(eye["gaze"]["direction"],
                              {"left", "right", "upward", "downward", "indeterminate"})
                self.assertIsInstance(eye["specularSpots"], list)

    def test_rejects_unsupported_and_corrupt(self) -> None:
        boundary = "vfboundary123"
        body = io.BytesIO()
        body.write(f"--{boundary}\r\n".encode())
        body.write(b'Content-Disposition: form-data; name="files"; filename="fake.jpg"\r\n')
        body.write(b"Content-Type: image/jpeg\r\n\r\n")
        body.write(b"this is not an image at all")
        body.write(f"\r\n--{boundary}--\r\n".encode())
        status, response = self.request(
            "/api/vf/upload", "POST", body.getvalue(),
            f"multipart/form-data; boundary={boundary}")
        self.assertEqual(status, 201)
        self.assertEqual(response["images"], [])
        self.assertTrue(response["errors"])


if __name__ == "__main__":
    unittest.main()
