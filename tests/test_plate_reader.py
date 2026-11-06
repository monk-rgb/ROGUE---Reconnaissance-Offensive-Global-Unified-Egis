from __future__ import annotations

import io
import email.message
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

import plate_reader


class PlateReaderTests(unittest.TestCase):
    def test_normalize_plate_removes_spaces_and_separators(self) -> None:
        self.assertEqual(plate_reader.normalize_plate("abC-123 xy"), "ABC123XY")

    def test_hikvision_recording_extensions_are_accepted(self) -> None:
        self.assertTrue({".dav", ".264", ".h264"}.issubset(plate_reader.ALLOWED_EXTENSIONS))

    def test_ocr_match_combines_adjacent_words_on_the_same_line(self) -> None:
        data = {
            "text": ["ABC", "123", "XY"],
            "conf": ["80", "90", "75"],
            "page_num": ["1", "1", "1"],
            "block_num": ["1", "1", "1"],
            "par_num": ["1", "1", "1"],
            "line_num": ["1", "1", "1"],
        }
        fake_ocr = mock.Mock()
        fake_ocr.image_to_data.return_value = data
        fake_ocr.Output.DICT = "dict"
        with mock.patch.object(plate_reader, "pytesseract", fake_ocr):
            matches = plate_reader._ocr_candidates(np.zeros((2, 2, 3), dtype=np.uint8),
                                                   "ABC123XY", 7)
        self.assertEqual(matches, [75.0])

    def test_frame_matching_checks_overlapping_full_resolution_tiles(self) -> None:
        frame = np.zeros((200, 400, 3), dtype=np.uint8)
        with (
            mock.patch.object(plate_reader, "_get_plate_cascade", return_value=None),
            mock.patch.object(
                plate_reader, "_ocr_candidates",
                side_effect=lambda image, _target, _psm: (
                    [88.2] if image.shape[:2] == (110, 220) else []
                ),
            ) as ocr_candidates,
        ):
            matches = plate_reader._frame_matches(frame, "ABC123")
        self.assertEqual(matches, [88.2])
        self.assertTrue(any(call.args[0].shape[:2] == (110, 220)
                            for call in ocr_candidates.call_args_list))

    def test_frame_matching_retries_tiles_at_double_resolution(self) -> None:
        frame = np.zeros((200, 400, 3), dtype=np.uint8)
        with (
            mock.patch.object(plate_reader, "_get_plate_cascade", return_value=None),
            mock.patch.object(
                plate_reader, "_ocr_candidates",
                side_effect=lambda image, _target, _psm: (
                    [88.2] if image.shape[:2] == (220, 440) else []
                ),
            ) as ocr_candidates,
        ):
            matches = plate_reader._frame_matches(frame, "ABC123")
        self.assertEqual(matches, [88.2])
        self.assertTrue(any(call.args[0].shape[:2] == (220, 440)
                            for call in ocr_candidates.call_args_list))

    def test_video_scan_updates_progress_and_returns_timestamped_frame(self) -> None:
        class FakeCapture:
            def __init__(self, _path: str) -> None:
                self.frames = [np.zeros((20, 40, 3), dtype=np.uint8) for _ in range(8)]

            def isOpened(self) -> bool:
                return True

            def get(self, prop: int) -> float:
                values = {
                    plate_reader.cv2.CAP_PROP_FPS: 8,
                    plate_reader.cv2.CAP_PROP_FRAME_COUNT: 8,
                    plate_reader.cv2.CAP_PROP_FRAME_WIDTH: 40,
                    plate_reader.cv2.CAP_PROP_FRAME_HEIGHT: 20,
                }
                return values[prop]

            def read(self) -> tuple[bool, np.ndarray | None]:
                if not self.frames:
                    return False, None
                return True, self.frames.pop(0)

            def release(self) -> None:
                return None

        with tempfile.NamedTemporaryFile(delete=False) as video:
            video_path = video.name
        plate_reader._JOBS["PL-UNIT"] = {
            "id": "PL-UNIT", "owner": "unit", "plate": "ABC123", "normalizedPlate": "ABC123",
            "location": "Test location", "status": "queued", "progress": 0,
            "processedFrames": 0, "totalFrames": 0, "matches": [], "error": "",
            "createdAt": 0, "completedAt": 0,
        }
        try:
            with (
                mock.patch.object(plate_reader.cv2, "VideoCapture", FakeCapture),
                mock.patch.object(plate_reader, "_frame_matches",
                                  side_effect=[[], [88.2], [], [91.0]]),
                mock.patch.object(plate_reader, "audit_event"),
            ):
                plate_reader._scan_video("PL-UNIT", video_path)
            result = plate_reader._JOBS["PL-UNIT"]
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["progress"], 100)
            self.assertEqual(result["processedFrames"], 4)
            self.assertEqual(len(result["matches"]), 1)
            self.assertEqual(result["matches"][0]["timestamp"], "00:00:00")
            self.assertTrue(result["matches"][0]["frameJpeg"])
            self.assertFalse(Path(video_path).exists())
        finally:
            plate_reader._JOBS.pop("PL-UNIT", None)
            if Path(video_path).exists():
                Path(video_path).unlink()

    def test_authenticated_multipart_upload_queues_a_search(self) -> None:
        boundary = "plate-test-boundary"
        parts = [
            ("video", "clip.mp4", b"video-bytes"),
            ("plate", None, b"ABC-123"),
            ("location", None, b"Main entrance"),
        ]
        body = bytearray()
        for name, filename, data in parts:
            disposition = f'form-data; name="{name}"'
            if filename:
                disposition += f'; filename="{filename}"'
            body.extend(f"--{boundary}\r\nContent-Disposition: {disposition}\r\n".encode())
            if filename:
                body.extend(b"Content-Type: video/mp4\r\n")
            body.extend(b"\r\n" + data + b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())

        class FakeHandler:
            def __init__(self) -> None:
                self.headers = email.message.Message()
                self.headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                self.headers["Content-Length"] = str(len(body))
                self.rfile = io.BytesIO(body)
                self.response: tuple[int, dict] | None = None

            def _require_case_staff(self) -> str:
                return "Police officer"

            def _session_official(self) -> tuple[str, str]:
                return "plate-test-officer", "Police officer"

            def _json(self, status: int, payload: dict) -> None:
                self.response = (status, payload)

        handler = FakeHandler()
        with (
            mock.patch.object(plate_reader, "_capability", return_value=(True, "")),
            mock.patch.object(plate_reader._WORKERS, "submit") as submit,
            mock.patch.object(plate_reader, "audit_event"),
        ):
            self.assertTrue(plate_reader.handle_post(handler, "/api/plate-search"))
        self.assertEqual(handler.response[0], 202)
        job_id = handler.response[1]["job"]["id"]
        queued_job = plate_reader._JOBS.pop(job_id)
        self.assertEqual(queued_job["plate"], "ABC-123")
        self.assertEqual(queued_job["location"], "Main entrance")
        video_path = submit.call_args.args[2]
        self.assertTrue(Path(video_path).is_file())
        Path(video_path).unlink()

    def test_search_job_is_private_to_its_submitting_officer(self) -> None:
        class FakeHandler:
            response: tuple[int, dict] | None = None

            def _require_case_staff(self) -> str:
                return "Police officer"

            def _session_official(self) -> tuple[str, str]:
                return "another-officer", "Police officer"

            def _json(self, status: int, payload: dict) -> None:
                self.response = (status, payload)

        plate_reader._JOBS["PL-PRIVATE"] = {
            "id": "PL-PRIVATE", "owner": "original-officer", "plate": "ABC123",
            "normalizedPlate": "ABC123", "location": "Test", "status": "complete",
            "progress": 100, "processedFrames": 2, "totalFrames": 2, "matches": [],
            "error": "", "createdAt": 1, "completedAt": 1,
        }
        try:
            handler = FakeHandler()
            self.assertTrue(plate_reader.handle_get(handler, "/api/plate-search/jobs/PL-PRIVATE"))
            self.assertEqual(handler.response[0], 403)
        finally:
            plate_reader._JOBS.pop("PL-PRIVATE", None)


if __name__ == "__main__":
    unittest.main()
