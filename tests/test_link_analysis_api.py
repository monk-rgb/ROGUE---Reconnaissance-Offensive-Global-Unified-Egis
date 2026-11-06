import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import early_warning_service as service


class LinkAnalysisApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "link-analysis.sqlite3"
        self.database_patch = patch.object(service, "DB_PATH", self.database)
        self.database_patch.start()
        service.initialise_database()
        self.server = service.ThreadingHTTPServer(("127.0.0.1", 0), service.Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)
        self.database_patch.stop()
        self.temporary_directory.cleanup()

    def request(
        self, path, method="GET", official="NG-POL-0001",
        official_type=None, supervisor=False, payload=None, auth_token=None
    ):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"X-NSP-Official": official}
        if official_type is not None:
            headers["X-NSP-Official-Type"] = official_type
        if data is not None:
            headers["Content-Type"] = "application/json"
        if supervisor:
            headers["X-NSP-Supervisor"] = "demo"
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        status = response.code
        result = json.loads(response.read())
        response.close()
        return status, result

    def family_case_payload(self, verification_token):
        return {
            "caseType": "Missing person",
            "person": {
                "fullName": "Synthetic Missing Person", "otherNames": [],
                "age": 16, "dateOfBirth": "", "sex": "Not known",
                "languages": [], "nin": "",
            },
            "photos": ["data:image/png;base64,iVBORw0KGgo="],
            "photoChecks": [],
            "location": {
                "placeName": "Synthetic test location", "state": "Lagos", "lga": "",
                "latitude": None, "longitude": None, "time": "", "accuracy": "unsure",
            },
            "circumstances": {
                "whatHappened": "Synthetic test report.", "lastWith": "",
                "vehicleDetails": "", "ransomDemand": "",
            },
            "reporter": {
                "name": "Synthetic Reporter", "relationship": "Family member",
                "phone": "08000000000", "email": "family@example.test",
            },
            "consent": {
                "accuracyConfirmed": True, "authorisedToReport": True,
                "adultOnBehalf": False,
            },
            "website": "",
            "verificationToken": verification_token,
        }

    def approved_officer_session(self):
        access = self.official_access_payload()
        status, _ = self.request("/api/access-requests", method="POST", payload=access)
        self.assertEqual(status, 201)
        status, _ = self.request(
            f"/api/admin/access-requests/{access['serviceNumber']}/decision",
            method="POST", supervisor=True, official="NG-SUP-TEST",
            payload={"decision": "accept", "reason": "Synthetic case test approval."},
        )
        self.assertEqual(status, 200)
        status, login = self.request(
            "/api/auth/login", method="POST",
            payload={
                "serviceNumber": access["serviceNumber"],
                "officialType": access["officialType"],
                "passcode": access["passcode"],
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 200)
        return access["serviceNumber"], access["officialType"], login["sessionToken"]

    def location_request_payload(self):
        return {
            "legalAuthorization": "SYNTH-WARRANT-001",
            "caseRef": "SYN-CASE-007",
            "reason": "Validate a fictional time-and-place lead.",
            "periodStart": "2026-01-01",
            "periodEnd": "2026-12-31",
            "people": ["00000000041", "00000000201"],
        }

    def official_access_payload(self):
        return {
            "name": "Synthetic Access Test Officer",
            "serviceNumber": "SYN-ACCESS-TEST-1",
            "officialType": "Police officer",
            "agencyUnit": "Synthetic test unit",
            "passcode": "SyntheticPasscode-42",
            "photo": "data:image/png;base64,iVBORw0KGgo=",
            "fingerprintVerified": True,
        }

    def test_platform_logo_is_removed_and_custom_background_is_retained(self):
        with urllib.request.urlopen(self.base_url + "/", timeout=3) as response:
            page = response.read().decode("utf-8")
        self.assertNotIn("rouge-platform-logo", page)
        self.assertIn("platform-background.png", page)
        self.assertNotIn("SYSTEM ONLINE", page)
        with urllib.request.urlopen(self.base_url + "/assets/platform-background.png", timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "image/png")
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(self.base_url + "/assets/rouge-platform-logo.jpg", timeout=3)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_family_report_requires_email_verification_and_status_token(self):
        with patch.object(service, "SMTP_HOST", "smtp.example.test"), \
             patch.object(service, "SMTP_FROM", "noreply@example.test"), \
             patch.object(service, "send_family_verification_email") as send_email:
            send_email.return_value = None
            status, requested = self.request(
                "/api/family/verification/request", method="POST",
                payload={"email": "family@example.test"},
            )
            self.assertEqual(status, 202)
            code = send_email.call_args.args[1]
            status, verified = self.request(
                "/api/family/verification/confirm", method="POST",
                payload={"verificationId": requested["verificationId"], "code": code},
            )
            self.assertEqual(status, 200)

        status, report = self.request(
            "/api/family/cases", method="POST",
            payload=self.family_case_payload(verified["verificationToken"]),
        )
        self.assertEqual(status, 201)
        self.assertEqual(report["report"]["status"], "New")
        self.assertTrue(report["statusCheckToken"])

        status, public_status = self.request(
            "/api/family/reports", method="POST",
            payload={
                "reference": report["report"]["reference"],
                "token": report["statusCheckToken"],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(public_status["report"]["status"], "New")
        self.assertEqual(public_status["timeline"][0]["status"], "New")
        self.assertNotIn("person", public_status)
        self.assertNotIn("reporter", public_status)
        self.assertNotIn("notes", public_status)

        status, denied = self.request(
            "/api/family/reports", method="POST",
            payload={"reference": report["report"]["reference"], "token": "wrong-token"},
        )
        self.assertEqual(status, 404)
        self.assertIn("No family report matched", denied["error"])

    def test_family_portal_and_shared_form_assets_are_served(self):
        for path, expected in (
            ("/family-report", "Family missing-person report"),
            ("/case_forms.js", "renderCaseMap"),
            ("/family_report.js", "/api/family/verification/request"),
        ):
            with urllib.request.urlopen(self.base_url + path, timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(expected.encode(), response.read())

    def test_preconfigured_demo_supervisor_can_sign_in(self):
        status, response = self.request(
            "/api/auth/login", method="POST",
            official="MZ-123", official_type="Military intelligence",
            payload={
                "serviceNumber": "MZ-123",
                "officialType": "Military intelligence",
                "passcode": "12345678",
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(response["sessionToken"])
        connection = sqlite3.connect(self.database)
        try:
            account = connection.execute(
                """SELECT status, official_type, passcode_hash, passcode_salt
                   FROM official_access WHERE service_key='mz-123'"""
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(account[0:2], ("approved", "Military intelligence"))
        self.assertNotEqual(account[2], "12345678")
        self.assertNotEqual(account[3], "12345678")

    def test_case_management_requires_officer_session_and_exposes_timeline_ids(self):
        service_number, official_type, token = self.approved_officer_session()
        headers = {"official":service_number, "official_type":official_type, "auth_token":token}

        status, denied = self.request("/api/cases", official=service_number, official_type=official_type)
        self.assertEqual(status, 401)
        self.assertIn("officer session", denied["error"])

        status, created = self.request(
            "/api/cases", method="POST", payload=self.family_case_payload(""),
            **headers,
        )
        self.assertEqual(status, 201)
        case = created["case"]
        self.assertEqual(case["status"], "Under review")
        self.assertEqual(case["priority"], "Critical")

        status, detail = self.request(
            f"/api/cases/{case['reference']}", official=service_number,
            official_type=official_type, auth_token=token,
        )
        self.assertEqual(status, 200)
        self.assertTrue(detail["case"]["timeline"][0]["id"])
        self.assertEqual(detail["case"]["timeline"][0]["event"], "report_received")

        status, unverified = self.request(
            f"/api/cases/{case['reference']}/status", method="POST",
            payload={"status":"Active", "reason":"Synthetic verification gate test.", "verify":False},
            **headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("must verify", unverified["error"])
        status, active = self.request(
            f"/api/cases/{case['reference']}/status", method="POST",
            payload={"status":"Active", "reason":"Synthetic officer verification.", "verify":True},
            **headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(active["verified"])

        status, notifications = self.request(
            "/api/cases/notifications", official=service_number,
            official_type=official_type, auth_token=token,
        )
        self.assertEqual(status, 200)
        self.assertTrue(any(item["eventType"] == "new_critical_case" for item in notifications["notifications"]))

    def test_workspace_records_survive_database_reopen(self):
        workspace = {
            "citizens": [{"id": "C-1013", "name": "Synthetic test citizen", "photo": "data:image/png;base64,AA=="}],
            "notes": [{"id": "N-1", "text": "Persistent note"}],
            "savedCases": [{"caseRef": "SYN-CASE-010", "citizenId": "C-1013"}],
            "accessRequests": [{"citizenId": "C-1013", "status": "pending"}],
            "audit": [{"who": "NG-POL-0001", "action": "SIGN-IN"}],
        }
        status, empty = self.request("/api/workspace")
        self.assertEqual(status, 200)
        self.assertEqual(empty["workspace"]["citizens"], [])

        status, saved = self.request("/api/workspace", method="POST", payload=workspace)
        self.assertEqual(status, 200)
        self.assertTrue(saved["ok"])

        service.initialise_database()
        status, loaded = self.request("/api/workspace")
        self.assertEqual(status, 200)
        self.assertEqual(loaded["workspace"], workspace)

    def test_workspace_rejects_missing_data_lists(self):
        status, response = self.request(
            "/api/workspace", method="POST", payload={"citizens": []}
        )
        self.assertEqual(status, 400)
        self.assertIn("Workspace data must include", response["error"])

    def test_official_access_requires_supervisor_approval_and_supports_cancellation(self):
        payload = self.official_access_payload()
        status, response = self.request(
            "/api/access-requests", method="POST", payload=payload
        )
        self.assertEqual(status, 201)
        self.assertEqual(response["status"], "pending")

        status, response = self.request(
            "/api/auth/login", method="POST",
            payload={
                "serviceNumber": payload["serviceNumber"],
                "officialType": payload["officialType"],
                "passcode": payload["passcode"],
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 401)

        status, response = self.request("/api/admin/access-requests")
        self.assertEqual(status, 403)
        status, queue = self.request(
            "/api/admin/access-requests", supervisor=True, official="NG-SUP-TEST"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(queue["requests"]), 1)
        self.assertEqual(queue["requests"][0]["serviceNumber"], payload["serviceNumber"])
        self.assertEqual(queue["requests"][0]["photo"], payload["photo"])
        self.assertTrue(queue["requests"][0]["fingerprintEnrolled"])
        self.assertNotIn("passcode", queue["requests"][0])
        self.assertNotIn("passcodeHash", queue["requests"][0])

        status, response = self.request(
            f"/api/admin/access-requests/{payload['serviceNumber']}/decision",
            method="POST", supervisor=True, official="NG-SUP-TEST",
            payload={"decision": "accept", "reason": "Synthetic approval test."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "approved")

        status, response = self.request(
            "/api/auth/login", method="POST",
            payload={
                "serviceNumber": payload["serviceNumber"],
                "officialType": payload["officialType"],
                "passcode": "IncorrectPasscode",
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 401)
        status, response = self.request(
            "/api/auth/login", method="POST",
            payload={
                "serviceNumber": payload["serviceNumber"],
                "officialType": payload["officialType"],
                "passcode": payload["passcode"],
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["officialType"], payload["officialType"])

        status, found = self.request(
            f"/api/admin/services?serviceNumber={payload['serviceNumber']}",
            supervisor=True, official="NG-SUP-TEST",
        )
        self.assertEqual(status, 200)
        self.assertEqual(found["service"]["status"], "approved")

        status, response = self.request(
            f"/api/admin/services/{payload['serviceNumber']}/cancel",
            method="POST", supervisor=True, official="NG-SUP-TEST",
            payload={"reason": "Synthetic cancellation test."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "cancelled")
        status, response = self.request(
            "/api/auth/login", method="POST",
            payload={
                "serviceNumber": payload["serviceNumber"],
                "officialType": payload["officialType"],
                "passcode": payload["passcode"],
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 401)

        connection = sqlite3.connect(self.database)
        try:
            stored = connection.execute(
                """SELECT passcode_salt, passcode_hash, status FROM official_access
                   WHERE service_key=?""",
                (payload["serviceNumber"].casefold(),),
            ).fetchone()
            actions = [row[0] for row in connection.execute("SELECT action FROM audit_log")]
        finally:
            connection.close()
        self.assertNotEqual(stored[0], payload["passcode"])
        self.assertNotEqual(stored[1], payload["passcode"])
        self.assertEqual(stored[2], "cancelled")
        self.assertIn("OFFICIAL ACCESS REQUEST SUBMITTED", actions)
        self.assertIn("OFFICIAL ACCESS REQUEST ACCEPT", actions)
        self.assertIn("OFFICIAL SERVICE CANCELLED", actions)

    def test_official_access_validates_photo_passcode_and_supervisor_decision(self):
        payload = self.official_access_payload()
        invalid = dict(payload, photo="data:image/png;base64,AA==")
        status, response = self.request(
            "/api/access-requests", method="POST", payload=invalid
        )
        self.assertEqual(status, 400)

        invalid = dict(payload, passcode="short")
        status, response = self.request(
            "/api/access-requests", method="POST", payload=invalid
        )
        self.assertEqual(status, 400)

        status, response = self.request(
            f"/api/admin/access-requests/{payload['serviceNumber']}/decision",
            method="POST", supervisor=True,
            payload={"decision": "accept", "reason": "Not found."},
        )
        self.assertEqual(status, 404)

        status, response = self.request(
            "/api/access-requests", method="POST", payload=payload
        )
        self.assertEqual(status, 201)
        status, response = self.request(
            f"/api/admin/access-requests/{payload['serviceNumber']}/decision",
            method="POST", supervisor=True, official="NG-SUP-TEST",
            payload={"decision": "reject", "reason": "Synthetic rejection test."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "rejected")
        status, response = self.request(
            "/api/auth/login", method="POST",
            payload={
                "serviceNumber": payload["serviceNumber"],
                "officialType": payload["officialType"],
                "passcode": payload["passcode"],
                "fingerprintVerified": True,
            },
        )
        self.assertEqual(status, 401)

    def test_alert_review_status_is_available_in_the_feed_after_refresh(self):
        alert_id = "SYN-ALERT-STATUS-1"
        with patch.object(service, "ALERTS", [{"id": alert_id, "title": "Synthetic alert"}]):
            status, action = self.request(
                f"/api/alerts/{alert_id}/action",
                method="POST",
                payload={"action": "flag", "reason": "Synthetic test review."},
            )
            self.assertEqual(status, 200)
            self.assertTrue(action["ok"])

            status, feed = self.request("/api/alerts")
            self.assertEqual(status, 200)
            self.assertEqual(
                feed["alerts"][0]["reviewStatus"]["action"],
                "flag",
            )
            self.assertTrue(feed["alerts"][0]["reviewStatus"]["updatedAt"])

            status, action = self.request(
                f"/api/alerts/{alert_id}/action",
                method="POST",
                payload={"action": "mark_false_alarm", "reason": "Updated synthetic test status."},
            )
            self.assertEqual(status, 200)
            self.assertTrue(action["ok"])
            status, feed = self.request("/api/alerts")
            self.assertEqual(status, 200)
            self.assertEqual(feed["alerts"][0]["reviewStatus"]["action"], "mark_false_alarm")

    def test_media_alert_feed_contains_only_news_with_review_status(self):
        flagged_id = "SYN-MEDIA-STATUS-1"
        with patch.object(
            service,
            "ALERTS",
            [
                {
                    "id": flagged_id, "title": "Synthetic flagged news",
                    "category": "Synthetic category", "snippet": "Details not shown to media.",
                    "sources": [{"platform": "Synthetic source"}],
                },
                {
                    "id": "SYN-MEDIA-UNREVIEWED", "title": "Unreviewed synthetic news",
                    "category": "Synthetic category", "snippet": "Unreviewed details.",
                },
            ],
        ):
            status, action = self.request(
                f"/api/alerts/{flagged_id}/action",
                method="POST",
                payload={"action": "flag", "reason": "Synthetic media feed test."},
            )
            self.assertEqual(status, 200)
            self.assertTrue(action["ok"])

            status, feed = self.request("/api/alerts", official_type="Media official")
            self.assertEqual(status, 200)
            self.assertEqual(len(feed["alerts"]), 1)
            self.assertEqual(feed["alerts"][0]["id"], flagged_id)
            self.assertEqual(feed["alerts"][0]["title"], "Synthetic flagged news")
            self.assertEqual(feed["alerts"][0]["reviewStatus"]["action"], "flag")
            self.assertNotIn("connectors", feed)
            self.assertNotIn("snippet", feed["alerts"][0])
            self.assertNotIn("sources", feed["alerts"][0])

    def test_location_request_requires_approval_and_expires_after_24_hours(self):
        status, created = self.request(
            "/api/link-analysis/location-requests", method="POST", payload=self.location_request_payload()
        )
        self.assertEqual(status, 201)
        request_id = created["request"]["id"]
        self.assertEqual(created["request"]["status"], "pending")

        status, pending = self.request(
            "/api/link-analysis/location-requests/pending",
            official="NG-POL-SUP-01", supervisor=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in pending["requests"]], [request_id])

        status, self_decision = self.request(
            f"/api/link-analysis/location-requests/{request_id}/decision",
            method="POST", official="NG-POL-0001", supervisor=True,
            payload={"decision": "approve", "reason": "Cannot approve own request."},
        )
        self.assertEqual(status, 403)
        self.assertIn("cannot approve their own", self_decision["error"])

        before_decision = time.time()
        status, decision = self.request(
            f"/api/link-analysis/location-requests/{request_id}/decision",
            method="POST", official="NG-POL-SUP-01", supervisor=True,
            payload={"decision": "approve", "reason": "Synthetic approval for the demo."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision["request"]["status"], "approved")
        expiry_seconds = decision["request"]["expiresAt"] / 1000
        self.assertGreaterEqual(expiry_seconds, before_decision + 24 * 60 * 60 - 2)
        self.assertLessEqual(expiry_seconds, time.time() + 24 * 60 * 60 + 2)

        status, own_request = self.request(
            f"/api/link-analysis/location-requests/{request_id}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(own_request["request"]["status"], "approved")
        self.assertEqual(own_request["request"]["people"], self.location_request_payload()["people"])

    def test_saved_board_stores_case_and_synthetic_record_ids_and_audits(self):
        payload = {
            "caseRef": "SYN-CASE-009",
            "reason": "Save an illustrative family lead.",
            "type": "Family link",
            "people": ["00000000041", "00000000201"],
            "links": [{"firstName": "Amaka Nwosu", "secondName": "Chika Nwosu", "confidence": "High"}],
            "authorizationId": None,
        }
        status, response = self.request("/api/link-analysis/boards", method="POST", payload=payload)
        self.assertEqual(status, 201)
        self.assertEqual(response["board"]["people"], payload["people"])
        status, listing = self.request("/api/link-analysis/boards")
        self.assertEqual(status, 200)
        self.assertEqual(listing["boards"][0]["id"], response["board"]["id"])
        self.assertEqual(listing["boards"][0]["people"], payload["people"])
        connection = sqlite3.connect(self.database)
        try:
            actions = [row[0] for row in connection.execute("SELECT action FROM audit_log")]
        finally:
            connection.close()
        self.assertIn("LINK ANALYSIS BOARD SAVED", actions)
        self.assertIn("LINK ANALYSIS SAVED BOARDS VIEWED", actions)

    def test_location_request_rejects_incomplete_context_and_invalid_people(self):
        payload = self.location_request_payload()
        payload["reason"] = ""
        status, response = self.request(
            "/api/link-analysis/location-requests", method="POST", payload=payload
        )
        self.assertEqual(status, 400)
        payload = self.location_request_payload()
        payload["people"] = ["not-a-nin", "00000000201"]
        status, response = self.request(
            "/api/link-analysis/location-requests", method="POST", payload=payload
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
