import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import early_warning_service as service


class EarlyWarningPipelineTests(unittest.TestCase):
    def test_classifies_incidents_and_avoids_sports_false_positives(self):
        self.assertEqual(
            service.classify("Gunmen attack a village in Kaduna after a curfew."),
            "Attack report",
        )
        self.assertEqual(
            service.classify("Unverified kidnapping claim circulated in Borno."),
            "Rumor risk",
        )
        self.assertEqual(
            service.classify("Residents organised a protest against the curfew in Bauchi."),
            "Protest or unrest",
        )
        self.assertEqual(
            service.classify("Fact check: a fabricated report falsely claims an attack occurred in Bama."),
            "Misinformation",
        )
        self.assertEqual(
            service.classify("Gunmen kidnapped two residents in Zamfara."),
            "Kidnapping report",
        )
        self.assertEqual(
            service.classify("Residents report a bomb threat in Kaduna."),
            "Threat report",
        )
        self.assertEqual(
            service.classify("Reports of violence in a community in Borno."),
            "Attack report",
        )
        self.assertIsNone(service.classify("UCL: Arsenal vs Lille and other clashes"))
        self.assertIsNone(service.classify("Court strikes out charges against a defendant"))

    def test_extracts_nigerian_state_and_lga(self):
        self.assertEqual(
            service.extract_location("Residents report an attack near Zaria, Kaduna State."),
            {"state": "Kaduna", "lga": "Zaria"},
        )
        self.assertEqual(
            service.extract_location("Residents report unrest in Bende, Abia State."),
            {"state": "Abia", "lga": "Bende"},
        )
        self.assertEqual(len(service.STATE_GAZETTEER), 37)
        self.assertEqual(sum(map(len, service.STATE_GAZETTEER.values())), 774)

    def test_news_rss_parser_and_gdelt_use_nigeria_event_terms(self):
        connector = service.RSSConnector("news-test", "Test News", "https://example.test/feed")
        feed = b"""<?xml version="1.0"?><rss><channel><item>
            <title>Security incident in Kaduna</title>
            <description>Residents report an attack near Zaria, Kaduna State.</description>
            <link>https://example.test/story?id=1</link>
            <pubDate>Mon, 12 Oct 2026 10:00:00 GMT</pubDate>
        </item></channel></rss>"""
        parsed = service.parse_feed(feed, connector)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["link"], "https://example.test/story?id=1")
        self.assertEqual(parsed[0]["location"], {"state": "Kaduna", "lga": "Zaria"})

        gdelt = service.GDELTConnector()
        query = service.urllib.parse.parse_qs(service.urllib.parse.urlsplit(gdelt.url).query)["query"][0]
        self.assertIn("Nigeria", query)
        self.assertIn('"Kaduna"', query)
        self.assertNotIn("sourcecountry:NG", query)
        self.assertEqual(
            service.safe_datetime("20261012T100000Z"),
            "2026-10-12T10:00:00+00:00",
        )
        self.assertEqual(
            service.clean_public_text("Update from @example_handle and officer@example.test"),
            "Update from [account omitted] and officer@example.test",
        )

    def test_source_articles_are_persisted_and_deduplicated_across_connectors_and_runs(self):
        item = {
            "platform": "Punch", "category": "News", "headline": "A report",
            "snippet": "A report about an attack in Kaduna.",
            "link": "https://punchng.com/story/?utm_source=rss",
            "timestamp": "2026-10-12T10:00:00+00:00",
            "sourceKey": "news-punch", "location": {"state": "Kaduna", "lga": ""},
        }
        duplicate_from_gdelt = {
            **item, "platform": "GDELT", "sourceKey": "gdelt",
            "link": "https://punchng.com/story/",
        }
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(service, "DB_PATH", Path(directory) / "items.sqlite3"):
                service.initialise_database()
                first_load, first_inserted = service.persist_and_load_source_items(
                    [item, duplicate_from_gdelt], now=1_800_000_000
                )
                second_load, second_inserted = service.persist_and_load_source_items(
                    [item], now=1_800_000_001
                )
                self.assertEqual(first_inserted, 1)
                self.assertEqual(second_inserted, 0)
                self.assertEqual(len(first_load), 1)
                self.assertEqual(len(second_load), 1)
                self.assertEqual(second_load[0]["sourceKey"], "news-punch")
                connection = sqlite3.connect(service.DB_PATH)
                try:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM source_items").fetchone()[0], 1)
                finally:
                    connection.close()

    def test_local_env_example_settings_are_supported_without_overriding_process_env(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "NSP_PORT=8766\nNSP_DB_PATH=./audit.sqlite3\n",
                encoding="utf-8",
            )
            with patch.object(service, "ROOT", root), patch.dict(os.environ, {}, clear=True):
                service.load_local_environment()
                self.assertEqual(os.environ["NSP_PORT"], "8766")
                self.assertEqual(os.environ["NSP_DB_PATH"], "./audit.sqlite3")

    def test_clusters_matching_reports_and_explains_confidence(self):
        reports = [
            {
                "platform": "Punch", "category": "News",
                "snippet": "Gunmen attacked a village near Zaria Kaduna.",
                "link": "https://punchng.com/sample", "timestamp": "2026-10-12T10:00:00+00:00",
                "location": {"state": "Kaduna", "lga": "Zaria"}, "language": "English",
                "engagement": {"likes": 0, "shares": 0, "comments": 0},
                "sourceKey": "news-punch", "domain": "punchng.com",
            },
            {
                "platform": "Vanguard", "category": "News",
                "snippet": "Gunmen attacked a village near Zaria Kaduna.",
                "link": "https://vanguardngr.com/sample", "timestamp": "2026-10-12T10:01:00+00:00",
                "location": {"state": "Kaduna", "lga": "Zaria"}, "language": "English",
                "engagement": {"likes": 0, "shares": 0, "comments": 0},
                "sourceKey": "news-vanguard", "domain": "vanguardngr.com",
            },
        ]
        alert = service.make_alert(reports)
        self.assertEqual(alert["confidence"], "Medium")
        self.assertEqual(alert["sourceCount"], 2)
        self.assertIn("credible news outlet matched", alert["confidenceReasons"])
        self.assertEqual(len(alert["sources"]), 2)
        self.assertEqual(alert["sources"][0]["articles"][0]["headline"], "Gunmen attacked a village near Zaria Kaduna")
        self.assertTrue(alert["sources"][0]["articles"][0]["link"].startswith("https://"))
        self.assertFalse(alert["requiresAnalystConfirmation"])

    def test_optional_connectors_are_unconfigured_stubs(self):
        active_ids = {"news-punch", "news-vanguard", "news-premium-times", "news-channels",
                      "news-daily-trust", "news-the-nation", "news-guardian", "news-bbc-pidgin", "gdelt"}
        self.assertTrue(active_ids.issubset(service.CONNECTORS))
        self.assertTrue(all(service.CONNECTORS[key].configured for key in active_ids))
        self.assertTrue(all(
            not connector.configured
            for key, connector in service.CONNECTORS.items() if key not in active_ids
        ))

    def test_social_connectors_use_tokens_without_exposing_account_handles(self):
        x_connector = service.XRecentSearchConnector("x-test-token")
        x_post = {
            "id": "12345",
            "text": "Threat reported in Kaduna by @local_reporter",
            "created_at": "2026-10-12T10:00:00Z",
            "lang": "en",
            "public_metrics": {"like_count": 4, "retweet_count": 2, "reply_count": 1},
        }
        with patch.object(service, "request_json", return_value={"data": [x_post]}) as request:
            x_items = x_connector.fetch()
        self.assertEqual(x_items[0]["category"], "X")
        self.assertEqual(x_items[0]["link"], "https://x.com/i/web/status/12345")
        self.assertNotIn("@local_reporter", x_items[0]["snippet"])
        self.assertEqual(x_items[0]["engagement"]["shares"], 2)
        self.assertIn("Bearer x-test-token", request.call_args.args[1]["Authorization"])
        self.assertEqual(
            service.make_alert(x_items)["verificationLabel"],
            "Unverified, social media only",
        )
        self.assertFalse(service.XRecentSearchConnector("").configured)

        meta_token = "meta-test-token"
        facebook = service.MetaGraphConnector("facebook-pages", "Facebook", meta_token)
        facebook_post = {
            "message": "A threat was reported in Kaduna.",
            "permalink_url": "https://facebook.com/page/posts/123",
            "created_time": "2026-10-12T10:00:00+0000",
        }
        with patch.object(service, "request_json", return_value={"data": [facebook_post]}) as request:
            facebook_items = facebook.fetch()
        self.assertEqual(facebook_items[0]["category"], "Facebook")
        self.assertEqual(facebook_items[0]["sourceKey"], "facebook-pages")
        self.assertIn("Bearer meta-test-token", request.call_args.args[1]["Authorization"])

        instagram = service.MetaGraphConnector("instagram-graph", "Instagram", meta_token)
        with patch.object(service, "request_json", side_effect=[
            {"id": "page-123", "instagram_business_account": {"id": "ig-456"}},
            {"data": [{
                "caption": "Violence reported in Borno.",
                "permalink": "https://instagram.com/p/example",
                "timestamp": "2026-10-12T10:00:00+0000",
            }]},
        ]):
            instagram_items = instagram.fetch()
        self.assertEqual(instagram_items[0]["category"], "Instagram")
        self.assertEqual(instagram_items[0]["sourceKey"], "instagram-graph")

    def test_connector_failures_keep_an_actionable_error(self):
        connector = service.Connector("timeout-test", "Timeout test", "Other")
        with patch.object(connector, "fetch", side_effect=TimeoutError()):
            self.assertEqual(connector.get_items(), [])
        self.assertEqual(connector.status, "failing")
        self.assertIn("timed out", connector.last_error)
        rate_limited = service.Connector("rate-limit-test", "Rate limit test", "Other")
        error = service.urllib.error.HTTPError("", 429, "Too Many Requests", {}, None)
        with patch.object(rate_limited, "fetch", side_effect=error):
            rate_limited.get_items()
        self.assertEqual(rate_limited.status, "failing")
        self.assertIn("next automatic attempt is in 12 minutes", rate_limited.last_error)

    def test_high_alert_needs_independent_sources_news_and_baseline(self):
        reports = [
            {
                "platform": name, "category": category,
                "snippet": "Bomb attack reported in Maiduguri, Borno State.",
                "link": f"https://{domain}/sample", "timestamp": "2026-10-12T10:00:00+00:00",
                "location": {"state": "Borno", "lga": "Maiduguri"}, "language": "English",
                "engagement": {"likes": 0, "shares": 0, "comments": 0},
                "sourceKey": source_key, "domain": domain,
            }
            for name, category, domain, source_key in [
                ("Punch", "News", "punchng.com", "news-punch"),
                ("Vanguard", "News", "vanguardngr.com", "news-vanguard"),
                ("GDELT", "Other", "gdeltproject.org", "gdelt"),
            ]
        ]
        alert = service.make_alert(reports)
        self.assertEqual(alert["confidence"], "High")
        self.assertTrue(alert["requiresAnalystConfirmation"])

    def test_similar_headlines_cluster_as_one_event(self):
        first = {
            "platform": "Punch", "category": "News", "headline": "Soldiers kill 40 terrorists planning attack in Borno",
            "snippet": "Soldiers kill 40 terrorists planning attack in Borno.",
            "link": "https://punchng.com/one", "timestamp": "2026-10-12T10:00:00+00:00",
            "location": {"state": "Borno", "lga": ""}, "language": "English",
            "engagement": {"likes": 0, "shares": 0, "comments": 0},
            "sourceKey": "news-punch", "domain": "punchng.com",
        }
        second = {
            **first,
            "platform": "Premium Times",
            "headline": "Nigerian troops kill 40 ISWAP fighters in Borno",
            "snippet": "Nigerian troops kill 40 ISWAP fighters in Borno.",
            "link": "https://premiumtimesng.com/two",
            "sourceKey": "news-premium-times", "domain": "premiumtimesng.com",
        }
        self.assertTrue(service.same_event(second, [first], service.normalised_key(second)))

    def test_fallback_data_is_explicitly_simulated(self):
        items = service.simulated_items()
        self.assertTrue(items)
        self.assertTrue(all(item["simulated"] for item in items))
        self.assertTrue(all(item["platform"] == "SIMULATED DATA" for item in items))
        self.assertTrue(all(item["link"].startswith("https://example.invalid/") for item in items))

    def test_pipeline_uses_simulated_fallback_only_when_no_connector_is_live(self):
        with (
            patch.dict(service.CONNECTORS, {}, clear=True),
            patch.object(service, "ITEM_WINDOW", {}),
            patch.object(service, "ALERTS", []),
            patch.object(service, "PENDING_HIGH", {}),
            patch.object(service, "PREVIOUS_EVENT_COUNTS", {}),
            patch.object(service, "REVIEW_DECISIONS", {}),
        ):
            service.CONNECTORS["unconfigured"] = service.Connector(
                "unconfigured", "Unconfigured test source", "Other", configured=False
            )
            service.run_pipeline()
            result = service.public_state()
            self.assertTrue(result["simulated"])
            self.assertTrue(result["alerts"])
            self.assertTrue(all(alert["simulated"] for alert in result["alerts"]))

    def test_simulated_banner_stays_until_a_connector_is_live(self):
        connector = service.Connector(
            "news", "Test news connector", "News", configured=True
        )
        connector.status = "failing"
        with (
            patch.dict(service.CONNECTORS, {"news": connector}, clear=True),
            patch.object(service, "ALERTS", [{"simulated": False}]),
        ):
            self.assertTrue(service.public_state()["simulated"])
            connector.status = "active"
            self.assertFalse(service.public_state()["simulated"])

    def test_audit_table_rejects_updates_and_deletes(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(service, "DB_PATH", Path(directory) / "audit.sqlite3"):
                service.initialise_database()
                service.audit_event("DEMO-UNIT-1", "TEST EVENT", "unit test", "DEMO-CASE-1")
                connection = sqlite3.connect(service.DB_PATH)
                try:
                    with self.assertRaises(sqlite3.DatabaseError):
                        connection.execute("UPDATE audit_log SET reason='changed' WHERE id=1")
                    with self.assertRaises(sqlite3.DatabaseError):
                        connection.execute("DELETE FROM audit_log WHERE id=1")
                finally:
                    connection.close()


if __name__ == "__main__":
    unittest.main()
