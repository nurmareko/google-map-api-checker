import http.client
import io
import json
import re
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import call, patch
from urllib.error import HTTPError, URLError

import app


KEY = "test_key_12345678901234567890"
SHA1 = "0123456789ABCDEF0123456789ABCDEF01234567"
ANDROID = {"package_name": "com.example.app", "sha1": SHA1}
COLON_SHA1 = ":".join(SHA1[i:i + 2] for i in range(0, 40, 2))


def invalid_android_values():
    values = [False, True, 0, "", "com.example.app", [], {},
              {"package_name": "com.example.app"}, {"sha1": SHA1}]
    for package in [None, 12, [], "", "example", ".com.example", "com.example.",
                    "com..example", "1com.example", "com.1example", "com._example",
                    "com.ex-ample", "com.ex ample", "com.éxample", "com.ｅxample",
                    "com.example\n", "com.example\r\nX-Injected: yes",
                    "com.example\x00", "a." + "b" * 254]:
        values.append({"package_name": package, "sha1": SHA1})
    for sha1 in [None, 12, [], "", "a" * 39, "a" * 41, "g" * 40,
                 ":".join(["ab"] * 19), ":".join(["ab"] * 21),
                 ":".join(["a"] * 20), COLON_SHA1.replace(":", "-"),
                 COLON_SHA1.replace(":", "", 1), SHA1[:20] + " " + SHA1[20:],
                 SHA1[:20] + "\n" + SHA1[20:], SHA1 + "\r\nX-Injected: yes",
                 SHA1 + "\x00", "Ａ" * 40]:
        values.append({"package_name": "com.example.app", "sha1": sha1})
    return values


class AndroidValidationTests(unittest.TestCase):
    def test_none(self):
        self.assertIsNone(app.validate_android(None))

    def test_valid_normalization(self):
        for package in ["com.example.app", "Com.Example_app2", "a.b", "a." + "b" * 253]:
            for sha1 in [SHA1, SHA1.lower(), COLON_SHA1.lower(), " \t" + COLON_SHA1 + "\r\n"]:
                with self.subTest(package=package, sha1=sha1):
                    self.assertEqual(app.validate_android({"package_name": package, "sha1": sha1}),
                                     {"package_name": package, "sha1": SHA1})

    def test_bad_values_raise_value_error_without_network(self):
        with patch("app.build_opener") as opener:
            for value in invalid_android_values():
                with self.subTest(value=value), self.assertRaises(ValueError):
                    app.validate_android(value)
            opener.assert_not_called()


class ClassificationTests(unittest.TestCase):
    def test_outcomes(self):
        cases = [
            (200, {"status": "OK"}, "available"),
            (200, {"status": "ZERO_RESULTS"}, "available"),
            (200, {"places": []}, "available"),
            (403, {"error": {"message": "Denied", "details": [{"reason": "SERVICE_DISABLED"}]}}, "disabled"),
            (403, {"error": {"message": "Denied", "details": [{"reason": "API_KEY_SERVICE_BLOCKED"}]}}, "restricted"),
            (403, {"error": {"message": "Denied", "details": [{"reason": "API_KEY_ANDROID_APP_BLOCKED"}]}}, "restricted"),
            (400, {"error": {"message": "API key not valid."}}, "invalid_key"),
            (200, {"status": "REQUEST_DENIED", "error_message": "Enable billing"}, "billing"),
            (429, {"error": {"message": "Too many requests"}}, "quota"),
            (200, {"status": "OVER_QUERY_LIMIT"}, "quota"),
            (403, {"error": {"message": "Permission denied"}}, "inconclusive"),
            (400, {"error": {"message": "Invalid argument"}}, "inconclusive"),
            (200, [], "inconclusive"),
        ]
        for code, payload, expected in cases:
            with self.subTest(payload=payload):
                self.assertEqual(app.classify(code, payload)[0], expected)

    def test_fixed_https_requests(self):
        for service in app.SERVICES:
            req = app.make_request(service["id"], "test_key_12345678901234567890")
            self.assertTrue(req.full_url.startswith("https://"))
            self.assertEqual(req.get_header("Accept"), "application/json")
            headers = {name.lower(): value for name, value in req.header_items()}
            self.assertNotIn("x-android-package", headers)
            self.assertNotIn("x-android-cert", headers)
            if req.data:
                self.assertIsInstance(json.loads(req.data), dict)

    def test_secret_redaction(self):
        key = "test_key_12345678901234567890"
        class Response:
            code = 403
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return json.dumps({"error": {"message": key}}).encode()
        with patch("app.build_opener") as opener:
            opener.return_value.open.return_value = Response()
            result = app.probe("geocoding", key)
        self.assertNotIn(key, json.dumps(result))


class AndroidRequestTests(unittest.TestCase):
    def test_android_headers_for_every_service(self):
        methods = set()
        for service in app.SERVICES:
            with self.subTest(service=service["id"]):
                baseline = app.make_request(service["id"], KEY)
                request = app.make_request(service["id"], KEY, ANDROID)
                headers = {name.lower(): value for name, value in request.header_items()}
                self.assertEqual(headers.pop("x-android-package"), ANDROID["package_name"])
                self.assertEqual(headers.pop("x-android-cert"), SHA1)
                self.assertEqual(headers, {name.lower(): value for name, value in baseline.header_items()})
                self.assertEqual(request.full_url, baseline.full_url)
                self.assertEqual(request.data, baseline.data)
                self.assertEqual(request.get_method(), baseline.get_method())
                methods.add(request.get_method())
        self.assertEqual(methods, {"GET", "POST"})

    def test_explicit_none_omits_android_headers(self):
        for service in app.SERVICES:
            with self.subTest(service=service["id"]):
                request = app.make_request(service["id"], KEY, None)
                headers = {name.lower() for name, _ in request.header_items()}
                self.assertNotIn("x-android-package", headers)
                self.assertNotIn("x-android-cert", headers)

    def test_probe_modes_and_propagation(self):
        for service in app.SERVICES:
            for android in [None, ANDROID]:
                with self.subTest(service=service["id"], android=android), patch("app.build_opener") as opener:
                    response = opener.return_value.open.return_value
                    response.__enter__.return_value = response
                    response.code = 200
                    response.read.return_value = b'{"status": "OK"}'
                    result = app.probe(service["id"], KEY, android)
                    self.assertEqual(result["status"], "available")
                    self.assertEqual(result["mode"], "android_rest" if android else "server")
                    opener.return_value.open.assert_called_once()
                    request = opener.return_value.open.call_args.args[0]
                    headers = {name.lower(): value for name, value in request.header_items()}
                    if android:
                        self.assertEqual(headers["x-android-package"], ANDROID["package_name"])
                        self.assertEqual(headers["x-android-cert"], SHA1)
                        message = result["message"].lower()
                        self.assertIn("rest", message)
                        self.assertIn("sdk", message)
                        self.assertRegex(message, r"not|doesn't|no |only")
                    else:
                        self.assertNotIn("x-android-package", headers)
                        self.assertNotIn("x-android-cert", headers)

    def test_default_probe_mode(self):
        with patch("app.build_opener") as opener:
            response = opener.return_value.open.return_value
            response.__enter__.return_value = response
            response.code = 200
            response.read.return_value = b'{}'
            self.assertEqual(app.probe("geocoding", KEY)["mode"], "server")

    def test_android_error_reason_and_network_error_keep_mode(self):
        payload = {"error": {"message": "Denied", "details": [{"reason": "API_KEY_ANDROID_APP_BLOCKED"}]}}
        for android in [None, ANDROID]:
            for error, expected in [
                (HTTPError("https://maps.googleapis.com/", 403, "Forbidden", {},
                           io.BytesIO(json.dumps(payload).encode())), "restricted"),
                (URLError("offline"), "network_error"),
            ]:
                with self.subTest(android=android, status=expected), patch("app.build_opener") as opener:
                    if isinstance(error, HTTPError):
                        self.addCleanup(error.close)
                    opener.return_value.open.side_effect = error
                    result = app.probe("geocoding", KEY, android)
                    self.assertEqual(result["status"], expected)
                    self.assertEqual(result["mode"], "android_rest" if android else "server")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        status, data = response.status, response.read()
        connection.close()
        return status, data

    def test_services_and_page(self):
        status, data = self.request("GET", "/api/services")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["services"]), 12)
        self.assertEqual(self.request("GET", "/")[0], 200)

    def test_rebinding_and_cross_origin_rejected(self):
        self.assertEqual(self.request("GET", "/", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.request("GET", "/", headers={"Origin": "https://evil.example"})[0], 403)

    def test_post_requires_custom_header(self):
        self.assertEqual(self.request("POST", "/api/check", "{}")[0], 403)

    def test_validation_and_mocked_check(self):
        headers = {"Content-Type": "application/json", "X-Local-Request": "1"}
        for body in [{}, [], {"key": "x"}, {"key": "a" * 39, "services": ["unknown"]}]:
            self.assertEqual(self.request("POST", "/api/check", json.dumps(body), headers)[0], 400)
        with patch("app.probe", return_value={"id": "geocoding", "status": "available"}) as probe:
            status, data = self.request("POST", "/api/check", json.dumps({"key": "a" * 39, "services": ["geocoding", "geocoding"]}), headers)
            self.assertEqual(status, 200)
            self.assertEqual(len(json.loads(data)["results"]), 1)
            probe.assert_called_once_with("geocoding", "a" * 39, None)


    def test_android_validation_before_any_probe(self):
        headers = {"Content-Type": "application/json", "X-Local-Request": "1"}
        with patch("app.probe", return_value={"status": "available"}) as probe, patch("app.build_opener") as opener:
            for android in invalid_android_values():
                with self.subTest(android=android):
                    probe.reset_mock()
                    opener.reset_mock()
                    body = {"key": KEY, "services": [s["id"] for s in app.SERVICES], "android": android}
                    status, data = self.request("POST", "/api/check", json.dumps(body), headers)
                    probe.assert_not_called()
                    opener.assert_not_called()
                    self.assertEqual(status, 400)
                    self.assertIn("error", json.loads(data))

    def test_mocked_endpoint_propagates_normalized_android(self):
        headers = {"Content-Type": "application/json", "X-Local-Request": "1"}
        services = [s["id"] for s in app.SERVICES]
        for android in [None, {"package_name": ANDROID["package_name"], "sha1": " " + COLON_SHA1.lower() + " "}]:
            normalized = ANDROID if android else None
            mode = "android_rest" if android else "server"
            with self.subTest(android=android), patch("app.probe") as probe:
                probe.side_effect = lambda service, key, android=None: {"id": service, "status": "available", "mode": mode}
                body = {"key": KEY, "services": services, "android": android}
                status, data = self.request("POST", "/api/check", json.dumps(body), headers)
                self.assertEqual(status, 200)
                probe.assert_has_calls([call(service, KEY, normalized) for service in services], any_order=True)
                self.assertEqual(probe.call_count, len(services))
                self.assertEqual(json.loads(data)["results"],
                                 [{"id": service, "status": "available", "mode": mode} for service in services])


class MarkupTests(unittest.TestCase):
    def test_script_and_accessibility_targets_exist(self):
        class Parser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = set()
                self.references = set()

            def handle_starttag(self, tag, attrs):
                for name, value in attrs:
                    if name == "id":
                        self.ids.add(value)
                    elif name in ("for", "aria-describedby", "aria-labelledby", "aria-controls") and value:
                        self.references.update(value.split())

        html = Path(__file__).with_name("index.html").read_text()
        parser = Parser()
        parser.feed(html)
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]
        script_targets = set(re.findall(r"\$\(['\"]([^'\"]+)['\"]\)", script))
        self.assertEqual(script_targets - parser.ids, set(), "JavaScript references missing elements")
        self.assertEqual(parser.references - parser.ids, set(), "Accessibility references missing elements")

    def test_balanced_markup_and_unique_ids(self):
        class Parser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.stack = []
                self.ids = []
            def handle_starttag(self, tag, attrs):
                if tag not in {"meta", "link", "input", "hr", "br", "img"}:
                    self.stack.append(tag)
                for key, value in attrs:
                    if key == "id": self.ids.append(value)
            def handle_endtag(self, tag):
                if not self.stack or self.stack.pop() != tag:
                    raise AssertionError("Unbalanced closing tag: " + tag)
        parser = Parser()
        parser.feed(Path(__file__).with_name("index.html").read_text())
        self.assertEqual(parser.stack, [])
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        self.assertIn("clear-data", parser.ids)


if __name__ == "__main__":
    unittest.main()
