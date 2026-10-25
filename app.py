#!/usr/bin/env python3
"""Loopback-only Google Maps REST service checker. No third-party dependencies."""
import argparse
import concurrent.futures
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler


SERVICES = [
    {"id": "geocoding", "name": "Geocoding", "description": "Geocode a sample address."},
    {"id": "directions", "name": "Directions (Legacy)", "description": "Request a short driving route."},
    {"id": "distance_matrix", "name": "Distance Matrix (Legacy)", "description": "Request one origin–destination pair."},
    {"id": "elevation", "name": "Elevation", "description": "Look up elevation for one coordinate."},
    {"id": "timezone", "name": "Time Zone", "description": "Look up a time zone for one coordinate."},
    {"id": "roads", "name": "Roads", "description": "Find the nearest road to one coordinate."},
    {"id": "geolocation", "name": "Geolocation", "description": "Locate the server's public IP address."},
    {"id": "places", "name": "Places (New)", "description": "Search for one place using an ID-only field mask."},
    {"id": "places_legacy", "name": "Places (Legacy)", "description": "Run a sample text search."},
    {"id": "routes", "name": "Routes", "description": "Compute one short driving route."},
    {"id": "air_quality", "name": "Air Quality", "description": "Request current conditions at one coordinate."},
    {"id": "address_validation", "name": "Address Validation", "description": "Validate a sample US address."},
]
SERVICE_BY_ID = {s["id"]: s for s in SERVICES}
MAX_RESPONSE = 1_000_000
CHECK_SLOTS = threading.BoundedSemaphore(4)


def validate_android(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("Android identity must contain package_name and sha1.")
    package = value.get("package_name")
    fingerprint = value.get("sha1")
    if not isinstance(package, str) or len(package) > 255 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
        raise ValueError("Enter an Android package name, such as com.example.app.")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){19})", fingerprint.strip()):
        raise ValueError("SHA-1 must be 40 hexadecimal characters, optionally separated into bytes by colons.")
    return {"package_name": package, "sha1": fingerprint.strip().replace(":", "").upper()}


def make_request(service, key, android=None):
    """Build fixed, bounded sample requests; destinations never come from the client."""
    params = {"key": key}
    headers = {"Accept": "application/json", "User-Agent": "LocalMapsChecker/1.0"}
    android = validate_android(android)
    if android:
        headers["X-Android-Package"] = android["package_name"]
        headers["X-Android-Cert"] = android["sha1"]
    body = None
    base = "https://maps.googleapis.com/maps/api/"
    if service == "geocoding":
        url = base + "geocode/json"
        params["address"] = "1600 Amphitheatre Parkway, Mountain View, CA"
    elif service == "directions":
        url = base + "directions/json"
        params.update(origin="37.422,-122.084", destination="37.423,-122.09")
    elif service == "distance_matrix":
        url = base + "distancematrix/json"
        params.update(origins="37.422,-122.084", destinations="37.423,-122.09")
    elif service == "elevation":
        url = base + "elevation/json"
        params["locations"] = "37.422,-122.084"
    elif service == "timezone":
        url = base + "timezone/json"
        params.update(location="37.422,-122.084", timestamp="1700000000")
    elif service == "roads":
        url = "https://roads.googleapis.com/v1/nearestRoads"
        params["points"] = "37.422,-122.084"
    elif service == "places_legacy":
        url = base + "place/textsearch/json"
        params["query"] = "Googleplex Mountain View"
    else:
        endpoints = {
            "geolocation": "https://www.googleapis.com/geolocation/v1/geolocate",
            "places": "https://places.googleapis.com/v1/places:searchText",
            "routes": "https://routes.googleapis.com/directions/v2:computeRoutes",
            "air_quality": "https://airquality.googleapis.com/v1/currentConditions:lookup",
            "address_validation": "https://addressvalidation.googleapis.com/v1:validateAddress",
        }
        url = endpoints[service]
        bodies = {
            "geolocation": {"considerIp": True},
            "places": {"textQuery": "Googleplex Mountain View", "pageSize": 1},
            "routes": {
                "origin": {"location": {"latLng": {"latitude": 37.422, "longitude": -122.084}}},
                "destination": {"location": {"latLng": {"latitude": 37.423, "longitude": -122.09}}},
                "travelMode": "DRIVE",
            },
            "air_quality": {"location": {"latitude": 37.422, "longitude": -122.084}},
            "address_validation": {"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Parkway, Mountain View, CA 94043"]}},
        }
        body = json.dumps(bodies[service]).encode()
        headers["Content-Type"] = "application/json"
        # Modern APIs accept header authentication, avoiding keys in request URLs.
        if service != "geolocation":
            params = {}
            headers["X-Goog-Api-Key"] = key
        if service == "places":
            headers["X-Goog-FieldMask"] = "places.id"
        if service == "routes":
            headers["X-Goog-FieldMask"] = "routes.distanceMeters"
    if params:
        url += "?" + urlencode(params)
    return Request(url, data=body, headers=headers)


def classify(code, payload):
    """Never equate a generic permission denial with an explicitly disabled API."""
    if not isinstance(payload, dict):
        return "inconclusive", "Google returned an unexpected response format."
    error = payload.get("error")
    legacy = payload.get("status", "")
    if isinstance(error, dict):
        message = str(error.get("message", "Google returned an error."))
        details = error.get("details", [])
        reasons = {str(d.get("reason", "")) for d in details if isinstance(d, dict)} if isinstance(details, list) else set()
    else:
        message = str(payload.get("error_message") or error or legacy or "")
        reasons = set()
    lower = message.lower()
    if "API_KEY_INVALID" in reasons or "api key not valid" in lower or "provided api key is invalid" in lower or "invalid api key" in lower or legacy == "REQUEST_DENIED" and "api key is invalid" in lower:
        return "invalid_key", message
    if reasons & {"BILLING_DISABLED", "BILLING_NOT_ACTIVE"} or "billing" in lower:
        return "billing", message
    if "SERVICE_DISABLED" in reasons or any(t in lower for t in ("has not been used in project", "api is not enabled", "api has not been enabled", "service is disabled")):
        return "disabled", message
    if reasons & {"API_KEY_SERVICE_BLOCKED", "API_KEY_HTTP_REFERRER_BLOCKED", "API_KEY_IP_ADDRESS_BLOCKED", "API_KEY_ANDROID_APP_BLOCKED", "API_KEY_IOS_APP_BLOCKED"} or any(t in lower for t in ("referer", "referrer", "ip address", "api restrictions", "requests from this", "not authorized to use this api")):
        return "restricted", message
    if code == 429 or legacy in ("OVER_QUERY_LIMIT", "OVER_DAILY_LIMIT") or any(t in lower for t in ("quota", "rate limit", "resource_exhausted")):
        return "quota", message
    if 200 <= code < 300 and not error and legacy in ("", "OK", "ZERO_RESULTS"):
        return "available", "Request accepted by Google." + (" No matching results for the sample query." if legacy == "ZERO_RESULTS" else "")
    return "inconclusive", message or f"HTTP {code}; enablement could not be established."


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward credentials to redirect destinations.
        return None


def probe(service, key, android=None):
    started = time.monotonic()
    code = None
    try:
        opener = build_opener(NoRedirect())
        try:
            response = opener.open(make_request(service, key, android), timeout=15)
        except HTTPError as exc:
            response = exc
        with response:
            code = response.code
            data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            status, message = "inconclusive", "Google's response exceeded the size limit."
        else:
            try:
                status, message = classify(code, json.loads(data))
            except (ValueError, UnicodeDecodeError):
                status, message = "inconclusive", "Google returned a non-JSON response."
    except (URLError, TimeoutError, OSError):
        status, message = "network_error", "Could not reach Google within 15 seconds. Check your network, proxy, and TLS configuration."
    if android and status == "available":
        message += " REST request only; this does not verify Maps SDK for Android or enforcement of Android restrictions."
    # Never return an exception/URL containing the supplied credential.
    message = message.replace(key, "[REDACTED]")[:2000]
    return {"id": service, "name": SERVICE_BY_ID[service]["name"], "mode": "android_rest" if android else "server", "status": status, "message": message, "http_status": code, "elapsed_ms": round((time.monotonic() - started) * 1000)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, data, content_type="application/json; charset=utf-8"):
        raw = json.dumps(data).encode() if isinstance(data, dict) else data
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def trusted(self):
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in hosts:
            self.reply(403, {"error": "Use the loopback URL printed by the app."})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + h for h in hosts}:
            self.reply(403, {"error": "Cross-origin requests are not allowed."})
            return False
        return True

    def do_GET(self):
        if not self.trusted():
            return
        if self.path == "/":
            self.reply(200, Path(__file__).with_name("index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/services":
            self.reply(200, {"services": SERVICES})
        else:
            self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if not self.trusted():
            return
        if self.path != "/api/check":
            self.reply(404, {"error": "Not found"})
            return
        if self.headers.get("X-Local-Request") != "1" or self.headers.get_content_type() != "application/json":
            self.reply(403, {"error": "A local JSON request is required."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                raise ValueError("Request body must be between 1 and 8192 bytes.")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("Expected a JSON object.")
            key = payload.get("key", "")
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,200}", key):
                raise ValueError("Enter a valid API key (20–200 letters, digits, underscores or hyphens).")
            android = validate_android(payload.get("android"))
            services = payload.get("services")
            if not isinstance(services, list) or not 1 <= len(services) <= len(SERVICES) or any(not isinstance(s, str) or s not in SERVICE_BY_ID for s in services):
                raise ValueError("Select one or more supported services.")
            services = list(dict.fromkeys(services))
        except (ValueError, UnicodeDecodeError) as exc:
            # JSON parser errors do not echo the request body.
            self.reply(400, {"error": str(exc)})
            return
        if not CHECK_SLOTS.acquire(blocking=False):
            self.reply(429, {"error": "Too many active checks. Please wait."})
            return
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda s: probe(s, key, android), services))
            self.reply(200, {"results": results})
        finally:
            CHECK_SLOTS.release()

    def setup(self):
        super().setup()
        self.connection.settimeout(30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        parser.exit(1, f"Could not start local server: {exc}\n")
    print(f"Open http://127.0.0.1:{args.port} — press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
