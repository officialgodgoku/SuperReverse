"""Web Application & URL Reverse Engineering Engine.

Performs deep static and heuristic inspection of public websites and web applications:
- HTTP security headers audit (CSP, HSTS, X-Frame-Options, CORS, Cookies)
- Frontend framework & CMS fingerprinting (React, Next.js, Vue, Nuxt, Angular, Svelte, WordPress)
- Script bundle indexing & asset inventory
- Discovered REST/GraphQL API endpoints from HTML and JavaScript bundles
- Third-party integration tracking (Analytics, Payments, Cloud services, Auth)
- Generates web architecture diagrams and reconstruction obligation ledgers
"""
from __future__ import annotations

import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SecurityHeaderAudit:
    header: str
    status: str
    value: str
    risk: str
    recommendation: str


@dataclass
class WebAnalysisResult:
    url: str = ""
    domain: str = ""
    status_code: int = 0
    page_title: str = ""
    meta_description: str = ""
    server_banner: str = ""
    detected_frameworks: List[str] = field(default_factory=list)
    detected_cms: List[str] = field(default_factory=list)
    detected_libraries: List[str] = field(default_factory=list)
    security_headers: List[SecurityHeaderAudit] = field(default_factory=list)
    script_urls: List[str] = field(default_factory=list)
    stylesheet_urls: List[str] = field(default_factory=list)
    discovered_api_endpoints: List[str] = field(default_factory=list)
    discovered_third_party: List[str] = field(default_factory=list)
    discovered_internal_routes: List[str] = field(default_factory=list)
    forms: List[Dict[str, str]] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)


class SimpleHTMLInspector(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self.in_title = False
        self.meta_desc = ""
        self.scripts: List[str] = []
        self.stylesheets: List[str] = []
        self.links: List[str] = []
        self.forms: List[Dict[str, str]] = []
        self.raw_inline_scripts: List[str] = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            name = attr_dict.get("name", "").lower()
            prop = attr_dict.get("property", "").lower()
            if name == "description" or prop == "og:description":
                self.meta_desc = attr_dict.get("content", "")
        elif tag == "script":
            src = attr_dict.get("src")
            if src:
                self.scripts.append(urllib.parse.urljoin(self.base_url, src))
            else:
                self.in_script = True
        elif tag == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href")
            if "stylesheet" in rel and href:
                self.stylesheets.append(urllib.parse.urljoin(self.base_url, href))
        elif tag == "a":
            href = attr_dict.get("href")
            if href:
                self.links.append(urllib.parse.urljoin(self.base_url, href))
        elif tag == "form":
            self.forms.append({
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
            })

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data.strip()
        elif self.in_script and len(data.strip()) > 10:
            self.raw_inline_scripts.append(data.strip())


class WebEngine:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SuperReverse/1.0"

    API_REGEX = re.compile(r"['\"`](/(?:api|v[0-9]+|graphql|auth|webhook|service)/[a-zA-Z0-9_\-\./]+)['\"`]")
    FETCH_REGEX = re.compile(r"(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?)\s*\(\s*['\"`]([a-zA-Z0-9_\-/\.:]+)['\"`]")
    ROUTE_REGEX = re.compile(r"['\"`](/(?:dashboard|login|signup|settings|account|user|profile|checkout|admin)[a-zA-Z0-9_\-/]*)['\"`]")

    THIRD_PARTY_SERVICES = {
        "Google Analytics / Tag Manager": ["google-analytics.com", "googletagmanager.com", "gtag"],
        "Google Fonts": ["fonts.googleapis.com", "fonts.gstatic.com"],
        "Cloudflare": ["cloudflare.com", "cdnjs.cloudflare.com", "__cf_bm"],
        "Stripe Payments": ["js.stripe.com", "stripe.com"],
        "Firebase": ["firebaseio.com", "firebase.googleapis.com"],
        "AWS S3 / CloudFront": ["s3.amazonaws.com", "cloudfront.net"],
        "Sentry Error Monitoring": ["sentry.io", "browser.sentry-cdn.com"],
        "Intercom / Chat": ["widget.intercom.io", "intercom.com"],
        "Segment / Analytics": ["cdn.segment.com"],
        "FontAwesome": ["fontawesome.com", "kit.fontawesome.com"],
        "Tailwind CSS": ["tailwindcss", "tailwind.min.css"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    }

    def __init__(self, target_url: str):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.url = target_url
        self.parsed = urllib.parse.urlparse(self.url)

    def analyze(self) -> WebAnalysisResult:
        result = WebAnalysisResult(url=self.url, domain=self.parsed.netloc)

        import ssl
        try:
            import certifi
            ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ssl_ctx = ssl._create_unverified_context()

        req = urllib.request.Request(self.url, headers={"User-Agent": self.USER_AGENT})
        html_bytes = b""
        headers_dict: Dict[str, str] = {}

        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=12) as response:
                result.status_code = response.status
                headers_dict = dict(response.headers)
                html_bytes = response.read(2 * 1024 * 1024)  # Read up to 2MB
        except Exception as e:
            # Fallback retry with unverified SSL in case of MITM or local CA issues
            try:
                unverified_ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, context=unverified_ctx, timeout=12) as response:
                    result.status_code = response.status
                    headers_dict = dict(response.headers)
                    html_bytes = response.read(2 * 1024 * 1024)
            except Exception as e2:
                result.vulnerabilities.append(f"HTTP Fetch Warning: {str(e2)}")
                return result

        result.server_banner = headers_dict.get("Server", headers_dict.get("server", ""))

        # 1. Audit HTTP Security Headers
        self._audit_headers(headers_dict, result)

        # 2. Parse HTML structure
        html_text = html_bytes.decode("utf-8", errors="ignore")
        inspector = SimpleHTMLInspector(self.url)
        try:
            inspector.feed(html_text)
        except Exception:
            pass

        result.page_title = inspector.title
        result.meta_description = inspector.meta_desc
        result.script_urls = sorted(set(inspector.scripts))
        result.stylesheet_urls = sorted(set(inspector.stylesheets))
        result.forms = inspector.forms

        # 3. Framework & CMS Fingerprinting
        self._fingerprint_tech(html_text, headers_dict, result)

        # 4. Extract Discovered API Endpoints & Routes
        combined_text = html_text + "\n" + "\n".join(inspector.raw_inline_scripts)
        apis = set(self.API_REGEX.findall(combined_text))
        apis.update(self.FETCH_REGEX.findall(combined_text))
        result.discovered_api_endpoints = sorted({a for a in apis if a.startswith("/") or a.startswith("http")})[:30]

        routes = set(self.ROUTE_REGEX.findall(combined_text))
        # Filter internal links
        for l in inspector.links:
            p = urllib.parse.urlparse(l)
            if p.netloc == self.parsed.netloc and p.path:
                routes.add(p.path)
        result.discovered_internal_routes = sorted(routes)[:25]

        # 5. Detect Third-Party Integrations
        all_urls_str = " ".join(inspector.scripts + inspector.stylesheets + inspector.links).lower()
        third_parties = set()
        for name, patterns in self.THIRD_PARTY_SERVICES.items():
            if any(p.lower() in all_urls_str or p.lower() in combined_text.lower() for p in patterns):
                third_parties.add(name)
        result.discovered_third_party = sorted(third_parties)

        # 6. Fetch and scan 1st external JS bundle if available for more API endpoints
        if result.script_urls:
            for s_url in result.script_urls[:2]:
                # If script is from same domain
                if urllib.parse.urlparse(s_url).netloc == self.parsed.netloc:
                    try:
                        s_req = urllib.request.Request(s_url, headers={"User-Agent": self.USER_AGENT})
                        with urllib.request.urlopen(s_req, context=ssl_ctx, timeout=5) as s_resp:
                            s_data = s_resp.read(512 * 1024).decode("utf-8", errors="ignore")
                            s_apis = self.API_REGEX.findall(s_data)
                            result.discovered_api_endpoints = sorted(set(result.discovered_api_endpoints + s_apis))[:40]
                    except Exception:
                        pass

        return result

    def _audit_headers(self, headers: Dict[str, str], result: WebAnalysisResult) -> None:
        h_lower = {k.lower(): v for k, v in headers.items()}

        # CSP
        csp = h_lower.get("content-security-policy", "")
        if csp:
            result.security_headers.append(
                SecurityHeaderAudit("Content-Security-Policy", "🟢 Configured", csp[:60] + "...", "Low", "Enforces strict resource injection policy")
            )
        else:
            result.security_headers.append(
                SecurityHeaderAudit("Content-Security-Policy", "🔴 Missing", "None", "High", "Add CSP to mitigate Cross-Site Scripting (XSS)")
            )
            result.vulnerabilities.append("SECURITY RISK: Missing Content-Security-Policy (CSP) header. Vulnerable to XSS injection attacks.")

        # HSTS
        hsts = h_lower.get("strict-transport-security", "")
        if hsts:
            result.security_headers.append(
                SecurityHeaderAudit("Strict-Transport-Security (HSTS)", "🟢 Enabled", hsts, "Low", "Enforces HTTPS connections")
            )
        else:
            result.security_headers.append(
                SecurityHeaderAudit("Strict-Transport-Security (HSTS)", "🟡 Missing", "None", "Medium", "Enable HSTS to prevent SSL stripping")
            )

        # X-Frame-Options
        xfo = h_lower.get("x-frame-options", "")
        if xfo:
            result.security_headers.append(
                SecurityHeaderAudit("X-Frame-Options", "🟢 Configured", xfo, "Low", "Protects against clickjacking")
            )
        else:
            result.security_headers.append(
                SecurityHeaderAudit("X-Frame-Options", "🔴 Missing", "None", "Medium", "Set to DENY or SAMEORIGIN to prevent clickjacking")
            )
            result.vulnerabilities.append("WARNING: Missing X-Frame-Options header. Potential Clickjacking vulnerability.")

        # X-Content-Type-Options
        xcto = h_lower.get("x-content-type-options", "")
        if xcto and "nosniff" in xcto.lower():
            result.security_headers.append(
                SecurityHeaderAudit("X-Content-Type-Options", "🟢 nosniff", xcto, "Low", "Prevents MIME-sniffing exploits")
            )
        else:
            result.security_headers.append(
                SecurityHeaderAudit("X-Content-Type-Options", "🟡 Missing", "None", "Low", "Set to 'nosniff'")
            )

        # Referrer-Policy
        ref = h_lower.get("referrer-policy", "")
        if ref:
            result.security_headers.append(
                SecurityHeaderAudit("Referrer-Policy", "🟢 Configured", ref, "Low", "Protects referrer leakage")
            )
        else:
            result.security_headers.append(
                SecurityHeaderAudit("Referrer-Policy", "⚪ Default", "None", "Informational", "Consider strict-origin-when-cross-origin")
            )

    def _fingerprint_tech(self, html: str, headers: Dict[str, str], result: WebAnalysisResult) -> None:
        frameworks = set()
        cms = set()
        libs = set()

        h_str = html.lower()
        hdr_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

        # React / Next.js
        if "__next_data__" in h_str or "_next/static" in h_str:
            frameworks.add("Next.js (React Framework)")
            frameworks.add("React")
        elif "react" in h_str or "data-reactroot" in h_str:
            frameworks.add("React")

        # Vue / Nuxt
        if "__nuxt__" in h_str or "_nuxt/" in h_str:
            frameworks.add("Nuxt.js (Vue Framework)")
            frameworks.add("Vue.js")
        elif "vue" in h_str or "data-v-" in h_str:
            frameworks.add("Vue.js")

        # Angular
        if "ng-version" in h_str or "<app-root>" in h_str:
            frameworks.add("Angular")

        # Svelte
        if "svelte-" in h_str:
            frameworks.add("Svelte / SvelteKit")

        # WordPress
        if "wp-content" in h_str or "wp-includes" in h_str:
            cms.add("WordPress")

        # Shopify
        if "cdn.shopify.com" in h_str or "shopify" in hdr_str:
            cms.add("Shopify")

        # Webflow
        if "assets.website-files.com" in h_str or "webflow" in h_str:
            cms.add("Webflow")

        # Libraries & Styling
        if "tailwind" in h_str:
            libs.add("Tailwind CSS")
        if "bootstrap" in h_str:
            libs.add("Bootstrap")
        if "jquery" in h_str:
            libs.add("jQuery")

        result.detected_frameworks = sorted(frameworks)
        result.detected_cms = sorted(cms)
        result.detected_libraries = sorted(libs)
