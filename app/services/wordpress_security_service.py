from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html import unescape
import json
import re
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from app.core.analysis_cache import AnalysisCache
from app.core.exceptions import InputValidationError
from app.schemas.wordpress import (
    WordPressAnalysisOptions,
    WordPressAnalysisResponse,
    WordPressAnalysisSummary,
    WordPressDetectionResult,
    WordPressDetectionSignal,
    WordPressItemAnalysis,
    WordPressVersionDetection,
    WordPressVulnerability,
)


_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](WordPress(?:\s+([0-9A-Za-z.\-_]+))?)["\']',
    re.IGNORECASE,
)
_READ_ME_RE = re.compile(r"Version\s+([0-9]+(?:\.[0-9A-Za-z]+)+)", re.IGNORECASE)
_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9._-]+)/", re.IGNORECASE)
_THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9._-]+)/", re.IGNORECASE)
_PLUGIN_VERSION_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9._-]+)/[^\"'?\s>]+(?:\?[^\"'\s>]*?\bver=([0-9A-Za-z.\-_]+))",
    re.IGNORECASE,
)
_THEME_VERSION_RE = re.compile(
    r"/wp-content/themes/([a-z0-9._-]+)/[^\"'?\s>]+(?:\?[^\"'\s>]*?\bver=([0-9A-Za-z.\-_]+))",
    re.IGNORECASE,
)
_RSS_VERSION_RE = re.compile(r"wordpress(?:\.org)?/?\?v=([0-9A-Za-z.\-_]+)", re.IGNORECASE)
_BODY_CLASS_RE = re.compile(r"<body[^>]+class=[\"']([^\"']+)[\"']", re.IGNORECASE)
_FEED_LINK_RE = re.compile(r'<link[^>]+rel=["\'][^"\']*alternate[^"\']*["\'][^>]+href=["\'][^"\']*/feed/[^"\']*["\']', re.IGNORECASE)


@dataclass(frozen=True)
class FetchedPage:
    url: str
    text: str
    status_code: int
    headers: dict[str, list[str]]


@dataclass(frozen=True)
class DetectionOutcome:
    layer: int
    name: str
    detected: bool
    value: str | None = None
    version: str | None = None
    source: str | None = None


class WordPressSecurityService:
    API_BASE_URL = "https://www.wpvulnerability.net"
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, *, cache_ttl_seconds: int = 3600, timeout_seconds: float = 5.0) -> None:
        self.cache = AnalysisCache(ttl_seconds=cache_ttl_seconds)
        self.timeout_seconds = max(1.0, timeout_seconds)

    def analyze_site(self, url: str, options: WordPressAnalysisOptions | None = None) -> WordPressAnalysisResponse:
        normalized_url = self._normalize_url(url)
        selected = options or WordPressAnalysisOptions()
        cache_key = self._build_cache_key(normalized_url, selected)
        cached = self.cache.get(cache_key)
        if cached is not None:
            return WordPressAnalysisResponse.model_validate({**cached, "cacheHit": True})

        home_page = self._fetch_page(normalized_url)
        scanned_url = home_page.url
        home_html = home_page.text
        progress_steps = [
            "Carregando pagina principal...",
            "Executando deteccao WordPress em multiplas camadas...",
            "Consolidando sinais encontrados...",
        ]

        detection = self._detect_wordpress(scanned_url, home_page)
        site_confirmed = detection.isWordPress
        version = detection.wordpressVersion
        version_source = self._version_source_from_signals(detection.signals)
        warnings: list[str] = []

        if not site_confirmed:
            warnings.append(
                "Nao foi possivel confirmar que este site utiliza WordPress. Verifique a URL e tente novamente."
            )
        elif detection.versionHidden:
            warnings.append(
                "WordPress detectado, mas a versao nao esta exposta publicamente. Isso costuma ser uma boa pratica de hardening."
            )

        plugin_slugs: list[str] = []
        theme_slugs: list[str] = []
        plugin_versions: dict[str, str] = {}
        theme_versions: dict[str, str] = {}

        if site_confirmed and (selected.detect_plugins or selected.detect_themes):
            progress_steps.append("Mapeando plugins e tema via HTML publico...")
            if selected.detect_plugins:
                plugin_slugs = self._extract_unique_slugs(_PLUGIN_RE, home_html)
                plugin_versions = self._extract_asset_versions(_PLUGIN_VERSION_RE, home_html)
            if selected.detect_themes:
                theme_slugs = self._extract_unique_slugs(_THEME_RE, home_html)
                theme_versions = self._extract_asset_versions(_THEME_VERSION_RE, home_html)

        items: list[WordPressItemAnalysis] = []

        if site_confirmed and selected.detect_core:
            progress_steps.append("Consultando vulnerabilidades do core...")
            items.append(self._build_core_item(version))

        if site_confirmed and selected.detect_plugins:
            progress_steps.append("Consultando vulnerabilidades de plugins...")
            for slug in plugin_slugs:
                items.append(
                    self._build_component_item(
                        slug=slug,
                        tipo="plugin",
                        version_detected=plugin_versions.get(slug),
                    )
                )

        if site_confirmed and selected.detect_themes:
            progress_steps.append("Consultando vulnerabilidades do tema...")
            for slug in theme_slugs:
                items.append(
                    self._build_component_item(
                        slug=slug,
                        tipo="tema",
                        version_detected=theme_versions.get(slug),
                    )
                )

        summary = self._build_summary(items, site_confirmed=site_confirmed)
        payload = WordPressAnalysisResponse(
            targetUrl=normalized_url,
            scannedUrl=scanned_url,
            siteConfirmed=site_confirmed,
            cacheHit=False,
            detection=detection,
            versionDetection=WordPressVersionDetection(
                version=version,
                source=version_source,
                warning=warnings[0] if warnings else None,
            ),
            items=items,
            summary=summary,
            warnings=warnings,
            progressSteps=progress_steps,
        )
        self.cache.set(cache_key, payload.model_dump(mode="json"))
        return payload

    def _detect_wordpress(self, scanned_url: str, home_page: FetchedPage) -> WordPressDetectionResult:
        checks: list[tuple[int, str, Callable[[], DetectionOutcome]]] = [
            (1, "Meta Generator", lambda: self._check_meta_generator(home_page.text)),
            (2, "Paths wp-content / wp-includes", lambda: self._check_asset_paths(home_page.text)),
            (3, "REST API wp-json", lambda: self._check_rest_api(scanned_url)),
            (4, "Arquivo wp-login.php", lambda: self._check_wp_login(scanned_url)),
            (5, "Arquivo xmlrpc.php", lambda: self._check_xmlrpc(scanned_url)),
            (6, "Diretorio wp-admin", lambda: self._check_wp_admin(scanned_url)),
            (7, "Feed RSS", lambda: self._check_feed(scanned_url, home_page.text)),
            (8, "Cookies WordPress", lambda: self._check_wp_cookies(home_page.headers)),
            (9, "Scripts do core", lambda: self._check_core_scripts(home_page.text)),
            (10, "Body classes do WordPress", lambda: self._check_body_classes(home_page.text)),
        ]

        outcomes: dict[int, DetectionOutcome] = {}
        with ThreadPoolExecutor(max_workers=len(checks)) as executor:
            futures = {
                executor.submit(check): (layer, name)
                for layer, name, check in checks
            }
            for future, metadata in futures.items():
                layer, name = metadata
                try:
                    outcome = future.result()
                except Exception:
                    outcome = DetectionOutcome(layer=layer, name=name, detected=False)
                outcomes[layer] = outcome

        signals = [
            WordPressDetectionSignal(
                layer=outcomes[layer].layer,
                name=outcomes[layer].name,
                detected=outcomes[layer].detected,
                value=outcomes[layer].value,
            )
            for layer, _, _ in checks
        ]
        positive = [signal for signal in signals if signal.detected]
        positive_count = len(positive)

        if positive_count >= 3:
            confidence = "confirmed"
        elif positive_count >= 1:
            confidence = "likely"
        else:
            confidence = "unlikely"

        version = None
        for layer, _, _ in checks:
            outcome = outcomes[layer]
            if outcome.version:
                version = outcome.version
                break

        positive_names = [f"{signal.layer}:{signal.name}" for signal in positive]
        print(
            "[wordpress-detection] "
            f"{scanned_url} -> {', '.join(positive_names) if positive_names else 'none'}"
        )

        return WordPressDetectionResult(
            isWordPress=positive_count > 0,
            confidence=confidence,
            signals=signals,
            wordpressVersion=version,
            versionHidden=positive_count > 0 and version is None,
        )

    def _check_meta_generator(self, html: str) -> DetectionOutcome:
        match = _GENERATOR_RE.search(html)
        if not match:
            return DetectionOutcome(layer=1, name="Meta Generator", detected=False)
        generator_text = unescape(match.group(1))
        version = match.group(2)
        return DetectionOutcome(
            layer=1,
            name="Meta Generator",
            detected=True,
            value=generator_text,
            version=version,
            source="meta_generator",
        )

    def _check_asset_paths(self, html: str) -> DetectionOutcome:
        matches = []
        lowered = html.lower()
        if "/wp-content/" in lowered:
            matches.append("/wp-content/")
        if "/wp-includes/" in lowered:
            matches.append("/wp-includes/")
        return DetectionOutcome(
            layer=2,
            name="Paths wp-content / wp-includes",
            detected=bool(matches),
            value=", ".join(matches) if matches else None,
        )

    def _check_rest_api(self, url: str) -> DetectionOutcome:
        page = self._fetch_optional_page(urljoin(self._base_url(url), "wp-json/"))
        if page is None:
            return DetectionOutcome(layer=3, name="REST API wp-json", detected=False)
        text = page.text.lower()
        if "namespaces" in text or "wp/v2" in text:
            return DetectionOutcome(
                layer=3,
                name="REST API wp-json",
                detected=True,
                value=f"HTTP {page.status_code} com namespaces/wp-v2",
            )
        if page.status_code in {401, 403}:
            return DetectionOutcome(
                layer=3,
                name="REST API wp-json",
                detected=True,
                value=f"HTTP {page.status_code} no endpoint /wp-json/",
            )
        return DetectionOutcome(layer=3, name="REST API wp-json", detected=False)

    def _check_wp_login(self, url: str) -> DetectionOutcome:
        page = self._fetch_optional_page(urljoin(self._base_url(url), "wp-login.php"), method="HEAD")
        detected = page is not None and page.status_code in {200, 301, 302, 303, 307, 308}
        return DetectionOutcome(
            layer=4,
            name="Arquivo wp-login.php",
            detected=detected,
            value=f"HTTP {page.status_code}" if detected and page is not None else None,
        )

    def _check_xmlrpc(self, url: str) -> DetectionOutcome:
        page = self._fetch_optional_page(urljoin(self._base_url(url), "xmlrpc.php"), method="HEAD")
        detected = page is not None and page.status_code in {200, 403, 405}
        return DetectionOutcome(
            layer=5,
            name="Arquivo xmlrpc.php",
            detected=detected,
            value=f"HTTP {page.status_code}" if detected and page is not None else None,
        )

    def _check_wp_admin(self, url: str) -> DetectionOutcome:
        page = self._fetch_optional_page(urljoin(self._base_url(url), "wp-admin/"), method="HEAD")
        detected = page is not None and page.status_code != 404
        return DetectionOutcome(
            layer=6,
            name="Diretorio wp-admin",
            detected=detected,
            value=f"HTTP {page.status_code}" if detected and page is not None else None,
        )

    def _check_feed(self, url: str, html: str) -> DetectionOutcome:
        if _FEED_LINK_RE.search(html):
            return DetectionOutcome(
                layer=7,
                name="Feed RSS",
                detected=True,
                value="Link alternate para /feed/ encontrado no HTML",
            )
        page = self._fetch_optional_page(self._build_feed_url(url))
        if page is None:
            return DetectionOutcome(layer=7, name="Feed RSS", detected=False)
        version = self._detect_version_from_rss(page.text)
        if version:
            return DetectionOutcome(
                layer=7,
                name="Feed RSS",
                detected=True,
                value=f"Generator WordPress com versao {version}",
                version=version,
                source="feed_rss",
            )
        return DetectionOutcome(layer=7, name="Feed RSS", detected=False)

    def _check_wp_cookies(self, headers: dict[str, list[str]]) -> DetectionOutcome:
        cookie_names: list[str] = []
        for header in headers.get("set-cookie", []):
            name = header.split("=", 1)[0].strip()
            lowered = name.lower()
            if lowered.startswith("wordpress_") or lowered.startswith("wp-settings-"):
                cookie_names.append(name)
        return DetectionOutcome(
            layer=8,
            name="Cookies WordPress",
            detected=bool(cookie_names),
            value=", ".join(cookie_names) if cookie_names else None,
        )

    def _check_core_scripts(self, html: str) -> DetectionOutcome:
        lowered = html.lower()
        matches = []
        if "wp-emoji-release.min.js" in lowered:
            matches.append("wp-emoji-release.min.js")
        if "/wp-includes/js/" in lowered:
            matches.append("/wp-includes/js/")
        if "jquery.min.js?ver=" in lowered:
            matches.append("jquery.min.js?ver=")
        return DetectionOutcome(
            layer=9,
            name="Scripts do core",
            detected=bool(matches),
            value=", ".join(matches) if matches else None,
        )

    def _check_body_classes(self, html: str) -> DetectionOutcome:
        match = _BODY_CLASS_RE.search(html)
        if not match:
            return DetectionOutcome(layer=10, name="Body classes do WordPress", detected=False)
        classes = match.group(1).split()
        matched_classes = [
            class_name
            for class_name in classes
            if class_name.startswith("wp-")
            or class_name.startswith("logged-")
            or class_name.startswith("single-")
            or class_name.startswith("page-id-")
            or class_name.startswith("postid-")
            or class_name in {"home", "blog"}
        ]
        return DetectionOutcome(
            layer=10,
            name="Body classes do WordPress",
            detected=bool(matched_classes),
            value=", ".join(matched_classes[:6]) if matched_classes else None,
        )

    def _version_source_from_signals(self, signals: list[WordPressDetectionSignal]) -> str | None:
        for signal in signals:
            if signal.detected and signal.layer == 1 and signal.value:
                return "meta_generator"
            if signal.detected and signal.layer == 7 and signal.value:
                return "feed_rss"
        return None

    def _build_core_item(self, version: str | None) -> WordPressItemAnalysis:
        if version is None:
            return WordPressItemAnalysis(
                slug="wordpress-core",
                nome="WordPress Core",
                tipo="core",
                versaoDetectada=None,
                vulnerabilidades=[],
                status="nao_detectado",
                referencia=None,
            )

        endpoint = f"{self.API_BASE_URL}/core/{version}"
        payload = self._fetch_optional_json(endpoint)
        if payload is None or payload.get("error") not in {0, "0", None}:
            return WordPressItemAnalysis(
                slug="wordpress-core",
                nome="WordPress Core",
                tipo="core",
                versaoDetectada=version,
                vulnerabilidades=[],
                status="nao_detectado",
                referencia=endpoint,
            )

        data = payload.get("data") or {}
        vulnerabilities = self._extract_vulnerabilities(data.get("vulnerability") or [])
        return WordPressItemAnalysis(
            slug="wordpress-core",
            nome="WordPress Core",
            tipo="core",
            versaoDetectada=version,
            vulnerabilidades=vulnerabilities,
            status=self._status_for_vulnerabilities(vulnerabilities),
            referencia=data.get("link") or endpoint,
        )

    def _build_component_item(
        self,
        *,
        slug: str,
        tipo: str,
        version_detected: str | None,
    ) -> WordPressItemAnalysis:
        endpoint_type = "plugin" if tipo == "plugin" else "theme"
        endpoint = f"{self.API_BASE_URL}/{endpoint_type}/{slug}"
        payload = self._fetch_optional_json(endpoint)
        default_name = slug.replace("-", " ").replace("_", " ").title()

        if payload is None or payload.get("error") not in {0, "0", None}:
            return WordPressItemAnalysis(
                slug=slug,
                nome=default_name,
                tipo="plugin" if tipo == "plugin" else "tema",
                versaoDetectada=version_detected,
                vulnerabilidades=[],
                status="nao_detectado",
                referencia=endpoint,
            )

        data = payload.get("data") or {}
        vulnerabilities = self._extract_vulnerabilities(
            data.get("vulnerability") or [],
            version_detected=version_detected,
        )
        status = self._status_for_vulnerabilities(vulnerabilities)
        if not vulnerabilities and version_detected is None and (data.get("vulnerability") or []):
            status = "atencao"

        return WordPressItemAnalysis(
            slug=slug,
            nome=data.get("name") or default_name,
            tipo="plugin" if tipo == "plugin" else "tema",
            versaoDetectada=version_detected,
            vulnerabilidades=vulnerabilities,
            status=status,
            referencia=data.get("link") or endpoint,
        )

    def _extract_vulnerabilities(
        self,
        entries: list[dict[str, Any]],
        *,
        version_detected: str | None = None,
    ) -> list[WordPressVulnerability]:
        vulnerabilities: list[WordPressVulnerability] = []
        for entry in entries:
            operator = entry.get("operator") or {}
            if version_detected and operator and not self._version_matches_operator(version_detected, operator):
                continue

            severity, score = self._extract_severity_and_score(entry.get("impact") or {})
            source = self._pick_preferred_source(entry.get("source") or [])
            cve = source.get("id") if str(source.get("id", "")).upper().startswith("CVE-") else None
            title = unescape(source.get("name") or entry.get("name") or "Vulnerabilidade conhecida")
            vulnerability_id = str(entry.get("uuid") or source.get("id") or title).strip()
            reference = source.get("link")
            fixed_version = self._infer_fixed_version(operator)

            vulnerabilities.append(
                WordPressVulnerability(
                    id=vulnerability_id,
                    titulo=title,
                    severidade=severity,
                    cvssScore=score,
                    cve=cve,
                    corrigidoNaVersao=fixed_version,
                    referencia=reference,
                )
            )
        return vulnerabilities

    def _extract_severity_and_score(self, impact: dict[str, Any]) -> tuple[str, float | None]:
        cvss3 = impact.get("cvss3") or {}
        cvss = impact.get("cvss") or {}
        score_value = cvss3.get("score") or cvss.get("score")
        try:
            score = float(score_value) if score_value is not None else None
        except (TypeError, ValueError):
            score = None

        severity = str(cvss3.get("severity") or cvss.get("severity") or "").strip().lower()
        if severity in {"critical", "high", "medium", "low"}:
            return severity, score
        if severity in {"c", "h", "m", "l"}:
            return {"c": "critical", "h": "high", "m": "medium", "l": "low"}[severity], score
        if score is None:
            return "medium", None
        if score >= 9.0:
            return "critical", score
        if score >= 7.0:
            return "high", score
        if score >= 4.0:
            return "medium", score
        return "low", score

    def _pick_preferred_source(self, sources: list[dict[str, Any]]) -> dict[str, Any]:
        if not sources:
            return {}
        for source in sources:
            if str(source.get("id", "")).upper().startswith("CVE-"):
                return source
        return sources[0]

    def _infer_fixed_version(self, operator: dict[str, Any]) -> str | None:
        if not operator or str(operator.get("unfixed")) == "1":
            return None
        max_version = operator.get("max_version")
        max_operator = operator.get("max_operator")
        if max_version and max_operator in {"lt", "le", "lte"}:
            return f"> {max_version}"
        return max_version

    def _status_for_vulnerabilities(self, vulnerabilities: list[WordPressVulnerability]) -> str:
        if not vulnerabilities:
            return "seguro"
        severities = {item.severidade for item in vulnerabilities}
        if "critical" in severities or "high" in severities:
            return "critico"
        return "atencao"

    def _build_summary(
        self,
        items: list[WordPressItemAnalysis],
        *,
        site_confirmed: bool,
    ) -> WordPressAnalysisSummary:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in items:
            for vulnerability in item.vulnerabilidades:
                counts[vulnerability.severidade] += 1

        score = 100
        score -= counts["critical"] * 30
        score -= counts["high"] * 15
        score -= counts["medium"] * 8
        score -= counts["low"] * 3
        score = max(0, score)

        if not site_confirmed:
            score = 0

        if score >= 80:
            classification = "seguro"
        elif score >= 50:
            classification = "atencao"
        else:
            classification = "em_risco"

        return WordPressAnalysisSummary(
            totalItemsAnalisados=len(items),
            totalVulnerabilidades=sum(counts.values()),
            vulnerabilidadesPorSeveridade=counts,
            scoreGeral=score,
            classificacao=classification,
        )

    def _normalize_url(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            raise InputValidationError("Informe a URL do site WordPress que voce deseja analisar.")

        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise InputValidationError("Informe uma URL valida, por exemplo https://meusite.com.br.")

        path = parsed.path or "/"
        normalized = parsed._replace(fragment="", params="", query="", path=path)
        return urlunparse(normalized)

    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.path in {"", "/"}:
            path = "/"
        else:
            path = parsed.path if parsed.path.endswith("/") else f"{parsed.path.rsplit('/', 1)[0]}/"
            if not path.startswith("/"):
                path = f"/{path}"
        return urlunparse(parsed._replace(path=path, params="", query="", fragment=""))

    def _build_feed_url(self, url: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query["feed"] = ["rss2"]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True), fragment=""))

    def _build_cache_key(self, url: str, options: WordPressAnalysisOptions) -> str:
        return f"{url}|core={int(options.detect_core)}|plugins={int(options.detect_plugins)}|themes={int(options.detect_themes)}"

    def _fetch_optional_json(self, url: str) -> dict[str, Any] | None:
        try:
            return self._fetch_json(url)
        except (HTTPError, URLError, ValueError, TimeoutError):
            return None

    def _fetch_json(self, url: str) -> dict[str, Any]:
        page = self._fetch_page(url)
        payload = json.loads(page.text)
        if not isinstance(payload, dict):
            raise ValueError("Unexpected JSON payload")
        return payload

    def _fetch_optional_page(self, url: str, *, method: str = "GET") -> FetchedPage | None:
        try:
            return self._fetch_page(url, method=method)
        except (URLError, TimeoutError):
            return None

    def _fetch_page(self, url: str, *, method: str = "GET") -> FetchedPage:
        request = Request(
            url,
            headers={
                "User-Agent": self.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8",
            },
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return self._page_from_response(response)
        except HTTPError as exc:
            return self._page_from_response(exc)

    def _page_from_response(self, response: Any) -> FetchedPage:
        charset = response.headers.get_content_charset() or "utf-8"
        text = ""
        try:
            payload = response.read()
            if isinstance(payload, bytes):
                text = payload.decode(charset, errors="replace")
        except Exception:
            text = ""
        return FetchedPage(
            url=response.geturl(),
            text=text,
            status_code=getattr(response, "status", getattr(response, "code", 200)),
            headers=self._headers_to_dict(response.headers),
        )

    def _headers_to_dict(self, headers: Any) -> dict[str, list[str]]:
        normalized: dict[str, list[str]] = {}
        for key in headers.keys():
            values = headers.get_all(key) or []
            normalized[key.lower()] = [str(value) for value in values]
        return normalized

    def _detect_version_from_rss(self, xml_text: str) -> str | None:
        match = _RSS_VERSION_RE.search(xml_text)
        if match:
            return match.group(1)
        try:
            root = ElementTree.fromstring(xml_text)
        except ElementTree.ParseError:
            return None

        for element in root.iter():
            tag = element.tag.lower()
            if tag.endswith("generator") and element.text:
                direct_match = re.search(r"wordpress\s+([0-9A-Za-z.\-_]+)", element.text, re.IGNORECASE)
                if direct_match:
                    return direct_match.group(1)
                inner_match = _RSS_VERSION_RE.search(element.text)
                if inner_match:
                    return inner_match.group(1)
        return None

    def _extract_unique_slugs(self, pattern: re.Pattern[str], html: str) -> list[str]:
        seen: list[str] = []
        for match in pattern.findall(html):
            slug = str(match).lower()
            if slug not in seen:
                seen.append(slug)
        return seen

    def _extract_asset_versions(self, pattern: re.Pattern[str], html: str) -> dict[str, str]:
        versions: dict[str, str] = {}
        for slug, version in pattern.findall(html):
            if slug and version and slug.lower() not in versions:
                versions[slug.lower()] = version
        return versions

    def _version_matches_operator(self, version: str, operator: dict[str, Any]) -> bool:
        min_version = operator.get("min_version")
        min_operator = operator.get("min_operator")
        max_version = operator.get("max_version")
        max_operator = operator.get("max_operator")

        if min_version and min_operator:
            comparison = self._compare_versions(version, str(min_version))
            if min_operator in {"gt", ">"} and comparison <= 0:
                return False
            if min_operator in {"ge", "gte", ">="} and comparison < 0:
                return False
            if min_operator in {"eq", "="} and comparison != 0:
                return False

        if max_version and max_operator:
            comparison = self._compare_versions(version, str(max_version))
            if max_operator in {"lt", "<"} and comparison >= 0:
                return False
            if max_operator in {"le", "lte", "<="} and comparison > 0:
                return False
            if max_operator in {"eq", "="} and comparison != 0:
                return False

        return True

    def _compare_versions(self, left: str, right: str) -> int:
        left_parts = self._split_version(left)
        right_parts = self._split_version(right)
        max_len = max(len(left_parts), len(right_parts))
        for index in range(max_len):
            left_part = left_parts[index] if index < len(left_parts) else 0
            right_part = right_parts[index] if index < len(right_parts) else 0
            if left_part == right_part:
                continue
            return -1 if self._version_part_key(left_part) < self._version_part_key(right_part) else 1
        return 0

    def _split_version(self, value: str) -> list[int | str]:
        parts: list[int | str] = []
        for item in re.split(r"[.\-_+]", str(value)):
            if not item:
                continue
            parts.append(int(item) if item.isdigit() else item.lower())
        return parts

    def _version_part_key(self, value: int | str) -> tuple[int, int | str]:
        if isinstance(value, int):
            return (1, value)
        return (0, value)
