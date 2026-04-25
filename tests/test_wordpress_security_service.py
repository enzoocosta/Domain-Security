from app.services.wordpress_security_service import FetchedPage, WordPressSecurityService


class StubWordPressSecurityService(WordPressSecurityService):
    def __init__(
        self,
        *,
        page_payloads: dict[tuple[str, str], FetchedPage],
        json_payloads: dict[str, dict],
    ) -> None:
        super().__init__(cache_ttl_seconds=3600, timeout_seconds=1.0)
        self.page_payloads = page_payloads
        self.json_payloads = json_payloads
        self.page_calls: list[tuple[str, str]] = []
        self.json_calls: list[str] = []

    def _fetch_page(self, url: str, *, method: str = "GET") -> FetchedPage:
        self.page_calls.append((method, url))
        return self.page_payloads[(method, url)]

    def _fetch_optional_page(self, url: str, *, method: str = "GET") -> FetchedPage | None:
        self.page_calls.append((method, url))
        return self.page_payloads.get((method, url))

    def _fetch_json(self, url: str) -> dict:
        self.json_calls.append(url)
        return self.json_payloads[url]

    def _fetch_optional_json(self, url: str) -> dict | None:
        self.json_calls.append(url)
        return self.json_payloads.get(url)


def _page(url: str, text: str = "", status_code: int = 200, headers: dict[str, list[str]] | None = None) -> FetchedPage:
    return FetchedPage(
        url=url,
        text=text,
        status_code=status_code,
        headers=headers or {},
    )


def test_wordpress_security_service_detects_core_plugin_theme_and_multilayer_confidence():
    service = StubWordPressSecurityService(
        page_payloads={
            ("GET", "https://example.com/"): _page(
                "https://example.com/",
                text="""
                <html>
                  <head>
                    <meta name="generator" content="WordPress 6.4.2" />
                    <link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=4.0.1" />
                  </head>
                  <body class="home blog page-id-7">
                    <script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.3.1"></script>
                    <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2"></script>
                  </body>
                </html>
                """,
                headers={"set-cookie": ["wordpress_logged_in=1; Path=/"]},
            ),
            ("GET", "https://example.com/wp-json/"): _page(
                "https://example.com/wp-json/",
                text='{"namespaces":["wp/v2"]}',
                status_code=200,
            ),
            ("HEAD", "https://example.com/wp-login.php"): _page(
                "https://example.com/wp-login.php",
                status_code=200,
            ),
            ("HEAD", "https://example.com/xmlrpc.php"): _page(
                "https://example.com/xmlrpc.php",
                status_code=405,
            ),
            ("HEAD", "https://example.com/wp-admin/"): _page(
                "https://example.com/wp-admin/",
                status_code=302,
            ),
            ("GET", "https://example.com/?feed=rss2"): _page(
                "https://example.com/?feed=rss2",
                text="<rss><channel><generator>https://wordpress.org/?v=6.4.2</generator></channel></rss>",
                status_code=200,
            ),
        },
        json_payloads={
            "https://www.wpvulnerability.net/core/6.4.2": {
                "error": 0,
                "data": {
                    "link": "https://www.wpvulnerability.net/core/6.4.2",
                    "vulnerability": [
                        {
                            "uuid": "core-1",
                            "name": "WordPress 6.4.2 vulnerability",
                            "source": [
                                {
                                    "id": "CVE-2025-1000",
                                    "name": "CVE-2025-1000",
                                    "link": "https://www.cve.org/CVERecord?id=CVE-2025-1000",
                                }
                            ],
                            "impact": {"cvss3": {"score": "7.5", "severity": "high"}},
                        }
                    ],
                },
            },
            "https://www.wpvulnerability.net/plugin/contact-form-7": {
                "error": 0,
                "data": {
                    "name": "Contact Form 7",
                    "link": "https://wordpress.org/plugins/contact-form-7/",
                    "vulnerability": [
                        {
                            "uuid": "plugin-1",
                            "name": "Contact Form 7 < 5.3.2",
                            "operator": {
                                "max_version": "5.3.2",
                                "max_operator": "lt",
                                "unfixed": "0",
                            },
                            "source": [
                                {
                                    "id": "CVE-2020-35489",
                                    "name": "CVE-2020-35489",
                                    "link": "https://www.cve.org/CVERecord?id=CVE-2020-35489",
                                }
                            ],
                            "impact": {"cvss3": {"score": "10.0", "severity": "critical"}},
                        }
                    ],
                },
            },
            "https://www.wpvulnerability.net/theme/astra": {
                "error": 0,
                "data": {
                    "name": "Astra",
                    "link": "https://wordpress.org/themes/astra/",
                    "vulnerability": [],
                },
            },
        },
    )

    result = service.analyze_site("example.com")

    assert result.siteConfirmed is True
    assert result.detection.isWordPress is True
    assert result.detection.confidence == "confirmed"
    assert result.detection.wordpressVersion == "6.4.2"
    assert result.detection.versionHidden is False
    assert len([signal for signal in result.detection.signals if signal.detected]) >= 6
    assert result.versionDetection.version == "6.4.2"
    assert [item.slug for item in result.items] == ["wordpress-core", "contact-form-7", "astra"]
    assert result.items[0].status == "critico"
    assert result.items[1].vulnerabilidades[0].cve == "CVE-2020-35489"
    assert result.items[1].vulnerabilidades[0].corrigidoNaVersao == "> 5.3.2"
    assert result.items[2].status == "seguro"
    assert result.summary.totalItemsAnalisados == 3
    assert result.summary.totalVulnerabilidades == 2
    assert result.summary.scoreGeral == 55


def test_wordpress_security_service_detects_hidden_version_with_likely_confidence():
    service = StubWordPressSecurityService(
        page_payloads={
            ("GET", "https://hardened.example.com/"): _page(
                "https://hardened.example.com/",
                text="""
                <html>
                  <head><title>Hardened site</title></head>
                  <body>
                    <script src="/wp-includes/js/dist/hooks.min.js"></script>
                  </body>
                </html>
                """,
                status_code=200,
            ),
            ("GET", "https://hardened.example.com/wp-json/"): _page(
                "https://hardened.example.com/wp-json/",
                text="",
                status_code=403,
            ),
            ("HEAD", "https://hardened.example.com/wp-login.php"): _page(
                "https://hardened.example.com/wp-login.php",
                status_code=404,
            ),
            ("HEAD", "https://hardened.example.com/xmlrpc.php"): _page(
                "https://hardened.example.com/xmlrpc.php",
                status_code=404,
            ),
            ("HEAD", "https://hardened.example.com/wp-admin/"): _page(
                "https://hardened.example.com/wp-admin/",
                status_code=404,
            ),
        },
        json_payloads={},
    )

    result = service.analyze_site("https://hardened.example.com")

    assert result.siteConfirmed is True
    assert result.detection.isWordPress is True
    assert result.detection.confidence == "confirmed"
    assert result.detection.versionHidden is True
    assert result.detection.wordpressVersion is None
    assert "boa pratica" in result.warnings[0].lower()
    assert result.items[0].status == "nao_detectado"


def test_wordpress_security_service_only_marks_non_wordpress_after_all_layers_fail_and_uses_cache():
    service = StubWordPressSecurityService(
        page_payloads={
            ("GET", "https://plain.example.com/"): _page(
                "https://plain.example.com/",
                text="<html><head><title>Simple Site</title></head><body>Hello</body></html>",
                status_code=200,
            ),
            ("GET", "https://plain.example.com/wp-json/"): _page(
                "https://plain.example.com/wp-json/",
                text="not found",
                status_code=404,
            ),
            ("HEAD", "https://plain.example.com/wp-login.php"): _page(
                "https://plain.example.com/wp-login.php",
                status_code=404,
            ),
            ("HEAD", "https://plain.example.com/xmlrpc.php"): _page(
                "https://plain.example.com/xmlrpc.php",
                status_code=404,
            ),
            ("HEAD", "https://plain.example.com/wp-admin/"): _page(
                "https://plain.example.com/wp-admin/",
                status_code=404,
            ),
            ("GET", "https://plain.example.com/?feed=rss2"): _page(
                "https://plain.example.com/?feed=rss2",
                text="<rss><channel><title>No WordPress</title></channel></rss>",
                status_code=200,
            ),
        },
        json_payloads={},
    )

    first = service.analyze_site("https://plain.example.com")
    second = service.analyze_site("https://plain.example.com")

    assert first.siteConfirmed is False
    assert first.detection.isWordPress is False
    assert first.detection.confidence == "unlikely"
    assert all(signal.detected is False for signal in first.detection.signals)
    assert "Nao foi possivel confirmar" in first.warnings[0]
    assert first.summary.scoreGeral == 0
    assert second.cacheHit is True
    assert service.page_calls.count(("GET", "https://plain.example.com/")) == 1
