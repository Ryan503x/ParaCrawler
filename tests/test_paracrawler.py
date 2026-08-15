import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import paracrawler


def test_print_color_legend_explains_each_result_category(capsys):
    paracrawler.print_color_legend()

    output = capsys.readouterr().out
    for label in (
        "Query parameters",
        "HTML inputs",
        "JavaScript inputs",
        "Buttons",
        "Hidden fields",
        "Sensitive findings",
        "Versions",
        "IP addresses",
    ):
        assert label in output


def test_main_prints_color_legend_once(monkeypatch, capsys):
    class EmptyCrawler:
        def __init__(self, **kwargs):
            self.crawled_count = 0
            self.failed_urls = set()
            self.timeout_urls = set()
            self.found_files = set()

        def run_crawler(self, base_url, max_urls):
            return iter(())

        def retry_failed_urls(self, endpoints):
            return None

    monkeypatch.setattr(paracrawler, "AdvancedCrawler", EmptyCrawler)
    monkeypatch.setattr("sys.argv", ["paracrawler.py", "-u", "https://example.com"])

    paracrawler.main()

    assert capsys.readouterr().out.count("Result color legend:") == 1


def test_normalize_url_canonicalizes_scheme_host_port_path_and_fragment():
    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))

    normalized = crawler.normalize_url("HTTPS://Example.COM:443/a//b#section")

    assert normalized == "https://example.com/a/b"


def test_same_domain_ignores_port_but_rejects_lookalike_hosts():
    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"

    assert crawler.is_same_domain("https://example.com:8443/path") is True
    assert crawler.is_same_domain("https://evil-example.com/path") is False


def test_same_domain_allows_only_apex_www_equivalent_by_default():
    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"

    assert crawler.is_same_domain("https://www.example.com/path") is True
    assert crawler.is_same_domain("https://api.example.com/path") is False

    crawler.base_domain = "www.example.com"
    assert crawler.is_same_domain("https://example.com/path") is True
    assert crawler.is_same_domain("https://other.example.com/path") is False


def test_worker_does_not_yield_blocked_redirect_as_crawled(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"

    def blocked_redirect(url):
        crawler.url_status[url] = 302
        return None

    monkeypatch.setattr(crawler, "fetch_url_content", blocked_redirect)

    assert crawler.crawl_worker("https://example.com/") == (None, [])


def test_worker_falls_back_from_failed_http_to_https(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"
    calls = []

    def fetch(url):
        calls.append(url)
        if url.startswith("https://"):
            crawler.url_status[url] = 200
            crawler.url_content_map[url] = "<html><body>secure</body></html>"
            crawler.crawled_count += 1
            return crawler.url_content_map[url]
        crawler.timeout_urls.add(url)
        return None

    monkeypatch.setattr(crawler, "fetch_url_content", fetch)
    monkeypatch.setattr(crawler, "debug_extract_links", lambda html, url: [])

    result = crawler.crawl_worker("http://example.com/")

    assert result == ("https://example.com/", [])
    assert calls == ["http://example.com/", "https://example.com/"]
    assert "http://example.com/" not in crawler.timeout_urls


def test_subdomain_scope_respects_public_suffix_boundaries():
    crawler = paracrawler.AdvancedCrawler(crawl_subdomains=True, delay_range=(0, 0))
    crawler.base_domain = "victim.ac.uk"

    assert crawler.is_same_domain("https://api.victim.ac.uk/path") is True
    assert crawler.is_same_domain("https://attacker.ac.uk/path") is False


def test_regular_page_does_not_trigger_sveltekit_endpoint_probing(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(max_workers=2, delay_range=(0, 0))
    html = "<html><body><p>Regular page</p></body></html>"

    def fake_fetch(url, *args, **kwargs):
        crawler.url_status[url] = 200
        crawler.url_content_map[url] = html
        crawler.crawled_count += 1
        return html

    monkeypatch.setattr(crawler, "fetch_url_content", fake_fetch)
    monkeypatch.setattr(crawler, "debug_extract_links", lambda content, url: [])
    monkeypatch.setattr(crawler, "pre_resolve_dns", lambda domain: None)

    urls = list(crawler.run_crawler("https://example.com", max_urls=20))

    assert urls == ["https://example.com/"]


def test_max_urls_is_a_strict_limit_even_with_large_batches(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(max_workers=10, delay_range=(0, 0))
    html = "<html><body>page</body></html>"

    def fake_fetch(url, *args, **kwargs):
        crawler.url_status[url] = 200
        crawler.url_content_map[url] = html
        crawler.crawled_count += 1
        return html

    def fake_links(content, url):
        if url == "https://example.com/":
            return [f"https://example.com/page-{index}" for index in range(10)]
        return []

    monkeypatch.setattr(crawler, "fetch_url_content", fake_fetch)
    monkeypatch.setattr(crawler, "debug_extract_links", fake_links)
    monkeypatch.setattr(crawler, "pre_resolve_dns", lambda domain: None)

    urls = list(crawler.run_crawler("https://example.com", max_urls=3))

    assert len(urls) == 3
    assert crawler.crawled_count == 3


def test_max_urls_limits_non_html_file_checks_too(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(max_workers=10, delay_range=(0, 0))
    checked_files = []
    original_fetch = crawler.fetch_url_content

    def fake_fetch(url, *args, **kwargs):
        if url != "https://example.com/":
            return original_fetch(url, *args, **kwargs)
        crawler.url_content_map[url] = "<html></html>"
        crawler.url_status[url] = 200
        crawler.crawled_count += 1
        return "<html></html>"

    file_urls = [f"https://example.com/file-{index}.pdf" for index in range(10)]
    monkeypatch.setattr(crawler, "fetch_url_content", fake_fetch)
    monkeypatch.setattr(crawler, "pre_resolve_dns", lambda domain: None)
    monkeypatch.setattr(
        crawler,
        "debug_extract_links",
        lambda content, url: file_urls if url == "https://example.com/" else [],
    )
    monkeypatch.setattr(
        crawler,
        "check_file_status",
        lambda url: checked_files.append(url) or 200,
    )

    list(crawler.run_crawler("https://example.com", max_urls=2))

    assert len(crawler.visited) == 2
    assert len(checked_files) == 1


def test_crawl_worker_normalizes_links_before_queueing(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(max_workers=2, delay_range=(0, 0))
    crawler.base_domain = "example.com"
    html = "<html><body>page</body></html>"

    monkeypatch.setattr(crawler, "fetch_url_content", lambda url: html)
    monkeypatch.setattr(
        crawler,
        "debug_extract_links",
        lambda content, url: [
            "https://example.com/path#one",
            "HTTPS://EXAMPLE.COM:443/path#two",
            "https://example.com//path/",
        ],
    )

    crawler.crawl_worker("https://example.com/")

    assert list(crawler.to_visit) == ["https://example.com/path"]


def test_endpoint_detects_versions_and_ips_without_requiring_comments():
    endpoint = paracrawler.Endpoint(
        "https://example.com/status",
        "<html><body>Release 2.4.1 is served by 10.20.30.40</body></html>",
    )

    endpoint.fetch_parameters()
    endpoint.fetch_comments()

    assert endpoint.version_matches == ["2.4.1"]
    assert endpoint.ip_matches == ["10.20.30.40"]


def test_each_worker_thread_gets_an_independent_http_session():
    crawler = paracrawler.AdvancedCrawler(max_workers=2, delay_range=(0, 0))
    barrier = threading.Barrier(2)

    def get_session_id():
        session = crawler.get_session()
        barrier.wait(timeout=2)
        return id(session)

    with ThreadPoolExecutor(max_workers=2) as executor:
        session_ids = list(executor.map(lambda _: get_session_id(), range(2)))

    assert len(set(session_ids)) == 2


def test_completed_pages_are_yielded_without_waiting_for_slower_batch_items(monkeypatch):
    crawler = paracrawler.AdvancedCrawler(max_workers=2, delay_range=(0, 0))
    html = "<html><body>page</body></html>"

    def fake_fetch(url, *args, **kwargs):
        if url.endswith("a-slow"):
            time.sleep(0.1)
        crawler.url_status[url] = 200
        crawler.url_content_map[url] = html
        crawler.crawled_count += 1
        return html

    def fake_links(content, url):
        if url == "https://example.com/":
            return [
                "https://example.com/a-slow",
                "https://example.com/b-fast",
            ]
        return []

    monkeypatch.setattr(crawler, "fetch_url_content", fake_fetch)
    monkeypatch.setattr(crawler, "debug_extract_links", fake_links)
    monkeypatch.setattr(crawler, "pre_resolve_dns", lambda domain: None)

    urls = list(crawler.run_crawler("https://example.com", max_urls=3))

    assert urls == [
        "https://example.com/",
        "https://example.com/b-fast",
        "https://example.com/a-slow",
    ]


def test_main_passes_performance_options_to_crawler(monkeypatch):
    captured = {}

    class EmptyCrawler:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.crawled_count = 0
            self.failed_urls = set()
            self.timeout_urls = set()
            self.found_files = set()

        def run_crawler(self, base_url, max_urls):
            return iter(())

        def retry_failed_urls(self, endpoints):
            return None

    monkeypatch.setattr(paracrawler, "AdvancedCrawler", EmptyCrawler)
    monkeypatch.setattr(
        "sys.argv",
        [
            "paracrawler.py",
            "-u",
            "https://example.com",
            "--delay",
            "0.2",
            "--timeout",
            "7",
            "--retries",
            "2",
            "--max-size",
            "2",
        ],
    )

    paracrawler.main()

    assert captured["delay_range"] == (0.2, 0.2)
    assert captured["request_timeout"] == 7.0
    assert captured["request_retries"] == 2
    assert captured["max_response_bytes"] == 2 * 1024 * 1024


@pytest.mark.parametrize(
    "option,value",
    [("--delay", "nan"), ("--timeout", "inf"), ("--max-size", "0")],
)
def test_main_rejects_non_finite_or_non_positive_performance_values(
    monkeypatch, option, value
):
    monkeypatch.setattr(
        paracrawler.sys,
        "argv",
        ["paracrawler.py", "-u", "https://example.com", option, value],
    )

    with pytest.raises(SystemExit) as error:
        paracrawler.main()

    assert error.value.code == 2


def test_endpoint_handles_missing_html_without_raising():
    endpoint = paracrawler.Endpoint("https://example.com", None)

    assert endpoint.fetch_comments() is False
    assert endpoint.version_matches == []
    assert endpoint.ip_matches == []


def test_sveltekit_discovery_preserves_full_asset_and_api_paths():
    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"
    html = """
    <script src="/_app/immutable/entry/start.abc123.js"></script>
    <script>fetch('/api/users?page=1')</script>
    """

    routes = crawler.discover_sveltekit_routes(html, "https://example.com/")

    assert routes == [
        "https://example.com/_app/immutable/entry/start.abc123.js",
        "https://example.com/api/users?page=1",
    ]


def test_fetch_closes_streamed_response_on_404(monkeypatch):
    class Response:
        status_code = 404
        url = "https://example.com/missing"

        def __init__(self):
            self.headers = {}
            self.history = []
            self.closed = False

        def close(self):
            self.closed = True

    response = Response()

    class Session:
        def get(self, *args, **kwargs):
            return response

    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    monkeypatch.setattr(crawler, "get_session", lambda: Session())

    assert crawler.fetch_url_content(response.url, retries=1) is None
    assert response.closed is True


def test_fetch_disables_automatic_redirects_to_preserve_scope(monkeypatch):
    calls = []

    class Raw:
        def read(self, *args, **kwargs):
            return b""

    class Response:
        status_code = 302
        url = "https://example.com/redirect"
        raw = Raw()

        def __init__(self):
            self.headers = {"Location": "https://outside.example.net/"}
            self.history = []

        def close(self):
            return None

    class Session:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()

    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"
    monkeypatch.setattr(crawler, "get_session", lambda: Session())

    assert crawler.fetch_url_content("https://example.com/redirect", retries=1) is None
    assert calls[0][1]["allow_redirects"] is False


def test_file_status_check_blocks_external_redirects(monkeypatch):
    calls = []

    class Response:
        status_code = 302

        def __init__(self):
            self.headers = {"Location": "https://outside.example.net/file.pdf"}
            self.closed = False

        def close(self):
            self.closed = True

    response = Response()

    class Session:
        def head(self, url, **kwargs):
            calls.append((url, kwargs))
            return response

    crawler = paracrawler.AdvancedCrawler(delay_range=(0, 0))
    crawler.base_domain = "example.com"
    monkeypatch.setattr(crawler, "get_session", lambda: Session())

    assert crawler.check_file_status("https://example.com/file.pdf") is None
    assert calls == [
        (
            "https://example.com/file.pdf",
            {"timeout": (5, 10), "allow_redirects": False},
        )
    ]
    assert response.closed is True
