import asyncio
import sys
import unittest
import unittest.mock as mock

import pytest

from whodap import DNSClient, IPv4Client, IPv6Client, ASNClient
from whodap.errors import RateLimitError, NotFoundError, MalformedQueryError

fake_http_response = "fake-http-response"

links_a = [
    {
        "rel": "self",
        "href": "https://an-rdap-server/domain/domain.com",
        "type": "application/rdap+json",
    },
    {
        "rel": "related",
        "href": "https://the-authoritative-server/domain/domain.com",
        "type": "application/rdap+json",
    },
]

links_b = [
    {
        "rel": "self",
        "href": "https://the-authoritative-server/domain/domain.com",
        "type": "application/rdap+json",
    }
]

if sys.version_info >= (3, 8):

    def async_mock_request():
        mock_request = mock.AsyncMock(
            status_code=200,
            json=mock.Mock(return_value={"links": links_a}),
            read=mock.Mock(return_value=b'{"test": "json"}'),
        )
        return mock_request


    def mock_http_client():
        m = mock.AsyncMock(
            is_closed=1,
            get=mock.AsyncMock(return_value=fake_http_response)
        )
        return m


    def sync_mock_request():
        mock_request = mock.Mock(
            status_code=200,
            json=mock.Mock(return_value={"links": links_a}),
            read=mock.Mock(return_value=b'{"test": "json"}'),
        )
        return mock_request


    def test_build_query_url():
        expected_base_case = "http://some-url.com/domain/domain-name"
        output = DNSClient._build_query_href("http://some-url.com/", "domain-name")
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        expected_absolute_case = "http://bad-example/domain/forward-slash-domain"
        output = DNSClient._build_query_href(
            "http://bad-example", "/forward-slash-domain"
        )
        assert output == expected_absolute_case, f"{output} != {expected_absolute_case}"
        # ipv4
        expected_base_case = "http://some-url.com/ip/8.8.8.8"
        output = IPv4Client._build_query_href("http://some-url.com/", "8.8.8.8")
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        # ipv6
        expected_base_case = "http://some-url.com/ip/2001:4860:4860::8844"
        output = IPv6Client._build_query_href(
            "http://some-url.com/", "2001:4860:4860::8844"
        )
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        # asn
        expected_base_case = "http://some-url.com/autnum/12345"
        output = ASNClient._build_query_href("http://some-url.com/", "12345")
        assert output == expected_base_case, f"{output} != {expected_base_case}"


    def test_check_status():
        assert DNSClient._check_status_code(200) is None
        with pytest.raises(RateLimitError):
            DNSClient._check_status_code(429)
        with pytest.raises(NotFoundError):
            DNSClient._check_status_code(404)
        with pytest.raises(MalformedQueryError):
            DNSClient._check_status_code(400)


    def test_lookup():
        with mock.patch("whodap.client.RDAPClient._get_request", return_value=sync_mock_request()) as req:
            dns_client = DNSClient(None)
            dns_client.iana_dns_server_map = {"com": "https://an-rdap-server/"}
            dns_client.lookup("domain", "com")
            assert (
                    req.call_count == 2
            ), f"_aio_get_request call_count {req.call_count} != 2"
            # reset mock request's return
            req.return_value = mock.Mock(
                status_code=200,
                json=mock.Mock(return_value={"links": links_b}),
                read=mock.Mock(return_value=b'{"test": "json"}'),
            )
            dns_client.lookup(
                "domain",
                "com",
                auth_href="https://the-authoritative-server/domain/domain.com",
            )
            # should only have made 1 additional request
            assert (
                    req.call_count == 3
            ), f"_aio_get_request call_count {req.call_count} != 3"


    @pytest.mark.asyncio
    async def test_aio_lookup():
        with mock.patch("whodap.client.RDAPClient._aio_get_request", return_value=async_mock_request()) as req:
            dns_client = DNSClient(None)
            dns_client.iana_dns_server_map = {"com": "https://an-rdap-server/"}
            # check it
            await dns_client.aio_lookup("domain", "com")
            assert (
                    req.call_count == 2
            ), f"_aio_get_request call_count {req.call_count} != 2"
            # set up mock request
            req.return_value = mock.Mock(
                status_code=200,
                json=mock.Mock(return_value={"links": links_b}),
                read=mock.Mock(return_value=b'{"test": "json"}'),
            )
            await dns_client.aio_lookup(
                "domain",
                "com",
                auth_href="https://the-authoritative-server/domain/domain.com",
            )
            assert req.call_count == 3


    def test_iana_server_map():
        dns_client = DNSClient(None)
        rdap_output = {
            "publication": "2021-05-05",
            "version": "2",
            "services": [
                [["tld1", "tld2", "tld3"], ["https://api.rdap.somewhere.net/"]],
                [["tld4"], ["https://api.rdap.nic/"]],
            ],
        }
        dns_client._set_iana_info(rdap_output)
        assert len(dns_client.iana_dns_server_map.keys()) == 4
        assert dns_client.publication == "2021-05-05"
        assert dns_client.version == "2"


    @mock.patch("whodap.client.DNSClient._aio_get_request")
    @pytest.mark.asyncio
    async def test_aio_get_iana_info(mock_request):
        dns_client = DNSClient(None)
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        await dns_client._aio_get_iana_info()
        mock_request.assert_called_once()


    @mock.patch("whodap.client.DNSClient._get_request")
    def test_load_dns(mock_request):
        dns_client = DNSClient(None)
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        dns_client._get_iana_info()
        mock_request.assert_called_once()


    def test_get_request():
        dns_client = DNSClient(None)
        fake_http_response = "fake-http-response"
        mock_client = mock.Mock(get=mock.Mock(return_value=fake_http_response))
        dns_client.httpx_client = mock_client
        resp = dns_client._get_request("https://www.some-domain.com")
        assert resp == fake_http_response, f"{resp} != {fake_http_response}"


    @pytest.mark.asyncio
    async def test_get_aio_request():
        dns_client = DNSClient(None)
        fake_http_response = "fake-http-response"
        mock_client = mock_http_client()
        dns_client.httpx_client = mock_client
        resp = await dns_client._aio_get_request("https://www.some-domain.com")
        assert resp == fake_http_response, f"{resp} != {fake_http_response}"


    @pytest.mark.asyncio
    async def test_async_context_manager():
        fake_http_response = "fake-http-response"
        mock_client = mock_http_client()
        async with DNSClient.new_aio_client_context() as aio_dns_client:
            aio_dns_client.httpx_client = mock_client
            resp = await aio_dns_client._aio_get_request("https://www.some-domain.com")
            assert resp == fake_http_response, f"{resp} != {fake_http_response}"


    def test_context_manager():
        fake_http_response = "fake-http-response"
        mock_client = mock.Mock(get=mock.Mock(return_value=fake_http_response))
        with DNSClient.new_client_context() as dns_client:
            dns_client.httpx_client = mock_client
            resp = dns_client._get_request("https://www.some-domain.com")
            assert resp == fake_http_response, f"{resp} != {fake_http_response}"


    def test__check_next_href():
        current_href = "https://an-rdap-server/domain/domain.com"
        links_1 = [
            {
                "rel": "self",
                "href": "https://an-rdap-server/domain/domain.com",
                "type": "application/rdap+json",
            },
            {
                "rel": "related",
                "href": "https://the-authoritative-server/domain/domain.com",
                "type": "application/rdap+json",
            },
        ]
        links_2 = [
            {
                "rel": "self",
                "href": "https://an-rdap-server/domain/domain.com",
                "type": "application/rdap+json",
            },
            {
                "rel": "related",
                "href": "https://the-authoritative-server",
                "type": "text/html",
            },
        ]
        links_3 = [
            {
                "rel": "self",
                "href": "https://an-rdap-server/domain/domain.com",
                "type": "application/rdap+json",
            }
        ]
        links_4 = [
            {
                "rel": "self",
                "href": "https://an-rdap-server/domain/domain.com",
                "type": "application/rdap+json",
            },
            {
                "rel": "related",
                "href": "https://the-authoritative-server",
                "type": "application/rdap+json",
            },
        ]
        client = DNSClient(None)
        client._target = "domain.com"
        #
        output_1 = client._check_next_href(current_href, links_1)
        assert output_1 == links_1[1].get("href")
        #
        output_2 = client._check_next_href(current_href, links_2)
        assert output_2 is None
        #
        output_3 = client._check_next_href(current_href, links_3)
        assert output_3 is None
        #
        output_4 = client._check_next_href(current_href, links_4)
        assert output_4 == "https://the-authoritative-server/domain/domain.com"
