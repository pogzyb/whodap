import asynctest
import asynctest.mock as mock

from whodap import DNSClient, IPv4Client, IPv6Client, ASNClient
from whodap.errors import RateLimitError, NotFoundError, MalformedQueryError


class TestDNSClient(asynctest.TestCase):

    async def setUp(self) -> None:
        self.dns_client = DNSClient.new_client()
        self.aio_dns_client = await DNSClient.new_aio_client()

    async def tearDown(self) -> None:
        self.dns_client.close()
        await self.aio_dns_client.aio_close()

    def test_build_query_url(self):
        expected_base_case = "http://some-url.com/domain/domain-name"
        output = DNSClient._build_query_href("http://some-url.com/", "domain-name")
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        expected_absolute_case = "http://bad-example/domain/forward-slash-domain"
        output = DNSClient._build_query_href("http://bad-example", "/forward-slash-domain")
        assert output == expected_absolute_case, f"{output} != {expected_absolute_case}"
        # ipv4
        expected_base_case = "http://some-url.com/ip/8.8.8.8"
        output = IPv4Client._build_query_href("http://some-url.com/", "8.8.8.8")
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        # ipv6
        expected_base_case = "http://some-url.com/ip/2001:4860:4860::8844"
        output = IPv6Client._build_query_href("http://some-url.com/", "2001:4860:4860::8844")
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        # asn
        expected_base_case = "http://some-url.com/autnum/12345"
        output = ASNClient._build_query_href("http://some-url.com/", "12345")
        assert output == expected_base_case, f"{output} != {expected_base_case}"

    def test_check_status(self):
        assert DNSClient._check_status_code(200) is None
        self.assertRaises(RateLimitError, DNSClient._check_status_code, 429)
        self.assertRaises(NotFoundError, DNSClient._check_status_code, 404)
        self.assertRaises(MalformedQueryError, DNSClient._check_status_code, 400)

    @mock.patch("whodap.client.RDAPClient._get_request")
    def test_lookup(self, mock_request):
        self.dns_client.iana_dns_server_map = {'com': 'https://an-rdap-server/'}
        links = [
            {
                'rel': 'self',
                'href': 'https://an-rdap-server/domain/domain.com',
                'type': 'application/rdap+json'
            },
            {
                'rel': 'related',
                'href': 'https://the-authoritative-server/domain/domain.com',
                'type': 'application/rdap+json'
            }
        ]
        # set up mock request
        mock_request.return_value = \
            mock.Mock(status_code=200,
                      json=mock.Mock(return_value={'links': links}),
                      read=mock.Mock(return_value=b'{"test": "json"}'))
        self.dns_client.lookup('domain', 'com')
        assert mock_request.call_count == 2, f'_aio_get_request call_count {mock_request.call_count} != 2'
        # reset mock request's return
        links = [
            {
                'rel': 'self',
                'href': 'https://the-authoritative-server/domain/domain.com',
                'type': 'application/rdap+json'
            }
        ]
        mock_request.return_value = \
            mock.Mock(status_code=200,
                      json=mock.Mock(return_value={'links': links}),
                      read=mock.Mock(return_value=b'{"test": "json"}'))
        self.dns_client.lookup('domain', 'com', auth_href='https://the-authoritative-server/domain/domain.com')
        # should only have made 1 additional request
        assert mock_request.call_count == 3, f'_aio_get_request call_count {mock_request.call_count} != 3'

    @mock.patch("whodap.client.RDAPClient._aio_get_request")
    async def test_aio_lookup(self, mock_request):
        self.dns_client.iana_dns_server_map = {'com': 'https://an-rdap-server/'}
        links = [
            {
                'rel': 'self',
                'href': 'https://an-rdap-server/domain/domain.com',
                'type': 'application/rdap+json'
            },
            {
                'rel': 'related',
                'href': 'https://the-authoritative-server/domain/domain.com',
                'type': 'application/rdap+json'
            }
        ]
        # set up mock request
        mock_request.return_value = \
            mock.CoroutineMock(
                status_code=200,
                json=mock.Mock(return_value={'links': links}),
                read=mock.Mock(return_value=b'{"test": "json"}'))
        # check it
        await self.aio_dns_client.aio_lookup('domain', 'com')
        assert mock_request.call_count == 2, f'_aio_get_request call_count {mock_request.call_count} != 2'
        links = [
            {
                'rel': 'self',
                'href': 'https://the-authoritative-server/domain/domain.com',
                'type': 'application/rdap+json'
            }
        ]
        # set up mock request
        mock_request.return_value = \
            mock.CoroutineMock(status_code=200,
                               json=mock.Mock(return_value={'links': links}),
                               read=mock.Mock(return_value=b'{"test": "json"}'))
        await self.aio_dns_client.aio_lookup(
            'domain', 'com', auth_href='https://the-authoritative-server/domain/domain.com')
        assert mock_request.call_count == 3

    def test_iana_server_map(self):
        rdap_output = {
            "publication": "2021-05-05",
            "version": "2",
            "services": [
                [
                    ["tld1", "tld2", "tld3"],
                    ["https://api.rdap.somewhere.net/"]
                ],
                [
                    ["tld4"],
                    ["https://api.rdap.nic/"]
                ]
            ]
        }
        self.dns_client._set_iana_info(rdap_output)
        assert len(self.dns_client.iana_dns_server_map.keys()) == 4
        assert self.dns_client.publication == "2021-05-05"
        assert self.dns_client.version == "2"

    @mock.patch("whodap.client.DNSClient._aio_get_request")
    async def test_aio_get_iana_info(self, mock_request):
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        await self.aio_dns_client._aio_get_iana_info()
        mock_request.assert_called_once()

    @mock.patch("whodap.client.DNSClient._get_request")
    def test_load_dns(self, mock_request):
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        self.dns_client._get_iana_info()
        mock_request.assert_called_once()

    def test_get_request(self):
        fake_http_response = "fake-http-response"
        mock_client = mock.Mock(get=mock.Mock(return_value=fake_http_response))
        self.dns_client.httpx_client = mock_client
        resp = self.dns_client._get_request("https://www.some-domain.com")
        assert resp == fake_http_response, f"{resp} != {fake_http_response}"

    async def test_get_aio_request(self):
        fake_http_response = "fake-http-response"
        mock_client = mock.Mock(get=mock.CoroutineMock(return_value=fake_http_response))
        self.aio_dns_client.httpx_client = mock_client
        resp = await self.aio_dns_client._aio_get_request("https://www.some-domain.com")
        assert resp == fake_http_response, f"{resp} != {fake_http_response}"

    async def test_async_context_manager(self):
        fake_http_response = "fake-http-response"
        mock_client = mock.Mock(get=mock.CoroutineMock(return_value=fake_http_response),
                                json=mock.Mock(return_value=fake_http_response))
        async with DNSClient.new_aio_client_context() as aio_dns_client:
            aio_dns_client.httpx_client = mock_client
            resp = await aio_dns_client._aio_get_request("https://www.some-domain.com")
            assert resp == fake_http_response, f"{resp} != {fake_http_response}"

    def test_context_manager(self):
        fake_http_response = "fake-http-response"
        mock_client = mock.Mock(get=mock.Mock(return_value=fake_http_response))
        with DNSClient.new_client_context() as dns_client:
            dns_client.httpx_client = mock_client
            resp = dns_client._get_request("https://www.some-domain.com")
            assert resp == fake_http_response, f"{resp} != {fake_http_response}"

    def test__check_next_href(self):
        current_href = 'https://an-rdap-server/domain/domain.com'
        links_1 = [
            {
                'rel': 'self',
                'href': 'https://an-rdap-server/domain/domain.com',
                'type': 'application/rdap+json'
            },
            {
                'rel': 'related',
                'href': 'https://the-authoritative-server/domain/domain.com',
                'type': 'application/rdap+json'
            }
        ]
        links_2 = [
            {
                'rel': 'self',
                'href': 'https://an-rdap-server/domain/domain.com',
                'type': 'application/rdap+json'
            },
            {
                'rel': 'related',
                'href': 'https://the-authoritative-server',
                'type': 'text/html'
            }
        ]
        links_3 = [
            {
                'rel': 'self',
                'href': 'https://an-rdap-server/domain/domain.com',
                'type': 'application/rdap+json'
            }
        ]
        links_4 = [
            {
                'rel': 'self',
                'href': 'https://an-rdap-server/domain/domain.com',
                'type': 'application/rdap+json'
            },
            {
                'rel': 'related',
                'href': 'https://the-authoritative-server',
                'type': 'application/rdap+json'
            }

        ]

        client = DNSClient(None)
        client._target = "domain.com"
        #
        output_1 = client._check_next_href(current_href, links_1)
        self.assertEqual(output_1, links_1[1].get('href'))
        #
        output_2 = client._check_next_href(current_href, links_2)
        self.assertEqual(output_2, None)
        #
        output_3 = client._check_next_href(current_href, links_3)
        self.assertEqual(output_3, None)
        #
        output_4 = client._check_next_href(current_href, links_4)
        self.assertEqual(output_4, 'https://the-authoritative-server/domain/domain.com')
