import asynctest
import asynctest.mock as mock

from whodap import DNSClient
from whodap.errors import RateLimitError, NotFoundError, MalformedQueryError


class TestDNSClient(asynctest.TestCase):

    def setUp(self) -> None:
        self.dns_client = DNSClient.new_client()

    def test_build_query_url(self):
        expected_base_case = "http://some-url.com/domain/domain-name"
        output = self.dns_client._build_query_uri("http://some-url.com/", "domain-name")
        assert output == expected_base_case, f"{output} != {expected_base_case}"
        expected_absolute_case = "http://bad-example/domain/forward-slash-domain"
        output = self.dns_client._build_query_uri("http://bad-example", "/forward-slash-domain")
        assert output == expected_absolute_case, f"{output} != {expected_absolute_case}"

    def test_check_status(self):
        assert self.dns_client._check_status_code(200) is None
        self.assertRaises(RateLimitError, self.dns_client._check_status_code, 429)
        self.assertRaises(NotFoundError, self.dns_client._check_status_code, 404)
        self.assertRaises(MalformedQueryError, self.dns_client._check_status_code, 400)

    @mock.patch("whodap.client.DNSClient._get_request")
    @mock.patch("whodap.client.DomainResponse.from_json")
    def test_lookup(self, mock_rdap_resp, mock_request):
        self.dns_client.iana_dns_server_map = {'com': 'some-server-for-rdap'}
        mock_request.return_value = mock.Mock(status_code=200)
        mock_rdap_resp.return_value = mock.Mock(links=[mock.Mock(href='the-authority-server-for-domain')])
        self.dns_client.lookup('domain', 'com')
        assert mock_request.call_count == 2, f'_aio_get_request call_count {mock_request.call_count} != 2'
        assert mock_rdap_resp.call_count == 2, f'from_json call_count {mock_rdap_resp.call_count} != 2'
        self.dns_client.lookup('domain', 'com', auth_ref='some-auth-ref')
        assert mock_request.call_count == 3
        assert mock_rdap_resp.call_count == 3

    @mock.patch("whodap.client.DNSClient._aio_get_request")
    @mock.patch("whodap.client.DomainResponse.from_json")
    async def test_aio_lookup(self, mock_rdap_resp, mock_request):
        self.dns_client.iana_dns_server_map = {'com': 'some-server-for-rdap'}
        mock_request.return_value = mock.Mock(status_code=200)
        mock_rdap_resp.return_value = mock.Mock(links=[mock.Mock(href='the-authority-server-for-domain')])
        await self.dns_client.aio_lookup('domain', 'com')
        assert mock_request.call_count == 2, f'_aio_get_request call_count {mock_request.call_count} != 2'
        assert mock_rdap_resp.call_count == 2, f'from_json call_count {mock_rdap_resp.call_count} != 2'
        await self.dns_client.aio_lookup('domain', 'com', auth_ref='some-auth-ref')
        assert mock_request.call_count == 3
        assert mock_rdap_resp.call_count == 3

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
        self.dns_client.set_iana_dns_info(rdap_output)
        assert len(self.dns_client.iana_dns_server_map.keys()) == 4
        assert self.dns_client.publication == "2021-05-05"
        assert self.dns_client.version == "2"

    @mock.patch("whodap.client.DNSClient._aio_get_request")
    async def test_aio_load_dns(self, mock_request):
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        await self.dns_client.aio_get_iana_dns_info()
        mock_request.assert_called_once()

    @mock.patch("whodap.client.DNSClient._get_request")
    def test_load_dns(self, mock_request):
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        self.dns_client.get_iana_dns_info()
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
        self.dns_client.httpx_client = mock_client
        resp = await self.dns_client._aio_get_request("https://www.some-domain.com")
        assert resp == fake_http_response, f"{resp} != {fake_http_response}"
