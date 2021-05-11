import asynctest
import asynctest.mock as mock

from whodap import DNSClient


class TestDNSClient(asynctest.TestCase):

    def setUp(self) -> None:
        self.dns_client = DNSClient()

    @mock.patch("whodap.client.DNSClient._get_request")
    @mock.patch("whodap.client.DomainResponse.from_json")
    def test_lookup_domain(self, mock_rdap_resp, mock_request):
        self.dns_client.iana_dns_server_map = {'com': 'some-server-for-rdap'}
        mock_request.return_value = mock.Mock(status_code=200)
        mock_rdap_resp.return_value = mock.Mock(links=[mock.Mock(href='the-authority-server-for-domain')])
        self.dns_client.lookup('domain', 'com')
        assert mock_request.call_count == 2, f'_aio_get_request call_count {mock_request.call_count} != 2'
        assert mock_rdap_resp.call_count == 2, f'from_json call_count {mock_rdap_resp.call_count} != 2'

    @mock.patch("whodap.client.DNSClient._aio_get_request")
    @mock.patch("whodap.client.DomainResponse.from_json")
    async def test_aio_lookup_domain(self, mock_rdap_resp, mock_request):
        self.dns_client.iana_dns_server_map = {'com': 'some-server-for-rdap'}
        mock_request.return_value = mock.Mock(status_code=200)
        mock_rdap_resp.return_value = mock.Mock(links=[mock.Mock(href='the-authority-server-for-domain')])
        await self.dns_client.aio_lookup('domain', 'com')
        assert mock_request.call_count == 2, f'_aio_get_request call_count {mock_request.call_count} != 2'
        assert mock_rdap_resp.call_count == 2, f'from_json call_count {mock_rdap_resp.call_count} != 2'

    def test_iana_server_map(self):
        rdap_output = {
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
        self.dns_client._set_iana_dns_info(rdap_output)
        assert len(self.dns_client.iana_dns_server_map.keys()) == 4

    @mock.patch("whodap.client.DNSClient._aio_get_request")
    async def test_aio_load_dns(self, mock_request):
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        await self.dns_client._aio_load_from_iana()
        mock_request.assert_called_once()

    @mock.patch("whodap.client.DNSClient._get_request")
    def test_load_dns(self, mock_request):
        mock_request.return_value = mock.Mock(status_code=200, json=mock.Mock())
        self.dns_client._load_from_iana()
        mock_request.assert_called_once()
