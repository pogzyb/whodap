import asynctest
import asynctest.mock as mock

from whodap import lookup_domain, aio_lookup_domain


class TestPackageMethods(asynctest.TestCase):
    """
    Tests that the appropriate classes and methods are invoked for each package method.
    """

    @mock.patch('whodap.DNSClient')
    def test_lookup_domain(self, mock_dns_client):
        confirmation_string = 'dns_client_lookup_was_called'
        mock_dns_client.lookup.return_value = confirmation_string
        mock_dns_client.new_client.return_value = mock_dns_client
        resp = lookup_domain(domain='some-domain', tld='com')
        assert resp == confirmation_string, f"{resp} != {confirmation_string}"
        resp = lookup_domain(domain='some-domain', tld='com')
        assert resp == confirmation_string, f"{resp} != {confirmation_string}"

    @mock.patch('whodap.DNSClient')
    async def test_aio_lookup_domain(self, mock_dns_client):
        confirmation_string = 'dns_client_aio_lookup_was_called'
        mock_dns_client.aio_lookup = mock.CoroutineMock(return_value=confirmation_string)
        mock_dns_client.new_aio_client = mock.CoroutineMock(return_value=mock_dns_client)
        resp = await aio_lookup_domain(domain='some-domain', tld='com')
        assert resp == confirmation_string, f"{resp} != {confirmation_string}"
        resp = await aio_lookup_domain(domain='some-domain', tld='com')
        assert resp == confirmation_string, f"{resp} != {confirmation_string}"
