import asyncio
import sys
import unittest.mock as mock

import pytest
import whodap


confirmation_string = "dns_client_lookup_was_called"


if sys.version_info >= (3, 8):

    def mock_aio_dns_client():
        async_mock_client = mock.AsyncMock(
            name="mock-dns-client",
            aio_close=mock.AsyncMock(),
            aio_lookup=mock.AsyncMock(return_value=confirmation_string)
        )
        return async_mock_client


    def mock_dns_client():
        mock_client = mock.MagicMock(
            name="mock-dns-client",
            close=mock.Mock(),
            lookup=mock.Mock(return_value=confirmation_string)
        )
        return mock_client


    def test_lookup_domain():
        with mock.patch('whodap.DNSClient.new_client', return_value=mock_dns_client()):
            resp = whodap.lookup_domain(domain="some-domain", tld="com")
            assert resp == confirmation_string, f"{resp} != {confirmation_string}"


    @pytest.mark.asyncio
    async def test_aio_lookup_domain():
        with mock.patch('whodap.DNSClient.new_aio_client', return_value=mock_aio_dns_client()):
            resp = await whodap.aio_lookup_domain(domain="some-domain", tld="com")
            assert resp == confirmation_string, f"{resp} != {confirmation_string}"
