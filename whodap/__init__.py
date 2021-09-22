from typing import Optional

from httpx import Client, AsyncClient

from .client import DNSClient
from .response import DomainResponse

__all__ = ['aio_lookup_domain', 'lookup_domain', 'DNSClient']
__version__ = '0.1.2'


def lookup_domain(domain: str,
                  tld: str,
                  httpx_client: Optional[Client] = None) -> DomainResponse:
    """
    Convenience function that instantiates a DNSClient,
    submits an RDAP query for the given domain, and returns
    the result as a DomainResponse.

    :param domain: the domain name to lookup
    :param tld: the top level domain (e.g. "com", "net", "buzz")
    :param httpx_client: Custom, pre-configured instance `httpx.Client`
    :return: an instance of DomainResponse
    """
    dns_client = DNSClient.new_client(httpx_client)
    response = dns_client.lookup(domain, tld)
    if not httpx_client and not dns_client.httpx_client.is_closed:
        dns_client.httpx_client.close()
    return response


async def aio_lookup_domain(domain: str,
                            tld: str,
                            httpx_client: Optional[AsyncClient] = None) -> DomainResponse:
    """
    Async-compatible convenience function that instantiates
    a DNSClient, submits an RDAP query for the given domain,
    and returns the result as a DomainResponse.

    :param domain: the domain name to lookup
    :param tld: the top level domain (e.g. "com", "net", "buzz")
    :param httpx_client: Custom, pre-configured instance `httpx.AsyncClient`
    :return: an instance of DomainResponse
    """
    dns_client = await DNSClient.new_aio_client(httpx_client)
    response = await dns_client.aio_lookup(domain, tld)
    if not httpx_client and not dns_client.httpx_client.is_closed:
        await dns_client.httpx_client.aclose()
    return response
