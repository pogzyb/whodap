from .client import DNSClient
from .response import DomainResponse
from .utils import get_cached_dns_client, get_cached_aio_dns_client

__all__ = ['aio_lookup_domain', 'lookup_domain', 'DNSClient']
__version__ = '0.1.0'


def lookup_domain(domain: str,
                  tld: str,
                  cache: bool = True,
                  **http_client_kws) -> DomainResponse:
    """
    Convenience function that instantiates a DNSClient,
    submits an RDAP query for the given domain, and returns
    the result as a DomainResponse. By default, caches the DNSClient
    so that subsequent calls will re-use the existing DNSClient.

    :param domain: the domain name to lookup
    :param tld: the top level domain (e.g. "com", "net", "buzz")
    :param cache: if True, attempt to use a cached DNSClient
    :param http_client_kws: kwargs passed directly to `httpx.Client`
    :return: an instance of DomainResponse
    """
    if cache:
        client = get_cached_dns_client(**http_client_kws)
    else:
        client = DNSClient.new_client(**http_client_kws)
    return client.lookup(domain, tld)


async def aio_lookup_domain(domain: str,
                            tld: str,
                            cache: bool = True,
                            **http_client_kws) -> DomainResponse:
    """
    Async convenience function that instantiates a DNSClient,
    submits an RDAP query for the given domain, and returns
    the result as a DomainResponse. By default, caches the DNSClient
    so that subsequent calls will re-use the existing DNSClient.

    :param domain: the domain name to lookup
    :param tld: the top level domain (e.g. "com", "net", "buzz")
    :param cache: if True, attempt to use a cached DNSClient
    :param http_client_kws: kwargs passed directly to `httpx.AsyncClient`
    :return: an instance of DomainResponse
    """
    if cache:
        client = get_cached_aio_dns_client(**http_client_kws)
    else:
        client = await DNSClient.new_aio_client(**http_client_kws)
    return await client.aio_lookup(domain, tld)
