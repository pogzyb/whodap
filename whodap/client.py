import sys
import posixpath
import ipaddress
from abc import ABC, abstractmethod
from typing import Dict, Any, Union, Optional
from contextlib import contextmanager

# different installs for async contextmanager based on python version
if sys.version_info.major == 3 and sys.version_info.minor < 7:
    from async_generator import asynccontextmanager
else:
    from contextlib import asynccontextmanager

import httpx

from .codes import RDAPStatusCodes
from .errors import RateLimitError, NotFoundError, MalformedQueryError, BadStatusCode
from .response import DomainResponse


class RDAPClient(ABC):
    _iana_publication_key: str = 'publication'
    _iana_verison_key: str = 'version'
    _iana_services_key: str = 'services'
    _iana_uri: str = None

    def __init__(self, httpx_client: Union[httpx.Client, httpx.AsyncClient]):
        self.httpx_client = httpx_client
        self.version: str = ''
        self.publication: str = ''

    @classmethod
    @abstractmethod
    def new_client_context(cls, httpx_client):
        ...

    @classmethod
    @abstractmethod
    def new_client(cls, httpx_client):
        ...

    @classmethod
    @abstractmethod
    async def new_aio_client_context(cls, httpx_client):
        ...

    @classmethod
    @abstractmethod
    async def new_aio_client(cls, httpx_client):
        ...

    @abstractmethod
    def lookup(self):
        ...

    @abstractmethod
    async def aio_lookup(self):
        ...

    @staticmethod
    @abstractmethod
    def _build_query_uri() -> str:
        ...

    def _get_request(self, uri: str) -> httpx.Response:
        return self.httpx_client.get(uri)

    async def _aio_get_request(self, uri: str) -> httpx.Response:
        return await self.httpx_client.get(uri)

    @staticmethod
    def _check_status_code(status_code: int) -> None:
        if status_code == RDAPStatusCodes.POSITIVE_ANSWER_200:
            return None
        elif status_code == RDAPStatusCodes.MALFORMED_QUERY_400:
            raise MalformedQueryError(
                f"Malformed query: {RDAPStatusCodes.MALFORMED_QUERY_400}")
        elif status_code == RDAPStatusCodes.NEGATIVE_ANSWER_404:
            raise NotFoundError(
                f"Domain not found: {RDAPStatusCodes.NEGATIVE_ANSWER_404}")
        elif status_code == RDAPStatusCodes.RATE_LIMIT_429:
            raise RateLimitError(
                f"Too many requests: {RDAPStatusCodes.RATE_LIMIT_429}")
        else:
            raise BadStatusCode(f"Status code <{status_code}>")


class DNSClient(RDAPClient):
    # IANA DNS
    _iana_uri: str = 'https://data.iana.org/rdap/dns.json'

    def __init__(self, httpx_client: Union[httpx.Client, httpx.AsyncClient]):
        super(DNSClient, self).__init__(httpx_client)
        self.iana_dns_server_map: Dict[str, str] = {}

    @classmethod
    @contextmanager
    def new_client_context(cls, httpx_client: Optional[httpx.Client] = None):
        """
        Contextmanager for instantiating a Synchronous DNSClient

        :httpx_client: pre-configured instance of `httpx.Client`
        :return: yields the initialized DNSClient
        """
        dns_client = cls(httpx_client or httpx.Client())
        try:
            iana_dns_info = dns_client.get_iana_dns_info()
            dns_client.set_iana_dns_info(iana_dns_info)
            yield dns_client
        except:
            raise
        finally:
            if not dns_client.httpx_client.is_closed:
                dns_client.httpx_client.close()

    @classmethod
    def new_client(cls, httpx_client: Optional[httpx.Client] = None):
        """
        Classmethod for instantiating an synchronous instance of DNSClient

        :httpx_client: pre-configured instance of `httpx.Client`
        :return: DNSClient with a sync httpx_client
        """
        # init the client with a default httpx.Client if one is not provided
        dns_client = cls(httpx_client or httpx.Client())
        # load the dns server information from IANA
        iana_dns_info = dns_client.get_iana_dns_info()
        # parse and save the server information
        dns_client.set_iana_dns_info(iana_dns_info)
        # return the loaded client
        return dns_client

    @classmethod
    @asynccontextmanager
    async def new_aio_client_context(cls, httpx_client: Optional[httpx.AsyncClient] = None):
        """
        Contextmanager for instantiating an Asynchronous DNSClient

        :httpx_client: Optional pre-configured instance of `httpx.AsyncClient`
        :return: yields the initialized DNSClient
        """
        dns_client = cls(httpx_client or httpx.AsyncClient())
        try:
            iana_dns_info = await dns_client.aio_get_iana_dns_info()
            dns_client.set_iana_dns_info(iana_dns_info)
            yield dns_client
        except:
            raise
        finally:
            if not dns_client.httpx_client.is_closed:
                await dns_client.httpx_client.aclose()

    @classmethod
    async def new_aio_client(cls, httpx_client: Optional[httpx.AsyncClient] = None):
        """
        Classmethod for instantiating an asynchronous instance of DNSClient

        :httpx_client: pre-configured instance of `httpx.AsyncClient`
        :return: DNSClient with an async httpx_client
        """
        dns_client = cls(httpx_client or httpx.AsyncClient())
        iana_dns_info = await dns_client.aio_get_iana_dns_info()
        dns_client.set_iana_dns_info(iana_dns_info)
        return dns_client

    def get_iana_dns_info(self):
        response = self._get_request(self._iana_uri)
        return response.json()

    async def aio_get_iana_dns_info(self):
        response = await self._aio_get_request(self._iana_uri)
        return response.json()

    @staticmethod
    def _build_query_uri(rdap_uri: str, domain: str) -> str:
        return posixpath.join(rdap_uri, 'domain', domain.lstrip('/'))

    def lookup(self, domain: str, tld: str, auth_ref: str = None) -> DomainResponse:
        """
        Performs an RDAP domain lookup.

        First, finds the appropriate server for the top level domain,
        sends an HTTP request to the server, parses the response for a more authoritative source,
        sends an additional HTTP request to the more authoritative source, and finally
        encapsulates the HTTP response into a DomainResponse object.

        :param domain: the domain name
        :param tld: the top level domain
        :param auth_ref: optional authoritative url for the given TLD
        :return: instance of DomainResponse
        """
        domain_and_tld = domain + '.' + tld
        # if an authoritative url is provided; use it
        if auth_ref:
            query_url = self._build_query_uri(auth_ref, domain_and_tld)
            resp = self._get_request(query_url)
            self._check_status_code(resp.status_code)
            return DomainResponse.from_json(resp.text)
        # start with looking up server in the IANA list
        server_url = self.iana_dns_server_map.get(tld)
        if not server_url:
            raise NotImplementedError(f'No RDAP Server for ".{tld.upper()}"')
        # hit the server found in the IANA list
        query_url = self._build_query_uri(server_url, domain_and_tld)
        response = self._get_request(query_url)
        self._check_status_code(response.status_code)
        domain_response = DomainResponse.from_json(response.text)
        # try to extract an authoritative server for this domain
        if hasattr(domain_response, 'links'):
            authoritative_url = domain_response.links[-1].href
            # avoid redundant connections
            if authoritative_url.lower() != query_url.lower():
                resp = self._get_request(authoritative_url)
                self._check_status_code(resp.status_code)
                return DomainResponse.from_json(resp.text)
            else:
                return domain_response
        else:
            return domain_response

    async def aio_lookup(self, domain: str, tld: str, auth_ref: str = None) -> DomainResponse:
        """
        Performs an RDAP domain lookup.

        First, finds the appropriate server for the top level domain,
        sends an HTTP request to the server, parses the response for a more authoritative source,
        sends an additional HTTP request to the more authoritative source, and finally
        encapsulates the HTTP response into a DomainResponse object.

        :param domain: the domain name
        :param tld: the top level domain
        :param auth_ref: optional authoritative url for the given TLD
        :return: instance of DomainResponse
        """
        domain_and_tld = domain + '.' + tld
        if auth_ref:
            query_url = self._build_query_uri(auth_ref, domain_and_tld)
            resp = await self._aio_get_request(query_url)
            self._check_status_code(resp.status_code)
            return DomainResponse.from_json(resp.read())
        server_url = self.iana_dns_server_map.get(tld)
        if not server_url:
            raise NotImplementedError(f'Could not find RDAP server for .{tld.upper()} domains')
        query_url = self._build_query_uri(server_url, domain_and_tld)
        response = await self._aio_get_request(query_url)
        self._check_status_code(response.status_code)
        domain_response = DomainResponse.from_json(response.read())
        if hasattr(domain_response, 'links'):
            authoritative_url = domain_response.links[-1].href
            if authoritative_url.lower() != query_url.lower():
                resp = await self._aio_get_request(authoritative_url)
                self._check_status_code(resp.status_code)
                return DomainResponse.from_json(resp.read())
            else:
                return domain_response
        else:
            return domain_response

    def set_iana_dns_info(self, iana_dns_map: Dict[str, Any]) -> None:
        """
        Populates the DNSClient's `iana_dns_server_map` attribute with
        the server information found in the given `iana_dns_map`.

        :param iana_dns_map: Server information retrieved from `self._iana_url`
        :return: None
        """
        self.publication = iana_dns_map.get(self._iana_publication_key)
        self.version = iana_dns_map.get(self._iana_verison_key)
        tld_server_map = {}
        for tlds, server in iana_dns_map.get(self._iana_services_key):
            for tld in tlds:
                tld_server_map[tld] = server[0]
        self.iana_dns_server_map = tld_server_map


class IPv4Client(RDAPClient):
    # IANA IPv4
    _iana_uri: str = 'https://data.iana.org/rdap/ipv4.json'
    _arin_registry_uri: str = 'https://rdap.arin.net/registry/ip/'

    def __init__(self):
        super(IPv4Client, self).__init__()
        self.iana_ipv4_server_map: Dict[str, str] = {}

    @classmethod
    def new_client(cls):
        ...

    @classmethod
    async def new_aio_client(cls):
        ...

    def lookup(self):
        ...

    async def aio_lookup(self):
        ...

    @staticmethod
    def _build_query_uri(rdap_uri: str, ip_address: str) -> str:
        return posixpath.join(rdap_uri, ip_address)

    def _set_ipv4_server_map(self, iana_ipv4_map: Dict[str, Any]):
        ...


class IPv6Client(RDAPClient):
    # IANA IPv6
    ...

    @classmethod
    def new_client(cls):
        ...

    @classmethod
    async def new_aio_client(cls):
        ...

    def lookup(self):
        ...

    async def aio_lookup(self):
        ...

    @staticmethod
    def _build_query_uri() -> str:
        ...


class ASNClient(RDAPClient):
    # IANA ASN
    ...

    @classmethod
    def new_client(cls):
        ...

    @classmethod
    async def new_aio_client(cls):
        ...

    def lookup(self):
        ...

    async def _aio_load_from_iana(self):
        ...

    @staticmethod
    def _build_query_uri() -> str:
        ...
