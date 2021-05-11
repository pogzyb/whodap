from enum import Enum
from functools import lru_cache


@lru_cache(maxsize=1)
def get_cached_dns_client(**kwargs):
    from .client import DNSClient
    c = DNSClient.new_client(**kwargs)
    return c


@lru_cache(maxsize=1)
async def get_cached_aio_dns_client(**kwargs):
    from .client import DNSClient
    c = DNSClient.new_aio_client(**kwargs)
    return c


class WHOISKeys(str, Enum):
    """
    WHOIS field names
    """
    DOMAIN_NAME = 'domain_name'
    NAMESERVERS = 'nameservers'
    DNSSEC = 'dnssec'
    STATUS = 'status'
    CREATED_DATE = 'created_date'
    EXPIRES_DATE = 'expires_date'
    UPDATED_DATE = 'updated_date'
    ABUSE_EMAIL = 'abuse_email'
    ABUSE_PHONE = 'abuse_phone'
    ADMIN_NAME = 'admin_name'
    ADMIN_ORG = 'admin_organization'
    ADMIN_EMAIL = 'admin_email'
    ADMIN_ADDRESS = 'admin_address'
    ADMIN_PHONE = 'admin_phone'
    ADMIN_FAX = 'admin_fax'
    BILLING_NAME = 'billing_name'
    BILLING_ORG = 'billing_organization'
    BILLING_EMAIL = 'billing_email'
    BILLING_ADDRESS = 'billing_address'
    BILLING_PHONE = 'billing_phone'
    BILLING_FAX = 'billing_fax'
    REGISTRAR_NAME = 'registrar_name'
    REGISTRAR_EMAIL = 'registrar_email'
    REGISTRAR_ADDRESS = 'registrar_address'
    REGISTRAR_PHONE = 'registrar_phone'
    REGISTRAR_FAX = 'registrar_fax'
    REGISTRANT_NAME = 'registrant_name'
    REGISTRANT_ORG = 'registrant_organization'
    REGISTRANT_EMAIL = 'registrant_email'
    REGISTRANT_ADDRESS = 'registrant_address'
    REGISTRANT_PHONE = 'registrant_phone'
    REGISTRANT_FAX = 'registrant_fax'
    TECHNICAL_NAME = 'technical_name'
    TECHNICAL_ORG = 'technical_organization'
    TECHNICAL_EMAIL = 'technical_email'
    TECHNICAL_ADDRESS = 'technical_address'
    TECHNICAL_PHONE = 'technical_phone'
    TECHNICAL_FAX = 'technical_fax'

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value
