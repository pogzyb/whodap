## whodap

`whodap` | Simple RDAP Utility for Python

- Builtin support for Asyncio
- Saves (aka "bootstraps") initial directory lookups from IANA
- Leverages the [SimpleNamespace](https://docs.python.org/3/library/types.html#types.SimpleNamespace) type for cleaner RDAP Response traversal
- Supports the familiar look of WHOIS via the `to_whois_dict` method


#### Quickstart

```python
import asyncio
from pprint import pprint

import whodap

# standard
response = whodap.lookup_domain(domain='ebay', tld='com')
# raw output from RDAP lookup
print(response) 
# Traverse the RDAP response via "dot" notation
print(response.entities)
# Example: retrieving nested "event" dates
print(response.events[0].eventDate)
# Don't like "dot" notation? Use `to_dict` for dictionary format
print(response.to_dict()["events"][0]["eventDate"])
# Use `to_whois_dict` for the classic "flat" output of WHOIS
pprint(response.to_whois_dict())
"""
{admin_address: '2145 Hamilton Avenue, San Jose, CA, 95125, US',
 admin_email: 'hostmaster@ebay.com',
 admin_name: 'eBay Inc.',
 admin_phone: '+1.4083769801',
 billing_address: None,
 billing_email: None,
 billing_name: None,
 billing_phone: None,
 created_date: datetime.datetime(1995, 8, 4, 4, 0),
 dnssec: False,
 domain_name: 'ebay.com',
 expires_date: datetime.datetime(2021, 8, 2, 7, 0),
 nameservers: ['dns1.p06.nsone.net',
               'dns2.p06.nsone.net',
               'dns3.p06.nsone.net',
               'dns4.p06.nsone.net',
               'ns01.ebaydns.com',
               'ns02.ebaydns.com',
               'ns03.ebaydns.com',
               'ns04.ebaydns.com'],
 registrant_address: '2145 Hamilton Avenue, San Jose, CA, 95125, US',
 registrant_email: 'hostmaster@ebay.com',
 registrant_name: 'eBay Inc.',
 registrant_phone: '+1.4083769801',
 registrar_address: '3540 E Longwing Ln, Meridian, ID, 83646, US',
 registrar_email: None,
 registrar_name: 'MarkMonitor Inc.',
 registrar_phone: None,
 status: ['client update prohibited',
          'client transfer prohibited',
          'client delete prohibited',
          'server update prohibited',
          'server transfer prohibited',
          'server delete prohibited'],
 technical_address: '2145 Hamilton Avenue, San Jose, CA, 95125, US',
 technical_email: 'hostmaster@ebay.com',
 technical_name: 'eBay Inc.',
 technical_phone: '+1.4083769801',
 updated_date: datetime.datetime(2021, 3, 4, 21, 59, 49)}
"""

# asyncio (full support for asynchronous calls)
loop = asyncio.get_event_loop()
response = loop.run_until_complete(whodap.aio_lookup_domain(domain='ebay', tld='com'))
...

```

#### Contributions
- Interested in contributing? 
- Have any questions or comments? 
- Anything that you'd like to see?

Please feel free to reach out me (@pogzyb)


#### Roadmap

First Alpha Release:
- Support for RDAP "domain" queries

Coming Soon:
- Support for RDAP "ipv4" and "ipv6" queries


#### RDAP Resources:
  - https://tools.ietf.org/html/rfc7483
  - https://tools.ietf.org/html/rfc6350
