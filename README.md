## whodap

`whodap` | Simple RDAP Utility for Python

- Support for asyncio HTTP requests (thanks to `httpx`)
- Uses the Singleton pattern to save (aka "bootstrap") initial directory lookups from IANA
- Leverages the [SimpleNamespace](https://docs.python.org/3/library/types.html#types.SimpleNamespace) type for cleaner RDAP Response traversal
- Keeps the familiar look of WHOIS via the `to_whois_dict` method


#### Quickstart

```python
import asyncio
from pprint import pprint

import whodap

# Standard call
response = whodap.lookup_domain(domain='bitcoin', tld='org')
# asyncio call
loop = asyncio.get_event_loop()
response = loop.run_until_complete(whodap.aio_lookup_domain(domain='bitcoin', tld='org'))
# Raw output from RDAP lookup
print(response)
# Traverse the RDAP response via "dot" notation
print(response.events)
"""
[{
  "eventAction": "last update of RDAP database",
  "eventDate": "2021-04-23T21:50:03"
},
 {
  "eventAction": "registration",
  "eventDate": "2008-08-18T13:19:55"
},
 {
  "eventAction": "expiration",
  "eventDate": "2029-08-18T13:19:55"
},
 {
  "eventAction": "last changed",
  "eventDate": "2019-11-24T13:58:35"
}]
"""
# Retrieving the registration date from above:
print(response.events[1].eventDate)
"""
2008-08-18 13:19:55
"""
# Don't like "dot" notation? Use `to_dict` to get the RDAP response as a dictionary
pprint(response.to_dict())
# Use `to_whois_dict` for the familiar look of WHOIS output
pprint(response.to_whois_dict())
"""
{abuse_email: 'abuse@namecheap.com',
 abuse_phone: 'tel:+1.6613102107',
 admin_address: 'P.O. Box 0823-03411, Panama, Panama, PA',
 admin_email: '2603423f6ed44178a3b9d728827aa19a.protect@whoisguard.com',
 admin_name: 'WhoisGuard, Inc.',
 admin_phone: 'fax:+51.17057182',
 billing_address: None,
 billing_email: None,
 billing_name: None,
 billing_phone: None,
 created_date: datetime.datetime(2008, 8, 18, 13, 19, 55),
 domain_name: 'bitcoin.org',
 expires_date: datetime.datetime(2029, 8, 18, 13, 19, 55),
 nameservers: ['dns1.registrar-servers.com', 'dns2.registrar-servers.com'],
 registrant_address: 'P.O. Box 0823-03411, Panama, Panama, PA',
 registrant_email: '2603423f6ed44178a3b9d728827aa19a.protect@whoisguard.com',
 registrant_name: 'WhoisGuard, Inc.',
 registrant_phone: 'fax:+51.17057182',
 registrar_address: '4600 E Washington St #305, Phoenix, Arizona, 85034',
 registrar_email: 'support@namecheap.com',
 registrar_name: 'NAMECHEAP INC',
 registrar_phone: 'tel:+1.6613102107',
 status: ['client transfer prohibited'],
 technical_address: 'P.O. Box 0823-03411, Panama, Panama, PA',
 technical_email: '2603423f6ed44178a3b9d728827aa19a.protect@whoisguard.com',
 technical_name: 'WhoisGuard, Inc.',
 technical_phone: 'fax:+51.17057182',
 updated_date: datetime.datetime(2019, 11, 24, 13, 58, 35)}
"""
```

#### Contributions
- Interested in contributing? 
- Have any questions or comments? 
- Anything that you'd like to see?

Please post a question or comment.


#### Roadmap

Alpha Release:
- Support for RDAP "domain" queries

Coming Soon:
- Support for RDAP "ipv4" and "ipv6" queries


#### RDAP Resources:
  - https://tools.ietf.org/html/rfc7483
  - https://tools.ietf.org/html/rfc6350
