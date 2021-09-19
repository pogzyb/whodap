## whodap

[![Build Status](https://app.travis-ci.com/pogzyb/whodap.svg?token=xCoELzvjMvTqZThTS7Va&branch=main)](https://app.travis-ci.com/pogzyb/whodap)
[![codecov](https://codecov.io/gh/pogzyb/whodap/branch/main/graph/badge.svg?token=NCfdf6ftb9)](https://codecov.io/gh/pogzyb/whodap)
[![PyPI version](https://badge.fury.io/py/whodap.svg)](https://badge.fury.io/py/whodap)

`whodap` | Simple RDAP Utility for Python

- Support for asyncio HTTP requests (using `httpx`)
- Caching option for initial IANA dns loads
- Leverages the [SimpleNamespace](https://docs.python.org/3/library/types.html#types.SimpleNamespace) type for cleaner RDAP Response traversal
- Keeps the familiar look of WHOIS via the `to_whois_dict` method


#### Quickstart

```python
import asyncio
from pprint import pprint

import whodap

# Looking up a domain name
response = whodap.lookup_domain(domain='bitcoin', tld='org') 
# Equivalent asyncio call
loop = asyncio.get_event_loop()
response = loop.run_until_complete(whodap.aio_lookup_domain(domain='bitcoin', tld='org'))
# "response" is a DomainResponse object. It contains the output from the RDAP lookup.
print(response)
# Traverse the DomainResponse via "dot" notation
print(response.events)
"""
[{
  "eventAction": "last update of RDAP database",
  "eventDate": "2021-04-23T21:50:03"
},
 {
  "eventAction": "registration",
  "eventDate": "2008-08-18T13:19:55"
}, ... ]
"""
# Retrieving the registration date from above:
print(response.events[1].eventDate)
"""
2008-08-18 13:19:55
"""
# Don't want "dot" notation? Use `to_dict` to get the RDAP response as a dictionary
pprint(response.to_dict())
# Use `to_whois_dict` for the familiar look of WHOIS output
pprint(response.to_whois_dict())
"""
{abuse_email: 'abuse@namecheap.com',
 abuse_phone: 'tel:+1.6613102107',
 admin_address: 'P.O. Box 0823-03411, Panama, Panama, PA',
 admin_email: '2603423f6ed44178a3b9d728827aa19a.protect@whoisguard.com',
 admin_fax: 'fax:+51.17057182',
 admin_name: 'WhoisGuard Protected',
 admin_organization: 'WhoisGuard, Inc.',
 admin_phone: 'tel:+507.8365503',
 billing_address: None,
 billing_email: None,
 billing_fax: None,
 billing_name: None,
 billing_organization: None,
 billing_phone: None,
 created_date: datetime.datetime(2008, 8, 18, 13, 19, 55),
 domain_name: 'bitcoin.org',
 expires_date: datetime.datetime(2029, 8, 18, 13, 19, 55),
 nameservers: ['dns1.registrar-servers.com', 'dns2.registrar-servers.com'],
 registrant_address: 'P.O. Box 0823-03411, Panama, Panama, PA',
 registrant_email: '2603423f6ed44178a3b9d728827aa19a.protect@whoisguard.com',
 registrant_fax: 'fax:+51.17057182',
 registrant_name: 'WhoisGuard Protected',
 registrant_organization: None,
 registrant_phone: 'tel:+507.8365503',
 registrar_address: '4600 E Washington St #305, Phoenix, Arizona, 85034',
 registrar_email: 'support@namecheap.com',
 registrar_fax: None,
 registrar_name: 'NAMECHEAP INC',
 registrar_phone: 'tel:+1.6613102107',
 status: ['client transfer prohibited'],
 technical_address: 'P.O. Box 0823-03411, Panama, Panama, PA',
 technical_email: '2603423f6ed44178a3b9d728827aa19a.protect@whoisguard.com',
 technical_fax: 'fax:+51.17057182',
 technical_name: 'WhoisGuard Protected',
 technical_organization: 'WhoisGuard, Inc.',
 technical_phone: 'tel:+507.8365503',
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
