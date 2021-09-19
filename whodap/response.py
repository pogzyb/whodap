from abc import ABC, abstractmethod
from datetime import datetime
from json import dumps, loads
from types import SimpleNamespace
from typing import Dict, Any, List, Union

from .utils import WHOISKeys, RDAPVCardKeys

REDACTED = 'REDACTED FOR PRIVACY'


class RDAPResponse(SimpleNamespace, ABC):
    """
    Abstract class representing an RDAP Response
    """

    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)

    def __str__(self):
        return self.to_json(indent=2)

    def __repr__(self):
        return self.to_json(indent=2)

    @abstractmethod
    def to_json(self, **kwargs):
        ...

    @abstractmethod
    def to_dict(self, **kwargs):
        ...

    @staticmethod
    def _convert_date(ds: str) -> Union[str, datetime]:
        """
        Utility for converting known RDAP date strings
        into Python datetime objects.

        :param ds: a date string
        :return: a datetime object or the original string
        """
        known_rdap_formats = (
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S%z',
            # https://stackoverflow.com/questions/53291250/python-3-6-datetime-strptime-returns-error-while-python-3-7-works-well
            '%Y-%m-%dT%H:%M:%S.%fZ'
        )
        for date_format in known_rdap_formats:
            try:
                # try every date format used by RDAP
                v = datetime.strptime(ds, date_format)
                return v
            except ValueError:
                continue
        # return original date string if unsuccessful
        return ds

    def _convert_list(self, ls: List[Any]) -> List[Any]:
        """
        Iterates over the given list checking for nested RDAPResponses;
        Recursively calls itself when it encounters another list otherwise
        converts RDAPResponses and appends values.

        :param ls: any list
        :return: another list
        """
        converted = []
        for obj in ls:
            if isinstance(obj, type(self)):
                converted.append(self._convert_self_to_dict(obj))
            elif isinstance(obj, list):
                converted.append(self._convert_list(obj))
            else:
                converted.append(obj)
        return converted

    def _convert_self_to_dict(self, rdr: 'RDAPResponse') -> Dict[str, Any]:
        """
        Converts the RDAPResponse to a dictionary.
        Recursively calls itself to convert nested RDAPResponse.

        :param rdr: an instance of RDAPResponse
        :return: the RDAPResponse converted to a dictionary
        """
        converted = {}
        for key, value in rdr.__dict__.items():
            if isinstance(value, list):
                converted[key] = self._convert_list(value)
            elif isinstance(value, type(self)):
                converted[key] = self._convert_self_to_dict(value)
            else:
                converted[key] = value
        return converted

    @classmethod
    def from_json(cls, json: Union[str, bytes]):
        """
        Initializes an instance of DomainResponse from the
        JSON output of an RDAP HTTP query.

        :param json: JSON Response from the RDAP server
        :return: an RDAPResponse
        """
        return loads(json, object_hook=lambda d: cls(**d))


class DomainResponse(RDAPResponse):

    def __getattribute__(self, item):
        """
        Converts and returns an "eventDate" value to a datetime object;
        otherwise returns the value of the given attribute
        """
        val = super().__getattribute__(item)
        if item == 'eventDate':
            return self._convert_date(val)
        return val

    @staticmethod
    def _encoder(x: Any):
        """
        JSON encoding helper for "datetime" objects.

        :param x: Any
        :return: "datetime" as an iso formatted string or Any
        """
        if isinstance(x, datetime):
            return x.isoformat()
        return x

    def to_json(self, **kwargs) -> str:
        """
        Converts the DomainResponse to a JSON string.

        :param kwargs: arguments to be passed to `json.dumps`
        :return: JSON string
        """
        if not kwargs.get('default'):
            kwargs['default'] = self._encoder
        return dumps(self.to_dict(), **kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the DomainResponse to a dictionary.
        """
        return self._convert_self_to_dict(self)

    def to_whois_json(self, **kwargs) -> str:
        """
        Converts the DomainResponse to a WHOIS JSON string.

        :param kwargs: arguments to be passed to `json.dumps`
        :return: JSON string
        """
        if not kwargs.get('default'):
            kwargs['default'] = self._encoder
        return dumps(self.to_whois_dict(), **kwargs)

    def to_whois_dict(self) -> Dict[WHOISKeys, Union[str, List[str], datetime, None]]:
        """
        Returns the DomainResponse as "flattened" WHOIS dictionary;
        does not modify the original DomainResponse object.

        :return: dict with WHOIS keys
        """
        flat = {}

        # traverse and extract information from RDAP fields
        if getattr(self, 'nameservers', None):
            flat_nameservers = {'nameservers': []}
            for obj in self.nameservers:
                flat_nameservers['nameservers'].append(obj.ldhName)
            flat.update(flat_nameservers)

        if getattr(self, 'status', None):
            flat.update({'status': self.status})

        if getattr(self, 'events', None):
            flat.update(self._flat_dates(self.events))

        if getattr(self, 'entities', None):
            flat.update(self._flat_entities(self.entities))

        # convert dict keys over to "WHOISKeys"
        flat = self._construct_flat_dict(flat)

        # add domain name
        flat[WHOISKeys.DOMAIN_NAME] = self.ldhName

        # add dnssec after ensuring that it exists
        if getattr(self, 'secureDNS', None) and \
                getattr(self.secureDNS, 'delegationSigned', None):
            flat[WHOISKeys.DNSSEC] = self.secureDNS.delegationSigned

        return flat

    def _flatten_list(self, ls: List[Any]):
        """
        Recursively flattens the input list.

        :param ls: any list
        :return: a flattened list
        """
        flattened = []
        for i in ls:
            if isinstance(i, list):
                flattened.extend(self._flatten_list(i))
            else:
                flattened.append(i)
        return flattened

    @staticmethod
    def _flat_dates(events: List[SimpleNamespace]) -> Dict[str, datetime]:
        """
        Returns the list of events as a flattened dict of date keys and values

        :param events: list of "events" from the RDAP response
        :return: dictionary of "date" key value pairs
        """
        dates = dict([(event.eventAction, event.eventDate) for event in events])
        return dates

    def _flat_entities(self, entities: List[SimpleNamespace]) -> Dict[str, Dict[str, str]]:
        entities_dict = {}
        for entity in entities:
            ent_dict = {}
            # check for redacted information
            mark_redacted = False
            if hasattr(entity, 'remarks'):
                for remark in entity.remarks:
                    if hasattr(remark, 'title') and 'redact' in remark.title.lower():
                        mark_redacted = True
            # check for nested entities
            if hasattr(entity, 'entities'):
                # recursive call for nested entities
                ent_dict = self._flat_entities(entity.entities)
                entities_dict.update(ent_dict)
            # iterate through vCard array
            if hasattr(entity, 'vcardArray'):
                for vcard in entity.vcardArray[-1]:
                    # vCard represents information about an individual or entity.
                    vcard_type = vcard[0]
                    vcard_value = vcard[-1]
                    # check for organization
                    if vcard_type == RDAPVCardKeys.ORG:
                        ent_dict['org'] = vcard_value
                    # check for email
                    elif vcard_type == RDAPVCardKeys.EMAIL:
                        ent_dict['email'] = vcard_value
                    # check for name
                    elif vcard_type == RDAPVCardKeys.FN:
                        ent_dict['name'] = vcard_value
                    # check for address
                    elif vcard_type == RDAPVCardKeys.ADR:
                        values = self._flatten_list(vcard_value)
                        address_string = ', '.join([v for v in values if v])
                        ent_dict['address'] = address_string.lstrip()
                    # check for contact
                    elif vcard_type == RDAPVCardKeys.TEL:
                        # check the "type" of "tel" vcard (either voice or fax):
                        # vcard looks like: ['tel', {"type": "voice"}, 'uri', 'tel:0000000']
                        if hasattr(vcard[1], 'type'):
                            contact_type = vcard[1].to_dict().get('type')
                            if contact_type == 'voice':
                                ent_dict['phone'] = vcard_value
                            elif contact_type == 'fax':
                                ent_dict['fax'] = vcard_value
                        else:
                            ent_dict['phone'] = vcard_value
                        
            # add roles for this entity
            for role in entity.roles:
                if mark_redacted:
                    for key in ('address', 'phone', 'name', 'org', 'email', 'fax'):
                        if not ent_dict.get(key):
                            ent_dict[key] = REDACTED
                # save the information under this "role"
                entities_dict[role.lower()] = ent_dict

        # return parsed entities dict
        return entities_dict

    @staticmethod
    def _construct_flat_dict(parsed: Dict[str, Any]) -> Dict[WHOISKeys, Any]:
        converted = {
            WHOISKeys.ABUSE_EMAIL: parsed.get('abuse', {}).get('email'),
            WHOISKeys.ABUSE_PHONE: parsed.get('abuse', {}).get('phone'),
            WHOISKeys.ADMIN_NAME: parsed.get('administrative', {}).get('name'),
            WHOISKeys.ADMIN_ORG: parsed.get('administrative', {}).get('org'),
            WHOISKeys.ADMIN_EMAIL: parsed.get('administrative', {}).get('email'),
            WHOISKeys.ADMIN_ADDRESS: parsed.get('administrative', {}).get('address'),
            WHOISKeys.ADMIN_PHONE: parsed.get('administrative', {}).get('phone'),
            WHOISKeys.ADMIN_FAX: parsed.get('administrative', {}).get('fax'),
            WHOISKeys.BILLING_NAME: parsed.get('billing', {}).get('name'),
            WHOISKeys.BILLING_ORG: parsed.get('billing', {}).get('org'),
            WHOISKeys.BILLING_EMAIL: parsed.get('billing', {}).get('email'),
            WHOISKeys.BILLING_ADDRESS: parsed.get('billing', {}).get('address'),
            WHOISKeys.BILLING_PHONE: parsed.get('billing', {}).get('phone'),
            WHOISKeys.BILLING_FAX: parsed.get('billing', {}).get('fax'),
            WHOISKeys.REGISTRANT_NAME: parsed.get('registrant', {}).get('name'),
            WHOISKeys.REGISTRANT_ORG: parsed.get('registrant', {}).get('organization'),
            WHOISKeys.REGISTRANT_EMAIL: parsed.get('registrant', {}).get('email'),
            WHOISKeys.REGISTRANT_ADDRESS: parsed.get('registrant', {}).get('address'),
            WHOISKeys.REGISTRANT_PHONE: parsed.get('registrant', {}).get('phone'),
            WHOISKeys.REGISTRANT_FAX: parsed.get('registrant', {}).get('fax'),
            WHOISKeys.REGISTRAR_NAME: parsed.get('registrar', {}).get('name'),
            WHOISKeys.REGISTRAR_EMAIL: parsed.get('registrar', {}).get('email'),
            WHOISKeys.REGISTRAR_ADDRESS: parsed.get('registrar', {}).get('address'),
            WHOISKeys.REGISTRAR_PHONE: parsed.get('registrar', {}).get('phone'),
            WHOISKeys.REGISTRAR_FAX: parsed.get('registrar', {}).get('fax'),
            WHOISKeys.TECHNICAL_NAME: parsed.get('technical', {}).get('name'),
            WHOISKeys.TECHNICAL_ORG: parsed.get('technical', {}).get('org'),
            WHOISKeys.TECHNICAL_EMAIL: parsed.get('technical', {}).get('email'),
            WHOISKeys.TECHNICAL_ADDRESS: parsed.get('technical', {}).get('address'),
            WHOISKeys.TECHNICAL_PHONE: parsed.get('technical', {}).get('phone'),
            WHOISKeys.TECHNICAL_FAX: parsed.get('technical', {}).get('fax'),
            WHOISKeys.CREATED_DATE: parsed.get('registration'),
            WHOISKeys.UPDATED_DATE: parsed.get('last update') or parsed.get('last changed'),
            WHOISKeys.EXPIRES_DATE: parsed.get('expiration'),
            WHOISKeys.STATUS: parsed.get('status'),
            WHOISKeys.NAMESERVERS: parsed.get('nameservers')
        }
        return converted


class IPv4Response(RDAPResponse):

    def to_json(self, **kwargs):
        ...

    def to_dict(self, **kwargs):
        ...

    def get_geo_location(self):
        ...


class IPv6Response(RDAPResponse):

    def to_json(self, **kwargs):
        ...

    def to_dict(self, **kwargs):
        ...


class ASNResponse(RDAPResponse):

    def to_json(self, **kwargs):
        ...

    def to_dict(self, **kwargs):
        ...