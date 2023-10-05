import unittest
import json
import os
from datetime import datetime

from whodap.response import DomainResponse, WHOISKeys
from whodap.errors import RDAPConformanceException


def load_file(filename: str):
    base_dir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(base_dir, "samples", filename)) as data:
        return data.read()


class TestDomainResponse(unittest.TestCase):
    def setUp(self) -> None:
        self.address = "123 main street"
        self.phone = "tel+18005555555"
        self.test_filename = "google.com.json"
        self.json_string = load_file(self.test_filename)
        self.resp = DomainResponse.from_json(self.json_string)

    def test_to_dict(self):
        result = self.resp.to_dict()
        assert type(result) == dict, f"{type(result)} is not dict"
        self.assertEqual(result, json.loads(self.json_string))

    def test_to_json(self):
        result = self.resp.to_json(indent=2)
        assert type(result) == str, f"{type(result)} is not str"
        self.assertEqual(result, self.json_string)

    def test_to_whois_dict(self):
        whois_dict = self.resp.to_whois_dict()
        for k, v in whois_dict.items():
            assert type(k) == WHOISKeys
            if k == WHOISKeys.STATUS or k == WHOISKeys.NAMESERVERS:
                assert type(v) == list, f"{type(v)} is not list"
            if (
                k == WHOISKeys.CREATED_DATE
                or k == WHOISKeys.UPDATED_DATE
                or k == WHOISKeys.EXPIRES_DATE
            ):
                assert type(v) == datetime, f"{type(v)} is not datetime"
            if k == WHOISKeys.DNSSEC:
                assert type(v) == str, f"{type(v)} is not bool"

    def test_to_whois_dict_strict(self):
        self.test_filename = "bad_response_01.json"
        self.json_string = load_file(self.test_filename)
        self.resp = DomainResponse.from_json(self.json_string)
        self.assertRaises(
            RDAPConformanceException, self.resp.to_whois_dict, strict=True
        )
        self.test_filename = "bad_response_02.json"
        self.json_string = load_file(self.test_filename)
        self.resp = DomainResponse.from_json(self.json_string)
        self.assertRaises(RDAPConformanceException, self.resp.to_whois_dict, True)

    def test_to_whois_json(self):
        whois_dict = self.resp.to_whois_dict()
        whois_json = self.resp.to_whois_json()
        assert type(whois_json) == str
        for k, v in json.loads(whois_json).items():
            assert (
                k in whois_dict.keys()
            ), f"key {k} from whois_json is not in whois_dict"

    def test_convert_self_to_dict(self):
        json_string = (
            '{"list_key1": [{"inner_dict1": 1}, {"inner_dict2": 2}], "dict_key1": 1}'
        )
        resp = DomainResponse.from_json(json_string)
        resp_dict = resp._convert_self_to_dict(resp)
        self.assertEqual(list(resp_dict.keys()), list(json.loads(json_string).keys()))
        self.assertEqual(
            list(resp_dict.values()), list(json.loads(json_string).values())
        )

    def test_convert_list(self):
        json_string = (
            '{"list_key1": [{"inner_dict1": 1}, {"inner_dict2": 2}], "dict_key1": 1}'
        )
        resp = DomainResponse.from_json(json_string)
        resp_dict = resp._convert_self_to_dict(resp)
        self.assertEqual(list(resp_dict.keys()), list(json.loads(json_string).keys()))
        self.assertEqual(
            list(resp_dict.values()), list(json.loads(json_string).values())
        )

    def test_convert_dates(self):
        ds_1 = "2015-08-09T18:00:24.000+0000"
        ds_2 = "2020-05-14T00:00:00Z"
        ds_3 = "2021-11-17T16:00:29.0Z"
        dt_1 = self.resp._convert_date(ds_1)
        assert dt_1.year == 2015, f"year {dt_1.year} is not 2015"
        assert dt_1.month == 8, f"month {dt_1.month} is not 8"
        for ds in (ds_1, ds_2, ds_3):
            assert (
                type(self.resp._convert_date(ds)) == datetime
            ), f"failed to convert to datetime"
        ds_4 = "unsupported"
        assert (
            type(self.resp._convert_date(ds_4)) == str
        ), f"unexpected output from _convert_date"

    def test_flat_entities(self):
        flattened_entities = self.resp._flat_entities(self.resp.entities, strict=False)
        for role, role_values in flattened_entities.items():
            assert role in (
                "abuse",
                "registrant",
                "registrar",
                "technical",
                "billing",
                "administrative",
            ), f"{role} not found"
            for key, value in role_values.items():
                assert key in (
                    "org",
                    "abuse",
                    "address",
                    "phone",
                    "name",
                    "email",
                    "fax",
                ), f"role_value key {key} not found"
                assert value is not None

    def test_construct_flat_dict(self):
        flat = {
            "administrative": {
                "address": self.address,
                "phone": self.phone,
                "name": "test",
            }
        }
        flat_converted = self.resp._construct_flat_dict(flat)
        assert (
            flat_converted["admin_address"] == self.address
        ), f"{flat_converted['admin_address']} != {self.address}"
        assert (
            flat_converted["admin_phone"] == self.phone
        ), f"{flat_converted['admin_phone']} != {self.phone}"
        assert (
            flat_converted["admin_name"] == "test"
        ), f"{flat_converted['admin_name']} != test"
        for key, value in flat_converted.items():
            assert type(key) == WHOISKeys
