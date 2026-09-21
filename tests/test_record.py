#
#
#

from unittest import TestCase

from octodns.record import Record, ValidationError
from octodns.zone import Zone

from octodns_azure.record import (
    AzureAliasRecord,
    _AzureAliasValue,
    _is_tm_profile_id,
)

FRONT_DOOR_ID = (
    '/subscriptions/123456/resourceGroups/rg/providers/'
    'Microsoft.Cdn/profiles/prdglobal-redirect/afdEndpoints/wwwexamplecom'
)
PUBLIC_IP_ID = (
    '/subscriptions/123456/resourceGroups/rg/providers/'
    'Microsoft.Network/publicIPAddresses/ip'
)
TM_ID = (
    '/subscriptions/123456/resourceGroups/rg/providers/'
    'Microsoft.Network/trafficManagerProfiles/foo'
)


class TestIsTmProfileId(TestCase):
    def test_is_tm_profile_id(self):
        self.assertTrue(_is_tm_profile_id(TM_ID))
        # case-insensitive
        self.assertTrue(_is_tm_profile_id(TM_ID.upper()))
        self.assertFalse(_is_tm_profile_id(FRONT_DOOR_ID))


class TestAzureAliasValue(TestCase):
    def test_value(self):
        value = _AzureAliasValue(
            {'type': 'A', 'target-resource': FRONT_DOOR_ID}
        )
        self.assertEqual('A', value._type)
        self.assertEqual(FRONT_DOOR_ID, value.target_resource)
        self.assertEqual(
            {'type': 'A', 'target-resource': FRONT_DOOR_ID}, value.data
        )
        # data is a plain dict
        self.assertIs(dict, type(value.data))
        self.assertEqual(f'A {FRONT_DOOR_ID}', repr(value))

        # built values can be processed again, e.g. by Record.copy
        other = _AzureAliasValue.process([value])[0]
        self.assertEqual(value, other)
        self.assertEqual(value.data, other.data)

    def test_equality(self):
        a = _AzureAliasValue({'type': 'A', 'target-resource': FRONT_DOOR_ID})
        # ids are compared case-insensitively
        a_upper = _AzureAliasValue(
            {'type': 'A', 'target-resource': FRONT_DOOR_ID.upper()}
        )
        aaaa = _AzureAliasValue(
            {'type': 'AAAA', 'target-resource': FRONT_DOOR_ID}
        )
        a_ip = _AzureAliasValue({'type': 'A', 'target-resource': PUBLIC_IP_ID})

        self.assertEqual(a, a_upper)
        self.assertEqual(hash(a), hash(a_upper))
        self.assertEqual(1, len({a, a_upper}))
        # but the original casing is kept
        self.assertEqual(FRONT_DOOR_ID.upper(), a_upper.target_resource)

        self.assertNotEqual(a, aaaa)
        self.assertNotEqual(a, a_ip)
        self.assertTrue(a < aaaa)
        self.assertEqual([a, aaaa], sorted([aaaa, a]))


class TestAzureAliasRecord(TestCase):
    zone = Zone('unit.tests.', [])

    def test_registered(self):
        self.assertIs(
            AzureAliasRecord, Record.registered_types()['AzureProvider/ALIAS']
        )

    def test_record(self):
        record = Record.new(
            self.zone,
            '',
            {
                'type': 'AzureProvider/ALIAS',
                'ttl': 300,
                'values': [
                    {'type': 'AAAA', 'target-resource': FRONT_DOOR_ID},
                    {'type': 'A', 'target-resource': FRONT_DOOR_ID},
                ],
            },
        )
        self.assertIsInstance(record, AzureAliasRecord)
        self.assertEqual(300, record.ttl)
        # sorted by type
        self.assertEqual(['A', 'AAAA'], [v._type for v in record.values])
        self.assertEqual(
            {
                'ttl': 300,
                'values': [
                    {'type': 'A', 'target-resource': FRONT_DOOR_ID},
                    {'type': 'AAAA', 'target-resource': FRONT_DOOR_ID},
                ],
            },
            record.data,
        )

        # copies round-trip
        copy = record.copy()
        self.assertEqual(record.values, copy.values)
        self.assertEqual(record.data, copy.data)

        # single value
        record = Record.new(
            self.zone,
            'www',
            {
                'type': 'AzureProvider/ALIAS',
                'ttl': 60,
                'value': {'type': 'CNAME', 'target-resource': FRONT_DOOR_ID},
            },
        )
        self.assertEqual(['CNAME'], [v._type for v in record.values])
        self.assertEqual(
            {
                'ttl': 60,
                'value': {'type': 'CNAME', 'target-resource': FRONT_DOOR_ID},
            },
            record.data,
        )

    def test_changes(self):
        def alias(ttl, target):
            return Record.new(
                self.zone,
                'www',
                {
                    'type': 'AzureProvider/ALIAS',
                    'ttl': ttl,
                    'value': {'type': 'A', 'target-resource': target},
                },
            )

        a = alias(300, FRONT_DOOR_ID)
        # case of the id doesn't matter
        self.assertIsNone(a.changes(alias(300, FRONT_DOOR_ID.lower()), None))
        # target does
        self.assertTrue(a.changes(alias(300, PUBLIC_IP_ID), None))
        # as does ttl
        self.assertTrue(a.changes(alias(60, FRONT_DOOR_ID), None))

    def assertReasons(self, expected, name, values):
        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                self.zone,
                name,
                {'type': 'AzureProvider/ALIAS', 'ttl': 300, 'values': values},
            )
        self.assertEqual(expected, [r.reason for r in ctx.exception.reasons])

    def test_validation(self):
        self.assertReasons(['invalid value "nope"'], 'www', ['nope'])
        self.assertReasons(
            ['missing type'], 'www', [{'target-resource': FRONT_DOOR_ID}]
        )
        self.assertReasons(
            ['invalid type "MX"'],
            'www',
            [{'type': 'MX', 'target-resource': FRONT_DOOR_ID}],
        )
        self.assertReasons(['missing target-resource'], 'www', [{'type': 'A'}])
        self.assertReasons(
            [
                'invalid target-resource "foo", expected an Azure resource id '
                'starting with /subscriptions/'
            ],
            'www',
            [{'type': 'A', 'target-resource': 'foo'}],
        )
        self.assertReasons(
            [
                'invalid target-resource "42", expected an Azure resource id '
                'starting with /subscriptions/'
            ],
            'www',
            [{'type': 'A', 'target-resource': 42}],
        )
        self.assertReasons(
            [
                f'target-resource "{TM_ID}" is a Traffic Manager profile, use '
                'a dynamic record instead'
            ],
            'www',
            [{'type': 'A', 'target-resource': TM_ID}],
        )
        self.assertReasons(
            ['duplicate type "A"'],
            'www',
            [
                {'type': 'A', 'target-resource': FRONT_DOOR_ID},
                {'type': 'A', 'target-resource': PUBLIC_IP_ID},
            ],
        )
        self.assertReasons(
            ['CNAME cannot be combined with other types'],
            'www',
            [
                {'type': 'A', 'target-resource': FRONT_DOOR_ID},
                {'type': 'CNAME', 'target-resource': FRONT_DOOR_ID},
            ],
        )
        self.assertReasons(
            ['root CNAME not allowed'],
            '',
            [{'type': 'CNAME', 'target-resource': FRONT_DOOR_ID}],
        )
        # non-dict values are ignored by the root CNAME check, the value
        # validator takes care of them
        self.assertReasons(['invalid value "nope"'], '', ['nope'])

        # a single, non-list, value
        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                self.zone,
                '',
                {
                    'type': 'AzureProvider/ALIAS',
                    'ttl': 300,
                    'value': {
                        'type': 'CNAME',
                        'target-resource': FRONT_DOOR_ID,
                    },
                },
            )
        self.assertEqual(
            ['root CNAME not allowed'],
            [r.reason for r in ctx.exception.reasons],
        )

        # the value validator directly with a single value
        validator = _AzureAliasValue.VALIDATORS[0]
        self.assertEqual(
            [],
            validator.validate(
                _AzureAliasValue,
                {'type': 'A', 'target-resource': FRONT_DOOR_ID},
                'AzureProvider/ALIAS',
            ),
        )

        # a CNAME away from the root is fine
        record = Record.new(
            self.zone,
            'www',
            {
                'type': 'AzureProvider/ALIAS',
                'ttl': 300,
                'value': {'type': 'CNAME', 'target-resource': FRONT_DOOR_ID},
            },
        )
        self.assertEqual('CNAME', record.values[0]._type)
