#
#
#

from unittest import TestCase
from unittest.mock import Mock, call, patch

from azure.identity import AzureCliCredential
from azure.mgmt.dns.models import (
    AaaaRecord,
    ARecord,
    CaaRecord,
    CnameRecord,
    MxRecord,
    NsRecord,
    PtrRecord,
    RecordSet,
    SoaRecord,
    SrvRecord,
    SubResource,
    TxtRecord,
)
from azure.mgmt.dns.models import Zone as AzureZone
from azure.mgmt.privatedns.models import PrivateZone as AzurePrivateZone
from azure.mgmt.trafficmanager.models import (
    AlwaysServe,
    DnsConfig,
    Endpoint,
    EndpointStatus,
    MonitorConfig,
    MonitorConfigCustomHeadersItem,
    Profile,
)
from msrestazure.azure_exceptions import CloudError

from octodns.provider import SupportsException
from octodns.provider.base import Plan
from octodns.record import Create, Delete, Record, Update
from octodns.zone import Zone

from octodns_azure import (
    AzureException,
    AzurePrivateProvider,
    AzureProvider,
    _AzureRecord,
    _check_endswith_dot,
    _format_azure_subnets,
    _get_monitor,
    _parse_azure_type,
    _profile_is_match,
    _root_traffic_manager_name,
)

zone_public = Zone(name='unit.tests.', sub_zones=[])
octo_records = []
octo_records.append(
    Record.new(
        zone_public,
        '',
        {'ttl': 0, 'type': 'A', 'values': ['1.2.3.4', '10.10.10.10']},
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'a',
        {'ttl': 1, 'type': 'A', 'values': ['1.2.3.4', '1.1.1.1']},
    )
)
octo_records.append(
    Record.new(
        zone_public, 'aa', {'ttl': 9001, 'type': 'A', 'values': ['1.2.4.3']}
    )
)
octo_records.append(
    Record.new(
        zone_public, 'aaa', {'ttl': 2, 'type': 'A', 'values': ['1.1.1.3']}
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'aaaa1',
        {
            'ttl': 300,
            'type': 'AAAA',
            'values': [
                '2601:644:500:e210:62f8:1dff:feb8:947a',
                '2601:642:500:e210:62f8:1dff:feb8:947a',
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'aaaa2',
        {
            'ttl': 300,
            'type': 'AAAA',
            'value': '2601:644:500:e210:62f8:1dff:feb8:947a',
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'caa1',
        {
            'ttl': 9,
            'type': 'CAA',
            'value': {'flags': 0, 'tag': 'issue', 'value': 'ca.unit.tests'},
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'caa2',
        {
            'ttl': 9,
            'type': 'CAA',
            'values': [
                {'flags': 0, 'tag': 'issue', 'value': 'ca1.unit.tests'},
                {'flags': 0, 'tag': 'issue', 'value': 'ca2.unit.tests'},
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'cname',
        {'ttl': 3, 'type': 'CNAME', 'value': 'a.unit.tests.'},
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'mx1',
        {
            'ttl': 3,
            'type': 'MX',
            'values': [
                {'priority': 10, 'value': 'mx1.unit.tests.'},
                {'priority': 20, 'value': 'mx2.unit.tests.'},
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'mx2',
        {
            'ttl': 3,
            'type': 'MX',
            'values': [{'priority': 10, 'value': 'mx1.unit.tests.'}],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        '',
        {
            'ttl': 4,
            'type': 'NS',
            'values': ['ns1.unit.tests.', 'ns2.unit.tests.'],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public, 'foo', {'ttl': 5, 'type': 'NS', 'value': 'ns1.unit.tests.'}
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'ptr1',
        {'ttl': 5, 'type': 'PTR', 'value': 'ptr1.unit.tests.'},
    )
)
octo_records.append(
    Record.new(
        zone_public,
        '_srv._tcp',
        {
            'ttl': 6,
            'type': 'SRV',
            'values': [
                {
                    'priority': 10,
                    'weight': 20,
                    'port': 30,
                    'target': 'foo-1.unit.tests.',
                },
                {
                    'priority': 12,
                    'weight': 30,
                    'port': 30,
                    'target': 'foo-2.unit.tests.',
                },
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        '_srv2._tcp',
        {
            'ttl': 7,
            'type': 'SRV',
            'values': [
                {
                    'priority': 12,
                    'weight': 17,
                    'port': 1,
                    'target': 'srvfoo.unit.tests.',
                }
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'txt1',
        {'ttl': 8, 'type': 'TXT', 'value': 'txt singleton test'},
    )
)
octo_records.append(
    Record.new(
        zone_public,
        'txt2',
        {
            'ttl': 9,
            'type': 'TXT',
            'values': ['txt multiple test', 'txt multiple test 2'],
        },
    )
)

long_txt = "v=spf1 ip4:10.10.0.0/24 ip4:10.10.1.0/24 ip4:10.10.2.0/24"
long_txt += " ip4:10.10.3.0/24 ip4:10.10.4.0/24 ip4:10.10.5.0/24 "
long_txt += " 10.6.0/24 ip4:10.10.7.0/24 ip4:10.10.8.0/24 "
long_txt += " ip4:10.10.10.0/24 ip4:10.10.11.0/24 ip4:10.10.12.0/24"
long_txt += " ip4:10.10.13.0/24 ip4:10.10.14.0/24 ip4:10.10.15.0/24"
long_txt += " ip4:10.10.16.0/24 ip4:10.10.17.0/24 ip4:10.10.18.0/24"
long_txt += " ip4:10.10.19.0/24 ip4:10.10.20.0/24  ~all"
octo_records.append(
    Record.new(
        zone_public,
        'txt3',
        {'ttl': 10, 'type': 'TXT', 'values': ['txt multiple test', long_txt]},
    )
)

octo_records.append(
    Record.new(
        zone_public,
        'ptr2',
        {
            'ttl': 11,
            'type': 'PTR',
            'values': ['ptr21.unit.tests.', 'ptr22.unit.tests.'],
        },
    )
)

zone_private = Zone(name='unit.tests.', sub_zones=[])
octo_records = []
octo_records.append(
    Record.new(
        zone_private,
        '',
        {'ttl': 0, 'type': 'A', 'values': ['1.2.3.4', '10.10.10.10']},
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'a',
        {'ttl': 1, 'type': 'A', 'values': ['1.2.3.4', '1.1.1.1']},
    )
)
octo_records.append(
    Record.new(
        zone_private, 'aa', {'ttl': 9001, 'type': 'A', 'values': ['1.2.4.3']}
    )
)
octo_records.append(
    Record.new(
        zone_private, 'aaa', {'ttl': 2, 'type': 'A', 'values': ['1.1.1.3']}
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'aaaa1',
        {
            'ttl': 300,
            'type': 'AAAA',
            'values': [
                '2601:644:500:e210:62f8:1dff:feb8:947a',
                '2601:642:500:e210:62f8:1dff:feb8:947a',
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'aaaa2',
        {
            'ttl': 300,
            'type': 'AAAA',
            'value': '2601:644:500:e210:62f8:1dff:feb8:947a',
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'caa1',
        {
            'ttl': 9,
            'type': 'CAA',
            'value': {'flags': 0, 'tag': 'issue', 'value': 'ca.unit.tests'},
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'caa2',
        {
            'ttl': 9,
            'type': 'CAA',
            'values': [
                {'flags': 0, 'tag': 'issue', 'value': 'ca1.unit.tests'},
                {'flags': 0, 'tag': 'issue', 'value': 'ca2.unit.tests'},
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'cname',
        {'ttl': 3, 'type': 'CNAME', 'value': 'a.unit.tests.'},
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'mx1',
        {
            'ttl': 3,
            'type': 'MX',
            'values': [
                {'priority': 10, 'value': 'mx1.unit.tests.'},
                {'priority': 20, 'value': 'mx2.unit.tests.'},
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'mx2',
        {
            'ttl': 3,
            'type': 'MX',
            'values': [{'priority': 10, 'value': 'mx1.unit.tests.'}],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        '',
        {
            'ttl': 4,
            'type': 'NS',
            'values': ['ns1.unit.tests.', 'ns2.unit.tests.'],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'foo',
        {'ttl': 5, 'type': 'NS', 'value': 'ns1.unit.tests.'},
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'ptr1',
        {'ttl': 5, 'type': 'PTR', 'value': 'ptr1.unit.tests.'},
    )
)
octo_records.append(
    Record.new(
        zone_private,
        '_srv._tcp',
        {
            'ttl': 6,
            'type': 'SRV',
            'values': [
                {
                    'priority': 10,
                    'weight': 20,
                    'port': 30,
                    'target': 'foo-1.unit.tests.',
                },
                {
                    'priority': 12,
                    'weight': 30,
                    'port': 30,
                    'target': 'foo-2.unit.tests.',
                },
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        '_srv2._tcp',
        {
            'ttl': 7,
            'type': 'SRV',
            'values': [
                {
                    'priority': 12,
                    'weight': 17,
                    'port': 1,
                    'target': 'srvfoo.unit.tests.',
                }
            ],
        },
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'txt1',
        {'ttl': 8, 'type': 'TXT', 'value': 'txt singleton test'},
    )
)
octo_records.append(
    Record.new(
        zone_private,
        'txt2',
        {
            'ttl': 9,
            'type': 'TXT',
            'values': ['txt multiple test', 'txt multiple test 2'],
        },
    )
)

long_txt = "v=spf1 ip4:10.10.0.0/24 ip4:10.10.1.0/24 ip4:10.10.2.0/24"
long_txt += " ip4:10.10.3.0/24 ip4:10.10.4.0/24 ip4:10.10.5.0/24 "
long_txt += " 10.6.0/24 ip4:10.10.7.0/24 ip4:10.10.8.0/24 "
long_txt += " ip4:10.10.10.0/24 ip4:10.10.11.0/24 ip4:10.10.12.0/24"
long_txt += " ip4:10.10.13.0/24 ip4:10.10.14.0/24 ip4:10.10.15.0/24"
long_txt += " ip4:10.10.16.0/24 ip4:10.10.17.0/24 ip4:10.10.18.0/24"
long_txt += " ip4:10.10.19.0/24 ip4:10.10.20.0/24  ~all"
octo_records.append(
    Record.new(
        zone_private,
        'txt3',
        {'ttl': 10, 'type': 'TXT', 'values': ['txt multiple test', long_txt]},
    )
)

octo_records.append(
    Record.new(
        zone_private,
        'ptr2',
        {
            'ttl': 11,
            'type': 'PTR',
            'values': ['ptr21.unit.tests.', 'ptr22.unit.tests.'],
        },
    )
)

azure_records = []
_base0 = _AzureRecord('TestAzure', octo_records[0])
_base0.zone_name = 'unit.tests'
_base0.relative_record_set_name = '@'
_base0.record_type = 'A'
_base0.params['ttl'] = 0
_base0.params['a_records'] = [
    ARecord(ipv4_address='1.2.3.4'),
    ARecord(ipv4_address='10.10.10.10'),
]
azure_records.append(_base0)

_base1 = _AzureRecord('TestAzure', octo_records[1])
_base1.zone_name = 'unit.tests'
_base1.relative_record_set_name = 'a'
_base1.record_type = 'A'
_base1.params['ttl'] = 1
_base1.params['a_records'] = [
    ARecord(ipv4_address='1.2.3.4'),
    ARecord(ipv4_address='1.1.1.1'),
]
azure_records.append(_base1)

_base2 = _AzureRecord('TestAzure', octo_records[2])
_base2.zone_name = 'unit.tests'
_base2.relative_record_set_name = 'aa'
_base2.record_type = 'A'
_base2.params['ttl'] = 9001
_base2.params['a_records'] = ARecord(ipv4_address='1.2.4.3')
azure_records.append(_base2)

_base3 = _AzureRecord('TestAzure', octo_records[3])
_base3.zone_name = 'unit.tests'
_base3.relative_record_set_name = 'aaa'
_base3.record_type = 'A'
_base3.params['ttl'] = 2
_base3.params['a_records'] = ARecord(ipv4_address='1.1.1.3')
azure_records.append(_base3)

_base4 = _AzureRecord('TestAzure', octo_records[4])
_base4.zone_name = 'unit.tests'
_base4.relative_record_set_name = 'aaaa1'
_base4.record_type = 'AAAA'
_base4.params['ttl'] = 300
aaaa1 = AaaaRecord(ipv6_address='2601:644:500:e210:62f8:1dff:feb8:947a')
aaaa2 = AaaaRecord(ipv6_address='2601:642:500:e210:62f8:1dff:feb8:947a')
_base4.params['aaaa_records'] = [aaaa1, aaaa2]
azure_records.append(_base4)

_base5 = _AzureRecord('TestAzure', octo_records[5])
_base5.zone_name = 'unit.tests'
_base5.relative_record_set_name = 'aaaa2'
_base5.record_type = 'AAAA'
_base5.params['ttl'] = 300
_base5.params['aaaa_records'] = [aaaa1]
azure_records.append(_base5)

_base6 = _AzureRecord('TestAzure', octo_records[6])
_base6.zone_name = 'unit.tests'
_base6.relative_record_set_name = 'caa1'
_base6.record_type = 'CAA'
_base6.params['ttl'] = 9
_base6.params['caa_records'] = [
    CaaRecord(flags=0, tag='issue', value='ca.unit.tests')
]
azure_records.append(_base6)

_base7 = _AzureRecord('TestAzure', octo_records[7])
_base7.zone_name = 'unit.tests'
_base7.relative_record_set_name = 'caa2'
_base7.record_type = 'CAA'
_base7.params['ttl'] = 9
_base7.params['caa_records'] = [
    CaaRecord(flags=0, tag='issue', value='ca1.unit.tests'),
    CaaRecord(flags=0, tag='issue', value='ca2.unit.tests'),
]
azure_records.append(_base7)

_base8 = _AzureRecord('TestAzure', octo_records[8])
_base8.zone_name = 'unit.tests'
_base8.relative_record_set_name = 'cname'
_base8.record_type = 'CNAME'
_base8.params['ttl'] = 3
_base8.params['cname_record'] = CnameRecord(cname='a.unit.tests.')
azure_records.append(_base8)

_base9 = _AzureRecord('TestAzure', octo_records[9])
_base9.zone_name = 'unit.tests'
_base9.relative_record_set_name = 'mx1'
_base9.record_type = 'MX'
_base9.params['ttl'] = 3
_base9.params['mx_records'] = [
    MxRecord(preference=10, exchange='mx1.unit.tests.'),
    MxRecord(preference=20, exchange='mx2.unit.tests.'),
]
azure_records.append(_base9)

_base10 = _AzureRecord('TestAzure', octo_records[10])
_base10.zone_name = 'unit.tests'
_base10.relative_record_set_name = 'mx2'
_base10.record_type = 'MX'
_base10.params['ttl'] = 3
_base10.params['mx_records'] = [
    MxRecord(preference=10, exchange='mx1.unit.tests.')
]
azure_records.append(_base10)

_base11 = _AzureRecord('TestAzure', octo_records[11])
_base11.zone_name = 'unit.tests'
_base11.relative_record_set_name = '@'
_base11.record_type = 'NS'
_base11.params['ttl'] = 4
_base11.params['ns_records'] = [
    NsRecord(nsdname='ns1.unit.tests.'),
    NsRecord(nsdname='ns2.unit.tests.'),
]
azure_records.append(_base11)

_base12 = _AzureRecord('TestAzure', octo_records[12])
_base12.zone_name = 'unit.tests'
_base12.relative_record_set_name = 'foo'
_base12.record_type = 'NS'
_base12.params['ttl'] = 5
_base12.params['ns_records'] = [NsRecord(nsdname='ns1.unit.tests.')]
azure_records.append(_base12)

_base13 = _AzureRecord('TestAzure', octo_records[13])
_base13.zone_name = 'unit.tests'
_base13.relative_record_set_name = 'ptr1'
_base13.record_type = 'PTR'
_base13.params['ttl'] = 5
_base13.params['ptr_records'] = [PtrRecord(ptrdname='ptr1.unit.tests.')]
azure_records.append(_base13)

_base14 = _AzureRecord('TestAzure', octo_records[14])
_base14.zone_name = 'unit.tests'
_base14.relative_record_set_name = '_srv._tcp'
_base14.record_type = 'SRV'
_base14.params['ttl'] = 6
_base14.params['srv_records'] = [
    SrvRecord(priority=10, weight=20, port=30, target='foo-1.unit.tests.'),
    SrvRecord(priority=12, weight=30, port=30, target='foo-2.unit.tests.'),
]
azure_records.append(_base14)

_base15 = _AzureRecord('TestAzure', octo_records[15])
_base15.zone_name = 'unit.tests'
_base15.relative_record_set_name = '_srv2._tcp'
_base15.record_type = 'SRV'
_base15.params['ttl'] = 7
_base15.params['srv_records'] = [
    SrvRecord(priority=12, weight=17, port=1, target='srvfoo.unit.tests.')
]
azure_records.append(_base15)

_base16 = _AzureRecord('TestAzure', octo_records[16])
_base16.zone_name = 'unit.tests'
_base16.relative_record_set_name = 'txt1'
_base16.record_type = 'TXT'
_base16.params['ttl'] = 8
_base16.params['txt_records'] = [TxtRecord(value=['txt singleton test'])]
azure_records.append(_base16)

_base17 = _AzureRecord('TestAzure', octo_records[17])
_base17.zone_name = 'unit.tests'
_base17.relative_record_set_name = 'txt2'
_base17.record_type = 'TXT'
_base17.params['ttl'] = 9
_base17.params['txt_records'] = [
    TxtRecord(value=['txt multiple test']),
    TxtRecord(value=['txt multiple test 2']),
]
azure_records.append(_base17)

long_txt_az1 = "v=spf1 ip4:10.10.0.0/24 ip4:10.10.1.0/24 ip4:10.10.2.0/24"
long_txt_az1 += " ip4:10.10.3.0/24 ip4:10.10.4.0/24 ip4:10.10.5.0/24 "
long_txt_az1 += " 10.6.0/24 ip4:10.10.7.0/24 ip4:10.10.8.0/24 "
long_txt_az1 += " ip4:10.10.10.0/24 ip4:10.10.11.0/24 ip4:10.10.12.0/24"
long_txt_az1 += " ip4:10.10.13.0/24 ip4:10.10.14.0/24 ip4:10.10."
long_txt_az2 = "15.0/24 ip4:10.10.16.0/24 ip4:10.10.17.0/24 ip4:10.10.18.0/24"
long_txt_az2 += " ip4:10.10.19.0/24 ip4:10.10.20.0/24  ~all"
_base18 = _AzureRecord('TestAzure', octo_records[18])
_base18.zone_name = 'unit.tests'
_base18.relative_record_set_name = 'txt3'
_base18.record_type = 'TXT'
_base18.params['ttl'] = 10
_base18.params['txt_records'] = [
    TxtRecord(value=['txt multiple test']),
    TxtRecord(value=[long_txt_az1, long_txt_az2]),
]
azure_records.append(_base18)

_base19 = _AzureRecord('TestAzure', octo_records[19])
_base19.zone_name = 'unit.tests'
_base19.relative_record_set_name = 'ptr2'
_base19.record_type = 'PTR'
_base19.params['ttl'] = 11
_base19.params['ptr_records'] = [
    PtrRecord(ptrdname='ptr21.unit.tests.'),
    PtrRecord(ptrdname='ptr22.unit.tests.'),
]
azure_records.append(_base19)


class Test_AzureRecord(TestCase):
    def test_azure_record(self):
        assert len(azure_records) == len(octo_records)
        for i in range(len(azure_records)):
            octo = _AzureRecord('TestAzure', octo_records[i])
            assert azure_records[i]._equals(octo)


class Test_DynamicAzureRecord(TestCase):
    def test_azure_record(self):
        tm_profile = Profile()
        data = {
            'ttl': 60,
            'type': 'CNAME',
            'value': 'default.unit.tests.',
            'dynamic': {
                'pools': {
                    'one': {
                        'values': [{'value': 'one.unit.tests.', 'weight': 1}],
                        'fallback': 'two',
                    },
                    'two': {
                        'values': [{'value': 'two.unit.tests.', 'weight': 1}]
                    },
                },
                'rules': [{'geos': ['AF'], 'pool': 'one'}, {'pool': 'two'}],
            },
        }
        octo_record = Record.new(zone_public, 'foo', data)
        azure_record = _AzureRecord(
            'TestAzure', octo_record, traffic_manager=tm_profile
        )
        self.assertEqual(azure_record.zone_name, zone_public.name[:-1])
        self.assertEqual(azure_record.relative_record_set_name, 'foo')
        self.assertEqual(azure_record.record_type, 'CNAME')
        self.assertEqual(azure_record.params['ttl'], 60)
        self.assertEqual(azure_record.params['target_resource'], tm_profile)


class Test_ParseAzureType(TestCase):
    def test_parse_azure_type(self):
        for expected, test in [
            ['A', 'Microsoft.Network/dnszones/A'],
            ['AAAA', 'Microsoft.Network/dnszones/AAAA'],
            ['NS', 'Microsoft.Network/dnszones/NS'],
            ['MX', 'Microsoft.Network/dnszones/MX'],
        ]:
            self.assertEqual(expected, _parse_azure_type(test))


class Test_CheckEndswithDot(TestCase):
    def test_check_endswith_dot(self):
        for expected, test in [
            ['a.', 'a'],
            ['a.', 'a.'],
            ['foo.bar.', 'foo.bar.'],
            ['foo.bar.', 'foo.bar'],
        ]:
            self.assertEqual(expected, _check_endswith_dot(test))


class Test_RootTrafficManagerName(TestCase):
    def test_root_traffic_manager_name(self):
        test = Record.new(
            zone_public,
            'foo',
            data={'ttl': 60, 'type': 'CNAME', 'value': 'default.unit.tests.'},
        )
        self.assertEqual(_root_traffic_manager_name(test), 'foo--unit--tests')


class Test_GetMonitor(TestCase):
    def test_get_monitor(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'octodns': {
                    'healthcheck': {
                        'path': '/_ping',
                        'port': 4443,
                        'protocol': 'HTTPS',
                    }
                },
            },
        )

        monitor = _get_monitor(record)
        self.assertEqual(monitor.protocol, 'HTTPS')
        self.assertEqual(monitor.port, 4443)
        self.assertEqual(monitor.path, '/_ping')
        headers = monitor.custom_headers
        self.assertIsInstance(headers, list)
        self.assertEqual(len(headers), 1)
        headers = headers[0]
        self.assertEqual(headers.name, 'Host')
        self.assertEqual(headers.value, record.healthcheck_host())

        # test TCP monitor
        record.octodns['healthcheck']['protocol'] = 'TCP'
        monitor = _get_monitor(record)
        self.assertEqual(monitor.protocol, 'TCP')
        self.assertIsNone(monitor.custom_headers)


class Test_ProfileIsMatch(TestCase):
    def test_profile_is_match(self):
        is_match = _profile_is_match

        self.assertFalse(is_match(None, Profile()))

        # Profile object builder with default property values that can be
        # overridden for testing below
        def profile(
            name='foo-unit-tests',
            ttl=60,
            method='Geographic',
            dns_name=None,
            monitor_proto='HTTPS',
            monitor_port=4443,
            monitor_path='/_ping',
            monitor_interval=30,
            monitor_timeout=10,
            monitor_num_failures=3,
            endpoints=1,
            endpoint_name='name',
            endpoint_type='profile/nestedEndpoints',
            endpoint_status=None,
            always_serve=None,
            target='target.unit.tests',
            target_id='resource/id',
            geos=['GEO-AF'],
            subnets=['1.1.1.1'],
            weight=1,
            priority=1,
        ):
            dns = DnsConfig(relative_name=(dns_name or name), ttl=ttl)
            return Profile(
                name=name,
                traffic_routing_method=method,
                dns_config=dns,
                monitor_config=MonitorConfig(
                    protocol=monitor_proto,
                    port=monitor_port,
                    path=monitor_path,
                    interval_in_seconds=monitor_interval,
                    timeout_in_seconds=monitor_timeout,
                    tolerated_number_of_failures=monitor_num_failures,
                ),
                endpoints=[
                    Endpoint(
                        name=endpoint_name,
                        type=endpoint_type,
                        endpoint_status=endpoint_status,
                        always_serve=always_serve,
                        target=target,
                        target_resource_id=target_id,
                        geo_mapping=geos,
                        subnets=_format_azure_subnets(subnets),
                        weight=weight,
                        priority=priority,
                    )
                ]
                + [Endpoint()] * (endpoints - 1),
            )

        self.assertTrue(is_match(profile(), profile()))

        self.assertFalse(is_match(profile(), profile(name='two')))
        self.assertFalse(is_match(profile(), profile(endpoints=2)))
        self.assertFalse(is_match(profile(), profile(dns_name='two')))
        self.assertFalse(is_match(profile(), profile(monitor_proto='HTTP')))
        self.assertFalse(is_match(profile(), profile(monitor_interval=9)))
        self.assertFalse(is_match(profile(), profile(monitor_timeout=3)))
        self.assertFalse(is_match(profile(), profile(monitor_num_failures=2)))
        self.assertFalse(is_match(profile(), profile(endpoint_name='a')))
        self.assertFalse(is_match(profile(), profile(endpoint_type='b')))
        self.assertFalse(
            is_match(
                profile(), profile(endpoint_status=EndpointStatus.DISABLED)
            )
        )
        # compare always_serve if endpoint is enabled
        self.assertFalse(
            is_match(
                profile(
                    endpoint_status=EndpointStatus.ENABLED,
                    always_serve=AlwaysServe.ENABLED,
                ),
                profile(
                    endpoint_status=EndpointStatus.ENABLED,
                    always_serve=AlwaysServe.DISABLED,
                ),
            )
        )
        # always_serve shouldn't matter if endpoint is disabled
        self.assertTrue(
            is_match(
                profile(
                    endpoint_status=EndpointStatus.DISABLED,
                    always_serve=AlwaysServe.ENABLED,
                ),
                profile(
                    endpoint_status=EndpointStatus.DISABLED,
                    always_serve=AlwaysServe.DISABLED,
                ),
            )
        )
        self.assertFalse(
            is_match(profile(endpoint_type='b'), profile(endpoint_type='b'))
        )
        self.assertFalse(is_match(profile(), profile(target_id='rsrc/id2')))
        self.assertFalse(is_match(profile(), profile(geos=['IN'])))
        self.assertFalse(
            is_match(
                profile(endpoint_type='profile/externalEndpoints'),
                profile(endpoint_type='profile/externalEndpoints', geos=['IN']),
            )
        )
        self.assertFalse(
            is_match(
                profile(method='Subnet'),
                profile(method='Subnet', subnets=['2.2.2.2']),
            )
        )
        self.assertFalse(
            is_match(
                profile(method='Priority'),
                profile(method='Priority', priority=2),
            )
        )

        def wprofile(**kwargs):
            kwargs['method'] = 'Weighted'
            kwargs['endpoint_type'] = 'profile/externalEndpoints'
            return profile(**kwargs)

        self.assertFalse(is_match(wprofile(), wprofile(target='bar.unit')))
        self.assertFalse(is_match(wprofile(), wprofile(weight=3)))


class TestAzureDnsProvider(TestCase):
    @patch('octodns_azure.TrafficManagerManagementClient')
    @patch('octodns_azure.DnsManagementClient')
    @patch('octodns_azure.ClientSecretCredential')
    def _get_provider(self, mock_css, mock_client, mock_tm_client):
        '''Returns a mock AzureProvider object to use in testing.

        :param mock_spc: placeholder
        :type  mock_spc: str
        :param mock_client: placeholder
        :type  mock_client: str
        :param mock_tm_client: placeholder
        :type  mock_tm_client: str

        :type return: AzureProvider
        '''
        provider = AzureProvider(
            'mock_id',
            'mock_sub',
            'mock_rg',
            directory_id='mock_directory',
            client_id='mock_client',
            key='mock_key',
            client_status_retries=4,
            client_total_retries=42,
            strict_supports=False,
        )

        # Fetch the client to force it to load the creds
        provider.dns_client

        # set critical functions to return properly
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = []
        tm_sync = provider._tm_client.profiles.create_or_update

        def side_effect(rg, name, profile):
            return Profile(
                id=profile.id,
                name=profile.name,
                traffic_routing_method=profile.traffic_routing_method,
                dns_config=profile.dns_config,
                monitor_config=profile.monitor_config,
                endpoints=profile.endpoints,
            )

        tm_sync.side_effect = side_effect

        return provider

    def _get_dynamic_record(self, zone):
        return Record.new(
            zone,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {'value': 'one.unit.tests.', 'weight': 1}
                            ],
                            'fallback': 'two',
                        },
                        'two': {
                            'values': [
                                {'value': 'two1.unit.tests.', 'weight': 3},
                                {'value': 'two2.unit.tests.', 'weight': 4},
                            ],
                            'fallback': 'three',
                        },
                        'three': {
                            'values': [
                                {'value': 'three.unit.tests.', 'weight': 1}
                            ]
                        },
                    },
                    'rules': [
                        {
                            'geos': ['AF', 'EU-DE', 'NA-US-CA', 'OC'],
                            'pool': 'one',
                        },
                        {'pool': 'two'},
                    ],
                },
                'octodns': {
                    'healthcheck': {
                        'path': '/_ping',
                        'port': 4443,
                        'protocol': 'HTTPS',
                    }
                },
            },
        )

    def _get_tm_profiles(self, provider):
        sub = provider._client_subscription_id
        rg = provider._resource_group
        base_id = (
            '/subscriptions/'
            + sub
            + '/resourceGroups/'
            + rg
            + '/providers/Microsoft.Network/trafficManagerProfiles/'
        )
        prefix = 'foo--unit--tests'
        name_format = prefix + '-'
        id_format = base_id + name_format

        header = MonitorConfigCustomHeadersItem(
            name='Host', value='foo.unit.tests'
        )
        monitor = MonitorConfig(
            protocol='HTTPS',
            port=4443,
            path='/_ping',
            tolerated_number_of_failures=3,
            interval_in_seconds=30,
            timeout_in_seconds=10,
            custom_headers=[header],
        )
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'

        profiles = [
            Profile(
                id=f'{id_format}pool-two',
                name=f'{name_format}pool-two',
                traffic_routing_method='Weighted',
                dns_config=DnsConfig(ttl=60),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two--two1.unit.tests',
                        type=external,
                        target='two1.unit.tests',
                        weight=3,
                    ),
                    Endpoint(
                        name='two--two2.unit.tests',
                        type=external,
                        target='two2.unit.tests',
                        weight=4,
                    ),
                ],
            ),
            Profile(
                id=f'{id_format}rule-one',
                name=f'{name_format}rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(ttl=60),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=external,
                        target='one.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=f'{id_format}pool-two',
                        priority=2,
                    ),
                    Endpoint(
                        name='three',
                        type=external,
                        target='three.unit.tests',
                        priority=3,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='default.unit.tests',
                        priority=4,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                id=f'{id_format}rule-two',
                name=f'{name_format}rule-two',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(ttl=60),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=f'{id_format}pool-two',
                        priority=1,
                    ),
                    Endpoint(
                        name='three',
                        type=external,
                        target='three.unit.tests',
                        priority=2,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='default.unit.tests',
                        priority=3,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                id=base_id + prefix,
                name=prefix,
                traffic_routing_method='Geographic',
                dns_config=DnsConfig(ttl=60),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        geo_mapping=['GEO-AF', 'DE', 'US-CA', 'GEO-AP'],
                        name='one',
                        type=nested,
                        target_resource_id=f'{id_format}rule-one',
                    ),
                    Endpoint(
                        geo_mapping=['WORLD'],
                        name='two',
                        type=nested,
                        target_resource_id=f'{id_format}rule-two',
                    ),
                ],
            ),
        ]

        for profile in profiles:
            profile.dns_config.relative_name = profile.name

        return profiles

    def _get_dynamic_package(self):
        '''Convenience function to setup a sample dynamic record.'''
        provider = self._get_provider()

        # setup traffic manager profiles
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = self._get_tm_profiles(provider)

        # setup zone with dynamic record
        zone = Zone(name='unit.tests.', sub_zones=[])
        record = self._get_dynamic_record(zone)
        zone.add_record(record)

        # return everything
        return provider, zone, record

    def test_populate_records(self):
        provider = self._get_provider()

        rs = []
        recordSet = RecordSet(a_records=[ARecord(ipv4_address='1.1.1.1')])
        recordSet.name, recordSet.ttl, recordSet.type = 'a1', 0, 'A'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            a_records=[
                ARecord(ipv4_address='1.1.1.1'),
                ARecord(ipv4_address='2.2.2.2'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'a2', 1, 'A'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        aaaa1 = AaaaRecord(ipv6_address='1:1ec:1::1')
        recordSet = RecordSet(aaaa_records=[aaaa1])
        recordSet.name, recordSet.ttl, recordSet.type = 'aaaa1', 2, 'AAAA'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        aaaa2 = AaaaRecord(ipv6_address='1:1ec:1::2')
        recordSet = RecordSet(aaaa_records=[aaaa1, aaaa2])
        recordSet.name, recordSet.ttl, recordSet.type = 'aaaa2', 3, 'AAAA'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            caa_records=[
                CaaRecord(flags=0, tag='issue', value='caa1.unit.tests')
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'caa1', 4, 'CAA'
        rs.append(recordSet)
        recordSet = RecordSet(
            caa_records=[
                CaaRecord(flags=0, tag='issue', value='caa1.unit.tests'),
                CaaRecord(flags=0, tag='issue', value='caa2.unit.tests'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'caa2', 4, 'CAA'
        rs.append(recordSet)
        cname1 = CnameRecord(cname='cname.unit.test.')
        recordSet = RecordSet(cname_record=cname1)
        recordSet.name, recordSet.ttl, recordSet.type = 'cname1', 5, 'CNAME'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            mx_records=[MxRecord(preference=10, exchange='mx1.unit.test.')]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'mx1', 7, 'MX'
        rs.append(recordSet)
        recordSet = RecordSet(
            mx_records=[
                MxRecord(preference=10, exchange='mx1.unit.test.'),
                MxRecord(preference=11, exchange='mx2.unit.test.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'mx2', 8, 'MX'
        rs.append(recordSet)
        recordSet = RecordSet(ns_records=[NsRecord(nsdname='ns1.unit.test.')])
        recordSet.name, recordSet.ttl, recordSet.type = 'ns1', 9, 'NS'
        rs.append(recordSet)
        recordSet = RecordSet(
            ns_records=[
                NsRecord(nsdname='ns1.unit.test.'),
                NsRecord(nsdname='ns2.unit.test.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'ns2', 10, 'NS'
        rs.append(recordSet)
        ptr1 = PtrRecord(ptrdname='ptr1.unit.test.')
        recordSet = RecordSet(ptr_records=[ptr1])
        recordSet.name, recordSet.ttl, recordSet.type = 'ptr1', 11, 'PTR'
        rs.append(recordSet)
        recordSet = RecordSet(
            srv_records=[
                SrvRecord(priority=1, weight=2, port=3, target='1unit.tests.')
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = '_srv1._tcp', 13, 'SRV'
        rs.append(recordSet)
        recordSet = RecordSet(
            srv_records=[
                SrvRecord(priority=1, weight=2, port=3, target='1unit.tests.'),
                SrvRecord(priority=4, weight=5, port=6, target='2unit.tests.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = '_srv2._tcp', 14, 'SRV'
        rs.append(recordSet)
        recordSet = RecordSet(txt_records=[TxtRecord(value='sample text1')])
        recordSet.name, recordSet.ttl, recordSet.type = 'txt1', 15, 'TXT'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            txt_records=[
                TxtRecord(value='sample text1'),
                TxtRecord(value='sample text2'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'txt2', 16, 'TXT'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(soa_record=[SoaRecord()])
        recordSet.name, recordSet.ttl, recordSet.type = '', 17, 'SOA'
        rs.append(recordSet)
        long_txt = "v=spf1 ip4:10.10.0.0/24 ip4:10.10.1.0/24 ip4:10.10.2.0/24"
        long_txt += " ip4:10.10.3.0/24 ip4:10.10.4.0/24 ip4:10.10.5.0/24 "
        long_txt += " 10.6.0/24 ip4:10.10.7.0/24 ip4:10.10.8.0/24 "
        long_txt += " ip4:10.10.10.0/24 ip4:10.10.11.0/24 ip4:10.10.12.0/24"
        long_txt += " ip4:10.10.13.0/24 ip4:10.10.14.0/24 ip4:10.10.15.0/24"
        long_txt += " ip4:10.10.16.0/24 ip4:10.10.17.0/24 ip4:10.10.18.0/24"
        long_txt += " ip4:10.10.19.0/24 ip4:10.10.20.0/24  ~all"
        recordSet = RecordSet(
            txt_records=[
                TxtRecord(value='sample value1'),
                TxtRecord(value=long_txt),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'txt3', 18, 'TXT'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)

        record_list = provider.dns_client.record_sets.list_by_dns_zone
        record_list.return_value = rs

        zone_list = provider.dns_client.zones.list_by_resource_group
        zone_list.return_value = [zone_public]

        exists = provider.populate(zone_public)

        self.assertEqual(len(zone_public.records), 17)
        self.assertTrue(exists)

    def test_azure_zones(self):
        provider = self._get_provider()

        zone_list = provider.dns_client.zones.list_by_resource_group
        zone_1 = AzureZone(location='global')
        # This is far from ideal but the
        # zone constructor doesn't let me set it on creation
        zone_1.name = "zone-1"
        zone_2 = AzureZone(location='global')
        # This is far from ideal but the
        # zone constructor doesn't let me set it on creation
        zone_2.name = "zone-2"
        zone_list.return_value = [zone_1, zone_2, zone_1]

        zones = provider._azure_zones
        self.assertTrue(zone_1.name in zones)
        self.assertTrue(zone_2.name in zones)

        # This should be returning two zones since two zones are the same
        self.assertEqual(len(provider._azure_zones), 2)

    def test_list_zones(self):
        provider = self._get_provider()

        zone_list = provider.dns_client.zones.list_by_resource_group
        zone_1 = AzureZone(location='global')
        # This is far from ideal but the
        # zone constructor doesn't let me set it on creation
        zone_1.name = "other.thing"
        zone_2 = AzureZone(location='global')
        # This is far from ideal but the
        # zone constructor doesn't let me set it on creation
        zone_2.name = "alpha.com"
        zone_list.return_value = [zone_1, zone_2, zone_1]

        self.assertEqual(
            [f'{zone_2.name}.', f'{zone_1.name}.'], provider.list_zones()
        )

    def test_bad_zone_response(self):
        provider = self._get_provider()

        _get = provider.dns_client.zones.get
        _get.side_effect = CloudError(Mock(status=404), 'Azure Error')
        self.assertEqual(provider._check_zone('unit.test', create=False), None)

    def test_extra_changes(self):
        provider, existing, record = self._get_dynamic_package()

        # test simple records produce no extra changes
        desired = Zone(name=existing.name, sub_zones=[])
        simple = Record.new(
            desired,
            'simple',
            data={
                'type': record._type,
                'ttl': record.ttl,
                'value': record.value,
            },
        )
        desired.add_record(simple)
        extra = provider._extra_changes(desired, desired, [Create(simple)])
        self.assertEqual(len(extra), 0)

        # test an unchanged dynamic record produces no extra changes
        desired.add_record(record)
        extra = provider._extra_changes(existing, desired, [])
        self.assertEqual(len(extra), 0)

        # test unused TM produces the extra change for clean up
        sample_profile = self._get_tm_profiles(provider)[0]
        tm_id = provider._profile_name_to_id
        root_profile_name = _root_traffic_manager_name(record)
        extra_profile = Profile(
            id=tm_id(f'{root_profile_name}-pool-random'),
            name=f'{root_profile_name}-pool-random',
            traffic_routing_method='Weighted',
            dns_config=sample_profile.dns_config,
            monitor_config=sample_profile.monitor_config,
            endpoints=sample_profile.endpoints,
        )
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value.append(extra_profile)
        provider._populate_traffic_managers()
        extra = provider._extra_changes(existing, desired, [])
        self.assertEqual(len(extra), 1)
        extra = extra[0]
        self.assertIsInstance(extra, Update)
        self.assertEqual(extra.new, record)
        desired.remove_record(record)
        tm_list.return_value.pop()

        # test new dynamic record does not produce an extra change for it
        new_dynamic = Record.new(
            desired,
            record.name + '2',
            data={
                'type': record._type,
                'ttl': record.ttl,
                'value': record.value,
                'dynamic': record.dynamic._data(),
                'octodns': record.octodns,
            },
        )
        # test change in healthcheck by using a different port number
        update_dynamic = Record.new(
            desired,
            record.name,
            data={
                'type': record._type,
                'ttl': record.ttl,
                'value': record.value,
                'dynamic': record.dynamic._data(),
                'octodns': {
                    'healthcheck': {
                        'path': '/_ping',
                        'port': 443,
                        'protocol': 'HTTPS',
                    }
                },
            },
        )
        desired.add_record(new_dynamic)
        desired.add_record(update_dynamic)
        changes = [Create(new_dynamic)]
        extra = provider._extra_changes(existing, desired, changes)
        # implicitly asserts that new_dynamic was not added to extra changes
        # as it was already in the `changes` list
        self.assertEqual(len(extra), 1)
        extra = extra[0]
        self.assertIsInstance(extra, Update)
        self.assertEqual(extra.new, update_dynamic)

        # test dynamic record of unsupported type throws exception
        unsupported_dynamic = Record.new(
            desired,
            record.name + '3',
            data={
                'type': 'DNAME',
                'ttl': record.ttl,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': 'one.unit.tests.'}]}
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )
        desired.add_record(unsupported_dynamic)
        changes = [Create(unsupported_dynamic)]
        with self.assertRaises(AzureException) as ctx:
            provider._extra_changes(existing, desired, changes)
        self.assertTrue(
            str(ctx.exception).endswith('must be of type A/AAAA/CNAME')
        )
        desired.remove_record(unsupported_dynamic)

        # test colliding ATM names throws exception
        record1 = Record.new(
            desired,
            'sub.www',
            data={
                'type': record._type,
                'ttl': record.ttl,
                'value': record.value,
                'dynamic': record.dynamic._data(),
            },
        )
        record2 = Record.new(
            desired,
            'sub--www',
            data={
                'type': record._type,
                'ttl': record.ttl,
                'value': record.value,
                'dynamic': record.dynamic._data(),
            },
        )
        desired.add_record(record1)
        desired.add_record(record2)
        changes = [Create(record1), Create(record2)]
        with self.assertRaises(AzureException) as ctx:
            provider._extra_changes(existing, desired, changes)
        self.assertTrue(
            str(ctx.exception).startswith('Collision in Traffic Manager')
        )

    @patch('octodns_azure.AzureProvider._generate_traffic_managers')
    def test_extra_changes_non_last_fallback_contains_default(self, mock_gtm):
        provider = self._get_provider()

        desired = Zone(zone_public.name, sub_zones=[])
        record = Record.new(
            desired,
            'foo',
            {
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [{'value': 'one.unit.tests.'}],
                            'fallback': 'def',
                        },
                        'def': {
                            'values': [{'value': 'default.unit.tests.'}],
                            'fallback': 'two',
                        },
                        'two': {'values': [{'value': 'two.unit.tests.'}]},
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )
        desired.add_record(record)
        changes = [Create(record)]

        # assert that no exception is raised
        provider._extra_changes(zone_public, desired, changes)

        # simulate duplicate endpoint and assert exception
        endpoint = Endpoint(target='dup.unit.tests.')
        mock_gtm.return_value = [
            Profile(name='test-profile', endpoints=[endpoint, endpoint])
        ]
        with self.assertRaises(AzureException) as ctx:
            provider._extra_changes(zone_public, desired, changes)
        self.assertTrue('duplicate endpoint' in str(ctx.exception))

    def test_extra_changes_A_multi_defaults(self):
        provider = self._get_provider()

        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'A',
                'ttl': 60,
                'values': ['1.1.1.1', '8.8.8.8'],
                'dynamic': {
                    'pools': {'one': {'values': [{'value': '1.1.1.1'}]}},
                    'rules': [{'pool': 'one'}],
                },
            },
        )

        # test that extra changes doesn't show any changes
        desired = Zone(zone_public.name, sub_zones=[])
        desired.add_record(record)
        with self.assertRaises(AzureException) as ctx:
            provider._extra_changes(zone_public, desired, [])
        self.assertTrue('multiple top-level values' in str(ctx.exception))

    def test_generate_tm_profile(self):
        provider, zone, record = self._get_dynamic_package()
        profile_gen = provider._generate_tm_profile

        label = 'foobar'
        routing = 'Priority'
        endpoints = [
            Endpoint(target='one.unit.tests'),
            Endpoint(target_resource_id='/s/1/rg/foo/tm/foobar2'),
            Endpoint(name='invalid'),
        ]

        # invalid endpoint raises exception
        with self.assertRaises(AzureException):
            profile_gen(routing, endpoints, record, label)

        # regular test
        endpoints.pop()
        profile = profile_gen(routing, endpoints, record, label)

        # implicitly tests _profile_name_to_id
        sub = provider._client_subscription_id
        rg = provider._resource_group
        expected_name = 'foo--unit--tests-rule-foobar'
        expected_id = (
            '/subscriptions/'
            + sub
            + '/resourceGroups/'
            + rg
            + '/providers/Microsoft.Network/trafficManagerProfiles/'
            + expected_name
        )
        self.assertEqual(profile.id, expected_id)
        self.assertEqual(profile.name, expected_name)
        self.assertEqual(profile.name, profile.dns_config.relative_name)
        self.assertEqual(profile.traffic_routing_method, routing)
        self.assertEqual(profile.dns_config.ttl, record.ttl)
        self.assertEqual(len(profile.endpoints), len(endpoints))

        self.assertEqual(
            profile.endpoints[0].type,
            'Microsoft.Network/trafficManagerProfiles/externalEndpoints',
        )
        self.assertEqual(
            profile.endpoints[1].type,
            'Microsoft.Network/trafficManagerProfiles/nestedEndpoints',
        )

    def _validate_dynamic(self, record, expected_profiles):
        '''
        Takes a dynamic record as a test case and its corresponding expected profiles
        Tests that:
          1. expected profiles are generated from the given record
          2. the profiles correctly populate the same record back
          3. no extra changes are required

        This convenience method should be used to test various dynamic record test cases
        '''
        provider = self._get_provider()

        # test that traffic managers profiles are generated as expected
        profiles = provider._generate_traffic_managers(record)
        self.assertEqual(len(expected_profiles), len(profiles))
        profiles_to_compare = zip(profiles, expected_profiles)
        for have, expected in profiles_to_compare:
            self.assertTrue(_profile_is_match(have, expected))

        # check that dynamic record is populated back from profiles
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = profiles
        azrecord = RecordSet(
            ttl=60, target_resource=SubResource(id=profiles[-1].id)
        )
        azrecord.name = record.name or '@'
        azrecord.type = f'Microsoft.Network/dnszones/{record._type}'
        record2 = provider._populate_record(zone_public, azrecord, lenient=True)
        self.assertEqual(record2.dynamic._data(), record.dynamic._data())

        # test that extra changes doesn't show any changes
        desired = Zone(zone_public.name, sub_zones=[])
        desired.add_record(record)
        changes = provider._extra_changes(zone_public, desired, [])
        self.assertEqual(len(changes), 0)

    def test_dynamic_record(self):
        provider, _, record = self._get_dynamic_package()
        expected_profiles = self._get_tm_profiles(provider)
        self._validate_dynamic(record, expected_profiles)

    def test_generate_traffic_managers_middle_east(self):
        # check Asia/Middle East test case
        provider, _, record = self._get_dynamic_package()
        record.dynamic._data()['rules'][0]['geos'].append('AS')
        record.dynamic._data()['rules'][0]['geos'].sort()
        expected_profiles = self._get_tm_profiles(provider)
        expected_profiles[-1].endpoints[0].geo_mapping.extend(
            ['GEO-ME', 'GEO-AS']
        )
        self._validate_dynamic(record, expected_profiles)

    def test_populate_dynamic_middle_east(self):
        # Middle east without Asia raises exception
        provider, zone, record = self._get_dynamic_package()
        tm_suffix = _root_traffic_manager_name(record)
        tm_id = provider._profile_name_to_id
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = [
            Profile(
                id=tm_id(tm_suffix),
                name=tm_suffix,
                traffic_routing_method='Geographic',
                endpoints=[Endpoint(geo_mapping=['GEO-ME'])],
            )
        ]
        azrecord = RecordSet(
            ttl=60, target_resource=SubResource(id=tm_id(tm_suffix))
        )
        azrecord.name = record.name or '@'
        azrecord.type = f'Microsoft.Network/dnszones/{record._type}'
        with self.assertRaises(AzureException) as ctx:
            provider._populate_record(zone, azrecord)
        self.assertTrue(
            'Middle East (GEO-ME) is not supported' in str(ctx.exception)
        )

        # valid profiles with Middle East test case
        provider, zone, record = self._get_dynamic_package()
        geo_profile = provider._get_tm_for_dynamic_record(record)
        geo_profile.endpoints[0].geo_mapping.extend(['GEO-ME', 'GEO-AS'])
        record = provider._populate_record(zone, azrecord)
        self.assertIn('AS', record.dynamic.rules[0].data['geos'])
        self.assertNotIn('ME', record.dynamic.rules[0].data['geos'])

    def test_dynamic_no_geo(self):
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'

        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': 'one.unit.tests.'}]}
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )

        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='one',
                            type=external,
                            target='one.unit.tests',
                            priority=1,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=2,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                )
            ],
        )

    def test_dynamic_fallback_is_default(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'def': {'values': [{'value': 'default.unit.tests.'}]}
                    },
                    'rules': [{'geos': ['AF'], 'pool': 'def'}],
                },
            },
            lenient=True,
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        monitor = _get_monitor(record)
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-def',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-def', ttl=60
                    ),
                    monitor_config=monitor,
                    endpoints=[
                        Endpoint(
                            name='def--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                        )
                    ],
                ),
                Profile(
                    name='foo--unit--tests-rule-def',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-rule-def', ttl=60
                    ),
                    monitor_config=monitor,
                    endpoints=[
                        Endpoint(
                            name='def',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-def'
                            ),
                            priority=1,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=2,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Geographic',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=monitor,
                    endpoints=[
                        Endpoint(
                            name='def',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-rule-def'
                            ),
                            geo_mapping=['GEO-AF'],
                        )
                    ],
                ),
            ],
        )

    def test_dynamic_pool_contains_default(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'rr': {
                            'values': [
                                {'value': 'one.unit.tests.'},
                                {'value': 'two.unit.tests.'},
                                {'value': 'default.unit.tests.'},
                                {'value': 'final.unit.tests.'},
                            ]
                        }
                    },
                    'rules': [{'geos': ['AF'], 'pool': 'rr'}],
                },
            },
            lenient=True,
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-rr',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-rr', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr--one.unit.tests',
                            type=external,
                            target='one.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--two.unit.tests',
                            type=external,
                            target='two.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--final.unit.tests',
                            type=external,
                            target='final.unit.tests',
                            weight=1,
                        ),
                    ],
                ),
                Profile(
                    name='foo--unit--tests-rule-rr',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-rule-rr', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-rr'
                            ),
                            priority=1,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=2,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Geographic',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-rule-rr'
                            ),
                            geo_mapping=['GEO-AF'],
                        )
                    ],
                ),
            ],
        )

    def test_dynamic_pool_contains_default_no_geo(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'rr': {
                            'values': [
                                {'value': 'one.unit.tests.'},
                                {'value': 'two.unit.tests.'},
                                {'value': 'default.unit.tests.'},
                                {'value': 'final.unit.tests.'},
                            ]
                        }
                    },
                    'rules': [{'pool': 'rr'}],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-rr',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-rr', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr--one.unit.tests',
                            type=external,
                            target='one.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--two.unit.tests',
                            type=external,
                            target='two.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--final.unit.tests',
                            type=external,
                            target='final.unit.tests',
                            weight=1,
                        ),
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-rr'
                            ),
                            priority=1,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=2,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
            ],
        )

    def test_dynamic_last_pool_contains_default_no_geo(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'cloud': {
                            'values': [{'value': 'cloud.unit.tests.'}],
                            'fallback': 'rr',
                        },
                        'rr': {
                            'values': [
                                {'value': 'one.unit.tests.'},
                                {'value': 'two.unit.tests.'},
                                {'value': 'default.unit.tests.'},
                                {'value': 'final.unit.tests.'},
                            ]
                        },
                    },
                    'rules': [{'pool': 'cloud'}],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-rr',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-rr', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr--one.unit.tests',
                            type=external,
                            target='one.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--two.unit.tests',
                            type=external,
                            target='two.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--final.unit.tests',
                            type=external,
                            target='final.unit.tests',
                            weight=1,
                        ),
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='cloud',
                            type=external,
                            target='cloud.unit.tests',
                            priority=1,
                        ),
                        Endpoint(
                            name='rr',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-rr'
                            ),
                            priority=2,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=3,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
            ],
        )

    def test_dynamic_last_pool_equals_default_down(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {
                                    'value': 'default.unit.tests.',
                                    'status': 'down',
                                }
                            ]
                        }
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-one',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-one', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='one--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                            endpoint_status=EndpointStatus.DISABLED,
                        )
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='one',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-one'
                            ),
                            priority=1,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=2,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
            ],
        )

    def test_dynamic_intermediate_pool_contains_default_no_geo(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'cloud': {
                            'values': [{'value': 'cloud.unit.tests.'}],
                            'fallback': 'rr',
                        },
                        'rr': {
                            'values': [
                                {'value': 'one.unit.tests.'},
                                {'value': 'two.unit.tests.'},
                                {
                                    'value': 'default.unit.tests.',
                                    'status': 'down',
                                },
                                {'value': 'final.unit.tests.'},
                            ],
                            'fallback': 'dc',
                        },
                        'dc': {'values': [{'value': 'dc.unit.tests.'}]},
                    },
                    'rules': [{'pool': 'cloud'}],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-rr',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-rr', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='rr--one.unit.tests',
                            type=external,
                            target='one.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--two.unit.tests',
                            type=external,
                            target='two.unit.tests',
                            weight=1,
                        ),
                        Endpoint(
                            name='rr--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                            endpoint_status=EndpointStatus.DISABLED,
                        ),
                        Endpoint(
                            name='rr--final.unit.tests',
                            type=external,
                            target='final.unit.tests',
                            weight=1,
                        ),
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='cloud',
                            type=external,
                            target='cloud.unit.tests',
                            priority=1,
                        ),
                        Endpoint(
                            name='rr',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-rr'
                            ),
                            priority=2,
                        ),
                        Endpoint(
                            name='dc',
                            type=external,
                            target='dc.unit.tests',
                            priority=3,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=4,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
            ],
        )

    def test_dynamic_intermediate_pool_equals_default_no_geo(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [{'value': 'one.unit.tests.'}],
                            'fallback': 'two',
                        },
                        'two': {
                            'values': [{'value': 'default.unit.tests.'}],
                            'fallback': 'three',
                        },
                        'three': {'values': [{'value': 'three.unit.tests.'}]},
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-pool-two',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-pool-two', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='two--default.unit.tests',
                            type=external,
                            target='default.unit.tests',
                            weight=1,
                        )
                    ],
                ),
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=60
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='one',
                            type=external,
                            target='one.unit.tests',
                            priority=1,
                        ),
                        Endpoint(
                            name='two',
                            type=nested,
                            target_resource_id=name_to_id(
                                'foo--unit--tests-pool-two'
                            ),
                            priority=2,
                        ),
                        Endpoint(
                            name='three',
                            type=external,
                            target='three.unit.tests',
                            priority=3,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='default.unit.tests',
                            priority=4,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                ),
            ],
        )

    def test_dynamic_unique_traffic_managers(self):
        record = self._get_dynamic_record(zone_public)
        data = {
            'type': record._type,
            'ttl': record.ttl,
            'value': record.value,
            'dynamic': record.dynamic._data(),
        }
        record_names = ['www.foo', 'www-foo']
        provider = self._get_provider()

        seen = set()
        for name in record_names:
            record = Record.new(zone_public, name, data=data)
            tms = provider._generate_traffic_managers(record)
            for tm in tms:
                self.assertNotIn(tm.name, seen)
                seen.add(tm.name)

    def test_dynamic_reused_pool(self):
        # test that traffic managers are generated as expected
        provider = self._get_provider()
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'

        record = Record.new(
            zone_public,
            'foo',
            data={
                'octodns': {'lenient': True},
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'sto': {
                            'values': [{'value': 'sto.unit.tests.'}],
                            'fallback': 'iad',
                        },
                        'iad': {
                            'values': [{'value': 'iad.unit.tests.'}],
                            'fallback': 'lhr',
                        },
                        'lhr': {'values': [{'value': 'lhr.unit.tests.'}]},
                    },
                    'rules': [
                        {'geos': ['EU'], 'pool': 'iad'},
                        {'geos': ['EU-GB'], 'pool': 'lhr'},
                        {'geos': ['EU-SE'], 'pool': 'sto'},
                        {'pool': 'lhr'},
                    ],
                },
            },
        )
        profiles = provider._generate_traffic_managers(record)

        self.assertEqual(len(profiles), 4)
        self.assertTrue(
            _profile_is_match(
                profiles[-1],
                Profile(
                    name='foo--unit--tests',
                    traffic_routing_method='Geographic',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests', ttl=record.ttl
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='iad',
                            type=nested,
                            target_resource_id=profiles[0].id,
                            geo_mapping=['GEO-EU'],
                        ),
                        Endpoint(
                            name='lhr',
                            type=nested,
                            target_resource_id=profiles[1].id,
                            geo_mapping=['GB', 'WORLD'],
                        ),
                        Endpoint(
                            name='sto',
                            type=nested,
                            target_resource_id=profiles[2].id,
                            geo_mapping=['SE'],
                        ),
                    ],
                ),
            )
        )

        # test that same record gets populated back from traffic managers
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = profiles
        azrecord = RecordSet(
            ttl=60, target_resource=SubResource(id=profiles[-1].id)
        )
        azrecord.name = record.name or '@'
        azrecord.type = f'Microsoft.Network/dnszones/{record._type}'
        record2 = provider._populate_record(zone_public, azrecord, lenient=True)
        self.assertEqual(record2.dynamic._data(), record.dynamic._data())

        # test that extra changes doesn't show any changes
        desired = Zone(zone_public.name, sub_zones=[])
        desired.add_record(record)
        changes = provider._extra_changes(zone_public, desired, [])
        self.assertEqual(len(changes), 0)

    def test_dynamic_pool_status(self):
        provider = self._get_provider()
        zone1 = Zone('unit.tests.', [])
        record = Record.new(
            zone1,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {'value': 'one1.unit.tests.', 'status': 'up'}
                            ]
                        },
                        'two': {
                            'values': [
                                {'value': 'two1.unit.tests.', 'status': 'down'},
                                {'value': 'two2.unit.tests.'},
                            ]
                        },
                    },
                    'rules': [{'geos': ['AS'], 'pool': 'one'}, {'pool': 'two'}],
                },
            },
        )

        # statuses are correctly converted to traffic manager profiles and back
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = provider._profile_name_to_id
        monitor = _get_monitor(record)
        profiles = [
            Profile(
                name='foo--unit--tests-rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-one', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=external,
                        target='one1.unit.tests',
                        priority=1,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='default.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-pool-two',
                traffic_routing_method='Weighted',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-pool-two', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two--two1.unit.tests',
                        type=external,
                        target='two1.unit.tests',
                        weight=1,
                        endpoint_status=EndpointStatus.DISABLED,
                    ),
                    Endpoint(
                        name='two--two2.unit.tests',
                        type=external,
                        target='two2.unit.tests',
                        weight=1,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-rule-two',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-two', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-pool-two'
                        ),
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='default.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests',
                traffic_routing_method='Geographic',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        geo_mapping=['GEO-AS', 'GEO-ME'],
                    ),
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-two'
                        ),
                        geo_mapping=['WORLD'],
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

        # _process_desired_zone shouldn't change anything when status value is
        # supported
        zone1 = Zone(zone_public.name, sub_zones=[])
        record.dynamic.pools['one'].data['values'][0]['status'] = 'down'
        zone1.add_record(record)
        zone2 = provider._process_desired_zone(zone1.copy())
        record2 = list(zone2.records)[0]
        self.assertTrue(record.data, record2.data)

    def test_protocol_process_desired_zone(self):
        zone1 = Zone(zone_public.name, sub_zones=[])
        record1 = Record.new(
            zone1,
            'foo',
            data={
                'octodns': {'healthcheck': {'protocol': 'ICMP'}},
                'type': 'A',
                'ttl': 42,
                'value': '1.2.3.4',
            },
            lenient=True,
        )
        zone1.add_record(record1)
        with self.assertRaises(SupportsException) as ctx:
            self._get_provider()._process_desired_zone(zone1.copy())
        self.assertEqual(
            'mock_id: healthcheck protocol "ICMP" not supported',
            str(ctx.exception),
        )

    def test_simple_process_desired_zone(self):
        # simple records should not get changed by _process_desired_zone
        zone1 = Zone(zone_public.name, sub_zones=[])
        record1 = Record.new(
            zone1,
            'foo',
            data={'type': 'CNAME', 'ttl': 86400, 'value': 'one.unit.tests.'},
        )
        zone1.add_record(record1)
        zone2 = self._get_provider()._process_desired_zone(zone1.copy())
        record2 = list(zone2.records)[0]
        self.assertTrue(record1.data, record2.data)

    def test_dynamic_A(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'A',
                'ttl': 60,
                'values': ['9.9.9.9'],
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {'value': '11.11.11.11'},
                                {'value': '12.12.12.12'},
                            ],
                            'fallback': 'two',
                        },
                        'two': {'values': [{'value': '2.2.2.2'}]},
                    },
                    'rules': [{'geos': ['AF'], 'pool': 'one'}, {'pool': 'two'}],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        profiles = [
            Profile(
                name='foo--unit--tests-A-pool-one',
                traffic_routing_method='Weighted',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-a-pool-one', ttl=record.ttl
                ),
                monitor_config=_get_monitor(record),
                endpoints=[
                    Endpoint(
                        name='one--11.11.11.11',
                        type=external,
                        target='11.11.11.11',
                        weight=1,
                    ),
                    Endpoint(
                        name='one--12.12.12.12',
                        type=external,
                        target='12.12.12.12',
                        weight=1,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-A-rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-a-rule-one', ttl=record.ttl
                ),
                monitor_config=_get_monitor(record),
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-A-pool-one'
                        ),
                        priority=1,
                    ),
                    Endpoint(
                        name='two', type=external, target='2.2.2.2', priority=2
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='9.9.9.9',
                        priority=3,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-A-rule-two',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-a-rule-two', ttl=record.ttl
                ),
                monitor_config=_get_monitor(record),
                endpoints=[
                    Endpoint(
                        name='two', type=external, target='2.2.2.2', priority=1
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='9.9.9.9',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-A',
                traffic_routing_method='Geographic',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-a', ttl=record.ttl
                ),
                monitor_config=_get_monitor(record),
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-A-rule-one'
                        ),
                        geo_mapping=['GEO-AF'],
                    ),
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-A-rule-two'
                        ),
                        geo_mapping=['WORLD'],
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

        provider = self._get_provider()

        # test that the record and ATM profile gets created
        tm_sync = provider._tm_client.profiles.create_or_update
        create = provider.dns_client.record_sets.create_or_update
        provider._apply_Create(Create(record))
        # sync is called once for each profile, plus 1 at the end for nested
        # endpoints to workaround A/AAAA nesting limitation in Azure
        self.assertEqual(tm_sync.call_count, len(profiles) + 1)
        create.assert_called_once()

        # test broken alias
        azrecord = RecordSet(ttl=60, target_resource=SubResource(id=None))
        azrecord.name = record.name or '@'
        azrecord.type = f'Microsoft.Network/dnszones/{record._type}'
        record2 = provider._populate_record(zone_public, azrecord, lenient=True)
        self.assertEqual(record2.values, [])

    def test_dynamic_AAAA(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'AAAA',
                'ttl': 60,
                'values': ['f::f'],
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [{'value': '1::1'}, {'value': '2::2'}]
                        }
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        monitor = _get_monitor(record)
        profiles = [
            Profile(
                name='foo--unit--tests-AAAA-pool-one',
                traffic_routing_method='Weighted',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-aaaa-pool-one',
                    ttl=record.ttl,
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one--1--1', type=external, target='1::1', weight=1
                    ),
                    Endpoint(
                        name='one--2--2', type=external, target='2::2', weight=1
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-AAAA',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-aaaa', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-AAAA-pool-one'
                        ),
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='f::f',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

        provider = self._get_provider()

        # test that the record and ATM profile gets created
        tm_sync = provider._tm_client.profiles.create_or_update
        create = provider.dns_client.record_sets.create_or_update
        provider._apply_Create(Create(record))
        # sync is called once for each profile, plus 1 at the end for nested
        # endpoints to workaround A/AAAA nesting limitation in Azure
        self.assertEqual(tm_sync.call_count, len(profiles) + 1)
        create.assert_called_once()

        # test broken alias
        azrecord = RecordSet(ttl=60, target_resource=SubResource(id=None))
        azrecord.name = record.name or '@'
        azrecord.type = f'Microsoft.Network/dnszones/{record._type}'
        record2 = provider._populate_record(zone_public, azrecord, lenient=True)
        self.assertEqual(record2.values, [])

    def test_always_serve_disabled(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'AAAA',
                'ttl': 60,
                'values': ['f::f'],
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': '1::1', 'status': 'down'}]}
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-AAAA',
                    traffic_routing_method='Priority',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-aaaa', ttl=record.ttl
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='one',
                            type=external,
                            target='1::1',
                            priority=1,
                            endpoint_status=EndpointStatus.DISABLED,
                            always_serve=AlwaysServe.DISABLED,
                        ),
                        Endpoint(
                            name='--default--',
                            type=external,
                            target='f::f',
                            priority=2,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                )
            ],
        )

    def test_always_serve_enabled(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'AAAA',
                'ttl': 60,
                'values': ['1::1'],
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': '1::1', 'status': 'up'}]}
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        self._validate_dynamic(
            record,
            [
                Profile(
                    name='foo--unit--tests-AAAA',
                    traffic_routing_method='Geographic',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-aaaa', ttl=record.ttl
                    ),
                    monitor_config=_get_monitor(record),
                    endpoints=[
                        Endpoint(
                            name='one--default--',
                            type=external,
                            target='1::1',
                            weight=1,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                            geo_mapping=['WORLD'],
                        )
                    ],
                )
            ],
        )

    def test_dynamic_subnets_and_geos_combined(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'def.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': 'one.unit.tests.'}]},
                        'def': {
                            'values': [
                                {'value': 'def.unit.tests.', 'status': 'up'}
                            ]
                        },
                    },
                    'rules': [
                        {
                            'subnets': ['10.1.0.0/16'],
                            'geos': ['AF'],
                            'pool': 'one',
                        },
                        {'pool': 'def'},
                    ],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        monitor = _get_monitor(record)
        profiles = [
            Profile(
                name='foo--unit--tests-rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-one', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=external,
                        target='one.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-geo',
                traffic_routing_method='Geographic',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-geo', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        geo_mapping=['GEO-AF'],
                    ),
                    Endpoint(
                        name='def--default--',
                        type=external,
                        target='def.unit.tests',
                        geo_mapping=['WORLD'],
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests',
                traffic_routing_method='Subnet',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        subnets=_format_azure_subnets(['10.1.0.0/16']),
                    ),
                    Endpoint(
                        name='--geo--',
                        type=nested,
                        target_resource_id=name_to_id('foo--unit--tests-geo'),
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

    def test_dynamic_subnets_and_geos_separate(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'def.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': 'one.unit.tests.'}]},
                        'two': {'values': [{'value': 'two.unit.tests.'}]},
                        'def': {
                            'values': [
                                {'value': 'def.unit.tests.', 'status': 'up'}
                            ]
                        },
                    },
                    'rules': [
                        {'subnets': ['10.1.0.0/16'], 'pool': 'one'},
                        {'geos': ['AF'], 'pool': 'two'},
                        {'pool': 'def'},
                    ],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        monitor = _get_monitor(record)
        profiles = [
            Profile(
                name='foo--unit--tests-rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-one', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=external,
                        target='one.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-rule-two',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-two', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two',
                        type=external,
                        target='two.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-geo',
                traffic_routing_method='Geographic',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-geo', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-two'
                        ),
                        geo_mapping=['GEO-AF'],
                    ),
                    Endpoint(
                        name='def--default--',
                        type=external,
                        target='def.unit.tests',
                        geo_mapping=['WORLD'],
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests',
                traffic_routing_method='Subnet',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        subnets=_format_azure_subnets(['10.1.0.0/16']),
                    ),
                    Endpoint(
                        name='--geo--',
                        type=nested,
                        target_resource_id=name_to_id('foo--unit--tests-geo'),
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

    def test_dynamic_all_profiles(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'def.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': 'one.unit.tests.'}]},
                        'two': {'values': [{'value': 'two.unit.tests.'}]},
                        'glb': {
                            'values': [
                                {'value': 'glb1.unit.tests.'},
                                {'value': 'glb2.unit.tests.'},
                            ]
                        },
                    },
                    'rules': [
                        {
                            'subnets': ['10.1.0.0/16'],
                            'geos': ['EU'],
                            'pool': 'one',
                        },
                        {'geos': ['AF'], 'pool': 'two'},
                        {'pool': 'glb'},
                    ],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        monitor = _get_monitor(record)
        profiles = [
            Profile(
                name='foo--unit--tests-rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-one', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=external,
                        target='one.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-rule-two',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-two', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='two',
                        type=external,
                        target='two.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-pool-glb',
                traffic_routing_method='Weighted',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-pool-glb', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='glb--glb1.unit.tests',
                        type=external,
                        target='glb1.unit.tests',
                        weight=1,
                    ),
                    Endpoint(
                        name='glb--glb2.unit.tests',
                        type=external,
                        target='glb2.unit.tests',
                        weight=1,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-rule-glb',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-glb', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='glb',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-pool-glb'
                        ),
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests-geo',
                traffic_routing_method='Geographic',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-geo', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        geo_mapping=['GEO-EU'],
                    ),
                    Endpoint(
                        name='two',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-two'
                        ),
                        geo_mapping=['GEO-AF'],
                    ),
                    Endpoint(
                        name='glb',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-glb'
                        ),
                        geo_mapping=['WORLD'],
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests',
                traffic_routing_method='Subnet',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        subnets=_format_azure_subnets(['10.1.0.0/16']),
                    ),
                    Endpoint(
                        name='--geo--',
                        type=nested,
                        target_resource_id=name_to_id('foo--unit--tests-geo'),
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

    def test_dynamic_subnets_only(self):
        record = Record.new(
            zone_public,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'def.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {'values': [{'value': 'one.unit.tests.'}]},
                        'def': {
                            'values': [
                                {'value': 'def.unit.tests.', 'status': 'up'}
                            ]
                        },
                    },
                    'rules': [
                        {'subnets': ['10.1.0.0/16'], 'pool': 'one'},
                        {'pool': 'def'},
                    ],
                },
            },
        )

        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        nested = 'Microsoft.Network/trafficManagerProfiles/nestedEndpoints'
        name_to_id = self._get_provider()._profile_name_to_id
        monitor = _get_monitor(record)
        profiles = [
            Profile(
                name='foo--unit--tests-rule-one',
                traffic_routing_method='Priority',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests-rule-one', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=external,
                        target='one.unit.tests',
                        priority=1,
                    ),
                    Endpoint(
                        name='--default--',
                        type=external,
                        target='def.unit.tests',
                        priority=2,
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
            Profile(
                name='foo--unit--tests',
                traffic_routing_method='Subnet',
                dns_config=DnsConfig(
                    relative_name='foo--unit--tests', ttl=record.ttl
                ),
                monitor_config=monitor,
                endpoints=[
                    Endpoint(
                        name='one',
                        type=nested,
                        target_resource_id=name_to_id(
                            'foo--unit--tests-rule-one'
                        ),
                        subnets=_format_azure_subnets(['10.1.0.0/16']),
                    ),
                    Endpoint(
                        name='def--default--',
                        type=external,
                        target='def.unit.tests',
                        endpoint_status=EndpointStatus.ENABLED,
                        always_serve=AlwaysServe.ENABLED,
                    ),
                ],
            ),
        ]
        self._validate_dynamic(record, profiles)

    def test_sync_traffic_managers(self):
        provider, zone, record = self._get_dynamic_package()
        provider._populate_traffic_managers()

        tm_sync = provider._tm_client.profiles.create_or_update

        prefix = 'foo--unit--tests'
        expected_seen = {
            prefix,
            f'{prefix}-pool-two',
            f'{prefix}-rule-one',
            f'{prefix}-rule-two',
        }

        # test no change
        profiles = provider._generate_traffic_managers(record)
        seen = provider._sync_traffic_managers(profiles)
        self.assertEqual(seen, expected_seen)
        tm_sync.assert_not_called()

        # test that changing weight causes update API call
        dynamic = record.dynamic._data()
        dynamic['pools']['two']['values'][0]['weight'] = 14
        data = {
            'type': 'CNAME',
            'ttl': record.ttl,
            'value': record.value,
            'dynamic': dynamic,
            'octodns': record.octodns,
        }
        new_record = Record.new(zone, record.name, data)
        tm_sync.reset_mock()
        profiles = provider._generate_traffic_managers(new_record)
        seen2 = provider._sync_traffic_managers(profiles)
        self.assertEqual(seen2, expected_seen)
        tm_sync.assert_called_once()

        # test that new profile was successfully inserted in cache
        new_profile = provider._get_tm_profile_by_name(f'{prefix}-pool-two')
        self.assertEqual(new_profile.endpoints[0].weight, 14)

    def test_sync_traffic_managers_duplicate(self):
        provider, zone, record = self._get_dynamic_package()
        tm_sync = provider._tm_client.profiles.create_or_update

        # change and duplicate profiles
        profile = self._get_tm_profiles(provider)[0]
        profile.name = 'changing_this_to_trigger_sync'
        provider._sync_traffic_managers([profile, profile])

        # it should only be called once for duplicate profiles
        tm_sync.assert_called_once()

    def test_find_traffic_managers(self):
        provider, zone, record = self._get_dynamic_package()

        # insert a non-matching profile
        sample_profile = self._get_tm_profiles(provider)[0]
        # dummy record for generating suffix
        record2 = Record.new(
            zone,
            record.name + '2',
            data={
                'type': record._type,
                'ttl': record.ttl,
                'value': record.value,
            },
        )
        prefix2 = _root_traffic_manager_name(record2)
        tm_id = provider._profile_name_to_id
        extra_profile = Profile(
            id=tm_id(f'{prefix2}-pool-random'),
            name=f'{prefix2}-pool-random',
            traffic_routing_method='Weighted',
            dns_config=sample_profile.dns_config,
            monitor_config=sample_profile.monitor_config,
            endpoints=sample_profile.endpoints,
        )
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value.append(extra_profile)
        provider._populate_traffic_managers()

        # implicitly asserts that non-matching profile is not included
        prefix = _root_traffic_manager_name(record)
        self.assertEqual(
            provider._find_traffic_managers(record),
            {
                prefix,
                f'{prefix}-pool-two',
                f'{prefix}-rule-one',
                f'{prefix}-rule-two',
            },
        )

    def test_traffic_manager_gc(self):
        provider, zone, record = self._get_dynamic_package()
        provider._populate_traffic_managers()

        profiles = provider._find_traffic_managers(record)
        profile_delete_mock = provider._tm_client.profiles.delete

        provider._traffic_managers_gc(record, profiles)
        profile_delete_mock.assert_not_called()

        profile_delete_mock.reset_mock()
        remove = list(profiles)[3]
        profiles.discard(remove)

        provider._traffic_managers_gc(record, profiles)
        profile_delete_mock.assert_has_calls(
            [call(provider._resource_group, remove)]
        )

    def test_apply(self):
        provider = self._get_provider()

        expected_n = len(octo_records)
        half = int(expected_n / 2)
        changes = [Create(r) for r in octo_records[:half]] + [
            Update(r, r) for r in octo_records[half:]
        ]
        deletes = [Delete(r) for r in octo_records]

        self.assertEqual(
            expected_n, provider.apply(Plan(None, zone_public, changes, True))
        )
        self.assertEqual(
            expected_n,
            provider.apply(Plan(zone_public, zone_public, deletes, True)),
        )

    def test_apply_create_dynamic(self):
        provider = self._get_provider()

        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = []

        tm_sync = provider._tm_client.profiles.create_or_update

        record = self._get_dynamic_record(zone_public)

        profiles = self._get_tm_profiles(provider)

        provider._apply_Create(Create(record))
        # create was called as many times as number of profiles required for
        # the dynamic record
        self.assertEqual(tm_sync.call_count, len(profiles))

        create = provider.dns_client.record_sets.create_or_update
        create.assert_called_once()

    def test_apply_create_root_ns_management(self):
        provider = self._get_provider()

        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = []

        provider._required_root_ns_values['unit.tests'] = set(
            ('ns1-1.azure-dns.com.', 'ns1-1.azure-dns.info.')
        )

        # modification required
        record = Record.new(
            zone_public,
            '',
            data={
                'ttl': 3600,
                'type': 'NS',
                'values': ('ns1.unit.tests.', 'ns2.unit.tests.'),
            },
        )

        provider._apply_Create(Create(record))

        create = provider.dns_client.record_sets.create_or_update
        create.assert_called_once_with(
            resource_group_name='mock_rg',
            zone_name='unit.tests',
            relative_record_set_name='@',
            record_type='NS',
            parameters={
                'ns_records': [
                    NsRecord(nsdname='ns1-1.azure-dns.com.'),
                    NsRecord(nsdname='ns1-1.azure-dns.info.'),
                    NsRecord(nsdname='ns1.unit.tests.'),
                    NsRecord(nsdname='ns2.unit.tests.'),
                ],
                'ttl': 3600,
            },
        )

    def test_apply_update_dynamic(self):
        # existing is simple, new is dynamic
        provider = self._get_provider()
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value = []
        profiles = self._get_tm_profiles(provider)
        dynamic_record = self._get_dynamic_record(zone_public)
        simple_record = Record.new(
            zone_public,
            dynamic_record.name,
            data={'type': 'CNAME', 'ttl': 3600, 'value': 'cname.unit.tests.'},
        )
        change = Update(simple_record, dynamic_record)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        self.assertEqual(tm_sync.call_count, len(profiles))
        dns_update.assert_called_once()
        tm_delete.assert_not_called()

        # existing is dynamic, new is simple
        provider, existing, dynamic_record = self._get_dynamic_package()
        profiles = self._get_tm_profiles(provider)
        change = Update(dynamic_record, simple_record)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        tm_sync.assert_not_called()
        dns_update.assert_called_once()
        self.assertEqual(tm_delete.call_count, len(profiles))

        # both are dynamic, healthcheck port is changed
        provider, existing, dynamic_record = self._get_dynamic_package()
        profiles = self._get_tm_profiles(provider)
        dynamic_record2 = self._get_dynamic_record(existing)
        dynamic_record2.octodns['healthcheck']['port'] += 1
        change = Update(dynamic_record, dynamic_record2)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        self.assertEqual(tm_sync.call_count, len(profiles))
        dns_update.assert_not_called()
        tm_delete.assert_not_called()

        # both are dynamic, extra profile should be deleted
        provider, existing, dynamic_record = self._get_dynamic_package()
        sample_profile = self._get_tm_profiles(provider)[0]
        tm_id = provider._profile_name_to_id
        root_profile_name = _root_traffic_manager_name(dynamic_record)
        extra_profile = Profile(
            id=tm_id(f'{root_profile_name}-pool-random'),
            name=f'{root_profile_name}-pool-random',
            traffic_routing_method='Weighted',
            dns_config=sample_profile.dns_config,
            monitor_config=sample_profile.monitor_config,
            endpoints=sample_profile.endpoints,
        )
        tm_list = provider._tm_client.profiles.list_by_resource_group
        tm_list.return_value.append(extra_profile)
        change = Update(dynamic_record, dynamic_record)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        tm_sync.assert_not_called()
        dns_update.assert_not_called()
        tm_delete.assert_called_once()

        # both are dynamic but alias is broken
        provider, existing, record1 = self._get_dynamic_package()
        azrecord = RecordSet(
            ttl=record1.ttl, target_resource=SubResource(id=None)
        )
        azrecord.name = record1.name or '@'
        azrecord.type = f'Microsoft.Network/dnszones/{record1._type}'

        record2 = provider._populate_record(zone_public, azrecord, lenient=True)
        self.assertIsNone(record2.value)

        change = Update(record2, record1)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        tm_sync.assert_not_called()
        dns_update.assert_called_once()
        tm_delete.assert_not_called()

    def test_apply_update_dynamic_A(self):
        # existing is simple, new is dynamic
        provider = self._get_provider()
        simple_record = Record.new(
            zone_public,
            'foo',
            data={'type': 'A', 'ttl': 3600, 'values': ['1.1.1.1', '2.2.2.2']},
        )
        dynamic_record = Record.new(
            zone_public,
            simple_record.name,
            data={
                'type': 'A',
                'ttl': 60,
                'values': ['1.1.1.1'],
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {'value': '8.8.8.8'},
                                {'value': '4.4.4.4'},
                            ],
                            'fallback': 'two',
                        },
                        'two': {'values': [{'value': '9.9.9.9'}]},
                    },
                    'rules': [{'geos': ['AF'], 'pool': 'two'}, {'pool': 'one'}],
                },
            },
        )
        num_tms = len(provider._generate_traffic_managers(dynamic_record))
        change = Update(simple_record, dynamic_record)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        # sync is called once for each profile, plus 1 at the end for nested
        # endpoints to workaround A/AAAA nesting limitation in Azure
        self.assertEqual(tm_sync.call_count, num_tms + 1)
        dns_update.assert_called_once()
        tm_delete.assert_not_called()

        # both are dynamic, healthcheck port is changed to trigger sync on
        # all profiles
        provider = self._get_provider()
        dynamic_record2 = Record.new(
            zone_public,
            dynamic_record.name,
            data={
                'type': dynamic_record._type,
                'ttl': 300,
                'values': dynamic_record.values,
                'dynamic': dynamic_record.dynamic._data(),
                'octodns': {'healthcheck': {'port': 4433}},
            },
        )
        change = Update(dynamic_record, dynamic_record2)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        # sync is called once for each profile, extra call at the end is not
        # needed when existing dynamic record is already aliased to its root
        # profile
        self.assertEqual(tm_sync.call_count, num_tms)
        dns_update.assert_not_called()
        tm_delete.assert_not_called()

    def test_apply_update_dynamic_A_singluar(self):
        # existing is simple, new is dynamic that needs only one profile
        provider = self._get_provider()
        simple_record = Record.new(
            zone_public,
            'foo',
            data={'type': 'A', 'ttl': 3600, 'values': ['1.1.1.1', '2.2.2.2']},
        )
        dynamic_record = Record.new(
            zone_public,
            simple_record.name,
            data={
                'type': 'A',
                'ttl': 60,
                'values': ['1.1.1.1'],
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {'value': '8.8.8.8'},
                                {'value': '1.1.1.1', 'status': 'up'},
                            ]
                        }
                    },
                    'rules': [{'pool': 'one'}],
                },
            },
        )
        external = 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        self._validate_dynamic(
            dynamic_record,
            [
                Profile(
                    name='foo--unit--tests-A',
                    traffic_routing_method='Weighted',
                    dns_config=DnsConfig(
                        relative_name='foo--unit--tests-a',
                        ttl=dynamic_record.ttl,
                    ),
                    monitor_config=_get_monitor(dynamic_record),
                    endpoints=[
                        Endpoint(
                            name='one--8.8.8.8',
                            type=external,
                            target='8.8.8.8',
                            weight=1,
                        ),
                        Endpoint(
                            name='one--1.1.1.1--default--',
                            type=external,
                            target='1.1.1.1',
                            weight=1,
                            endpoint_status=EndpointStatus.ENABLED,
                            always_serve=AlwaysServe.ENABLED,
                        ),
                    ],
                )
            ],
        )

        change = Update(simple_record, dynamic_record)
        provider._apply_Update(change)
        tm_sync, dns_update, tm_delete = (
            provider._tm_client.profiles.create_or_update,
            provider.dns_client.record_sets.create_or_update,
            provider._tm_client.profiles.delete,
        )
        self.assertEqual(tm_sync.call_count, 1)
        dns_update.assert_called_once()
        tm_delete.assert_not_called()

    def test_apply_delete_dynamic(self):
        provider, existing, record = self._get_dynamic_package()
        provider._populate_traffic_managers()
        profiles = self._get_tm_profiles(provider)
        change = Delete(record)
        provider._apply_Delete(change)
        dns_delete, tm_delete = (
            provider.dns_client.record_sets.delete,
            provider._tm_client.profiles.delete,
        )
        dns_delete.assert_called_once()
        self.assertEqual(tm_delete.call_count, len(profiles))

    def test_create_zone(self):
        provider = self._get_provider()

        changes = []
        for i in octo_records:
            changes.append(Create(i))
        desired = Zone('unit2.test.', [])

        err_msg = 'The Resource \'Microsoft.Network/dnszones/unit2.test\' '
        err_msg += 'under resource group \'mock_rg\' was not found.'
        _get = provider.dns_client.zones.get
        _get.side_effect = CloudError(Mock(status=404), err_msg)

        expected_n = len(octo_records)
        self.assertEqual(
            expected_n, provider.apply(Plan(None, desired, changes, True))
        )

    def test_check_zone_no_create(self):
        provider = self._get_provider()

        rs = []
        recordSet = RecordSet(a_records=[ARecord(ipv4_address='1.1.1.1')])
        recordSet.name, recordSet.ttl, recordSet.type = 'a1', 0, 'A'
        rs.append(recordSet)
        recordSet = RecordSet(
            a_records=[
                ARecord(ipv4_address='1.1.1.1'),
                ARecord(ipv4_address='2.2.2.2'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'a2', 1, 'A'
        rs.append(recordSet)

        record_list = provider.dns_client.record_sets.list_by_dns_zone
        record_list.return_value = rs

        err_msg = 'The Resource \'Microsoft.Network/dnszones/unit3.test\' '
        err_msg += 'under resource group \'mock_rg\' was not found.'
        _get = provider.dns_client.zones.get
        _get.side_effect = CloudError(Mock(status=404), err_msg)

        exists = provider.populate(Zone('unit3.test.', []))
        self.assertFalse(exists)

        self.assertEqual(len(zone_public.records), 0)

    def test_populate_caches_root_ns(self):
        provider = self._get_provider()

        # zone already exists
        provider._azure_zones.add('unit.test')

        rs = []

        recordSet = RecordSet(
            ns_records=[
                NsRecord(nsdname='ns1.unit.test.'),
                NsRecord(nsdname='ns1-1.azure-dns.com.'),
                NsRecord(nsdname='ns1-1.azure-dns.info.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = '@', 9, 'NS'
        rs.append(recordSet)

        recordSet = RecordSet(ns_records=[NsRecord(nsdname='ns3.unit.test.')])
        recordSet.name, recordSet.ttl, recordSet.type = 'sub', 12, 'NS'
        rs.append(recordSet)

        record_list = provider.dns_client.record_sets.list_by_dns_zone
        record_list.return_value = rs

        # zone will exist and have a mixture of NS records
        zone = Zone('unit.test.', [])
        self.assertTrue(provider.populate(zone))
        self.assertEqual(
            {
                'unit.test': set(
                    ('ns1-1.azure-dns.com.', 'ns1-1.azure-dns.info.')
                )
            },
            provider._required_root_ns_values,
        )

    def test_check_zone_create_caches_root_ns(self):
        provider = self._get_provider()

        # w/o create we just don't find the zone
        self.assertFalse(provider._check_zone('some.zone.com'))

        test_zone = AzureZone(location='global')
        test_zone.name_servers = [
            'ns1-1.azure-dns.com.',
            'ns1-1.azure-dns.info.',
        ]
        provider.dns_client.zones.create_or_update.return_value = test_zone

        # with create we'll fail to find it, create it, and grab it's root NS
        # record values
        self.assertTrue(provider._check_zone('unit.test', create=True))
        self.assertEqual(
            {
                'unit.test': set(
                    ('ns1-1.azure-dns.com.', 'ns1-1.azure-dns.info.')
                )
            },
            provider._required_root_ns_values,
        )

    def test_ensure_required_root_ns_values(self):
        provider = self._get_provider()

        # stuff some required values into the cache
        required = set(('ns1-1.azure-dns.com.', 'ns1-1.azure-dns.info.'))
        provider._required_root_ns_values = {'unit.test': required}

        zone = Zone('unit.test.', [])

        custom = set(('ns1.unit.test.', 'ns2.unit.test.'))

        # no required values
        record = Record.new(
            zone, '', data={'ttl': 4, 'type': 'NS', 'values': list(custom)}
        )
        ret, modified = provider._ensure_required_root_ns_values(record)
        self.assertTrue(modified)
        self.assertEqual(required | custom, set(ret.values))
        # make sure original record wasn't modified
        self.assertEqual(2, len(record.values))
        # same behavior with _process_desired_zone
        zone.add_record(record, replace=True)
        ret = provider._process_desired_zone(zone)
        ret = list(ret.records)[0]
        self.assertEqual(required | custom, set(ret.values))

        # has partial required
        record = Record.new(
            zone,
            '',
            data={
                'ttl': 4,
                'type': 'NS',
                'values': list(custom) + list(required)[1:],
            },
        )
        ret, modified = provider._ensure_required_root_ns_values(record)
        self.assertTrue(modified)
        self.assertEqual(required | custom, set(ret.values))
        self.assertEqual(3, len(record.values))
        # same behavior with _process_desired_zone
        zone.add_record(record, replace=True)
        ret = provider._process_desired_zone(zone)
        ret = list(ret.records)[0]
        self.assertEqual(required | custom, set(ret.values))

        # has everything that's required
        record = Record.new(
            zone,
            '',
            data={
                'ttl': 4,
                'type': 'NS',
                'values': list(custom) + list(required),
            },
        )
        ret, modified = provider._ensure_required_root_ns_values(record)
        # was not modified b/c it's already complete
        self.assertFalse(modified)
        # same behavior with _process_desired_zone
        zone.add_record(record, replace=True)
        ret = provider._process_desired_zone(zone)
        # same object, no copy
        self.assertEqual(id(zone), id(ret))

        # has just the required
        record = Record.new(
            zone, '', data={'ttl': 4, 'type': 'NS', 'values': list(required)}
        )
        ret, modified = provider._ensure_required_root_ns_values(record)
        # was not modified b/c it's already complete
        self.assertFalse(modified)
        # same behavior with _process_desired_zone
        zone.add_record(record, replace=True)
        ret = provider._process_desired_zone(zone)
        # same object, no copy
        self.assertEqual(id(zone), id(ret))

    def test_cli_provider(self):
        '''Tests that the AzureProvider is created correctly'''
        provider = AzureProvider(
            'mock_id',
            'mock_sub',
            'mock_rg',
            client_credential_method='cli',
            directory_id='mock_directory',
            client_id='mock_client',
            key='mock_key',
            strict_supports=False,
        )

        self.assertIsInstance(provider._client_credential, AzureCliCredential)

    def test_no_provider(self):
        provider = AzureProvider(
            'mock_id',
            'mock_sub',
            'mock_rg',
            client_credential_method='foobar',
            directory_id='mock_directory',
            client_id='mock_client',
            key='mock_key',
            strict_supports=False,
        )
        with self.assertRaises(AzureException):
            _ = provider._client_credential

    def test_client_retry_policy(self):
        # client_status_retries & client_total_retries
        provider = self._get_provider()
        policy = provider._dns_client_retry_policy
        # get provider passes client_status_retries=4 and client_total_retries=42
        self.assertEqual(4, policy.status_retries)
        self.assertEqual(42, policy.total_retries)
        # we should have defaults for these
        self.assertEqual(0.8, policy.backoff_factor)
        self.assertEqual(120, policy.backoff_max)

        # client_retry_policy
        provider = AzureProvider(
            'mock_id',
            'mock_sub',
            'mock_rg',
            directory_id='mock_directory',
            client_id='mock_client',
            key='mock_key',
            strict_supports=False,
            client_retry_policy={'backoff_factor': 0.5, 'backoff_max': 90},
        )
        policy = provider._dns_client_retry_policy
        # we should have the (azure) defaults we passed client_retry_policy and
        # didn't include them
        self.assertEqual(3, policy.status_retries)
        self.assertEqual(10, policy.total_retries)
        # and we should have the values we explicitly set
        self.assertEqual(0.5, policy.backoff_factor)
        self.assertEqual(90, policy.backoff_max)


class TestPrivateAzureDnsProvider(TestCase):
    @patch('octodns_azure.PrivateDnsManagementClient')
    @patch('octodns_azure.ClientSecretCredential')
    def _get_provider(self, mock_css, mock_client):
        '''Returns a mock AzureProvider object to use in testing.

        :param mock_spc: placeholder
        :type  mock_spc: str
        :param mock_client: placeholder
        :type  mock_client: str
        :param mock_tm_client: placeholder
        :type  mock_tm_client: str

        :type return: AzureProvider
        '''
        provider = AzurePrivateProvider(
            'mock_id',
            'mock_sub',
            'mock_rg',
            directory_id='mock_directory',
            client_id='mock_client',
            key='mock_key',
            strict_supports=False,
        )

        # Fetch the client to force it to load the creds
        provider.dns_client

        return provider

    def _get_dynamic_record(self, zone):
        return Record.new(
            zone,
            'foo',
            data={
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.unit.tests.',
                'dynamic': {
                    'pools': {
                        'one': {
                            'values': [
                                {'value': 'one.unit.tests.', 'weight': 1}
                            ],
                            'fallback': 'two',
                        },
                        'two': {
                            'values': [
                                {'value': 'two1.unit.tests.', 'weight': 3},
                                {'value': 'two2.unit.tests.', 'weight': 4},
                            ],
                            'fallback': 'three',
                        },
                        'three': {
                            'values': [
                                {'value': 'three.unit.tests.', 'weight': 1}
                            ]
                        },
                    },
                    'rules': [
                        {
                            'geos': ['AF', 'EU-DE', 'NA-US-CA', 'OC'],
                            'pool': 'one',
                        },
                        {'pool': 'two'},
                    ],
                },
                'octodns': {
                    'healthcheck': {
                        'path': '/_ping',
                        'port': 4443,
                        'protocol': 'HTTPS',
                    }
                },
            },
        )

    def _get_dynamic_package(self):
        '''Convenience function to setup a sample dynamic record.'''
        provider = self._get_provider()

        # setup zone with dynamic record
        zone = Zone(name='unit.tests.', sub_zones=[])
        record = self._get_dynamic_record(zone)
        zone.add_record(record)

        # return everything
        return provider, zone, record

    def test_populate_records(self):
        provider = self._get_provider()

        rs = []
        recordSet = RecordSet(a_records=[ARecord(ipv4_address='1.1.1.1')])
        recordSet.name, recordSet.ttl, recordSet.type = 'a1', 0, 'A'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            a_records=[
                ARecord(ipv4_address='1.1.1.1'),
                ARecord(ipv4_address='2.2.2.2'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'a2', 1, 'A'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        aaaa1 = AaaaRecord(ipv6_address='1:1ec:1::1')
        recordSet = RecordSet(aaaa_records=[aaaa1])
        recordSet.name, recordSet.ttl, recordSet.type = 'aaaa1', 2, 'AAAA'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        aaaa2 = AaaaRecord(ipv6_address='1:1ec:1::2')
        recordSet = RecordSet(aaaa_records=[aaaa1, aaaa2])
        recordSet.name, recordSet.ttl, recordSet.type = 'aaaa2', 3, 'AAAA'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            caa_records=[
                CaaRecord(flags=0, tag='issue', value='caa1.unit.tests')
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'caa1', 4, 'CAA'
        rs.append(recordSet)
        recordSet = RecordSet(
            caa_records=[
                CaaRecord(flags=0, tag='issue', value='caa1.unit.tests'),
                CaaRecord(flags=0, tag='issue', value='caa2.unit.tests'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'caa2', 4, 'CAA'
        rs.append(recordSet)
        cname1 = CnameRecord(cname='cname.unit.test.')
        recordSet = RecordSet(cname_record=cname1)
        recordSet.name, recordSet.ttl, recordSet.type = 'cname1', 5, 'CNAME'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            mx_records=[MxRecord(preference=10, exchange='mx1.unit.test.')]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'mx1', 7, 'MX'
        rs.append(recordSet)
        recordSet = RecordSet(
            mx_records=[
                MxRecord(preference=10, exchange='mx1.unit.test.'),
                MxRecord(preference=11, exchange='mx2.unit.test.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'mx2', 8, 'MX'
        rs.append(recordSet)
        recordSet = RecordSet(ns_records=[NsRecord(nsdname='ns1.unit.test.')])
        recordSet.name, recordSet.ttl, recordSet.type = 'ns1', 9, 'NS'
        rs.append(recordSet)
        recordSet = RecordSet(
            ns_records=[
                NsRecord(nsdname='ns1.unit.test.'),
                NsRecord(nsdname='ns2.unit.test.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'ns2', 10, 'NS'
        rs.append(recordSet)
        ptr1 = PtrRecord(ptrdname='ptr1.unit.test.')
        recordSet = RecordSet(ptr_records=[ptr1])
        recordSet.name, recordSet.ttl, recordSet.type = 'ptr1', 11, 'PTR'
        rs.append(recordSet)
        recordSet = RecordSet(
            srv_records=[
                SrvRecord(priority=1, weight=2, port=3, target='1unit.tests.')
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = '_srv1._tcp', 13, 'SRV'
        rs.append(recordSet)
        recordSet = RecordSet(
            srv_records=[
                SrvRecord(priority=1, weight=2, port=3, target='1unit.tests.'),
                SrvRecord(priority=4, weight=5, port=6, target='2unit.tests.'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = '_srv2._tcp', 14, 'SRV'
        rs.append(recordSet)
        recordSet = RecordSet(txt_records=[TxtRecord(value='sample text1')])
        recordSet.name, recordSet.ttl, recordSet.type = 'txt1', 15, 'TXT'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(
            txt_records=[
                TxtRecord(value='sample text1'),
                TxtRecord(value='sample text2'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'txt2', 16, 'TXT'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)
        recordSet = RecordSet(soa_record=[SoaRecord()])
        recordSet.name, recordSet.ttl, recordSet.type = '', 17, 'SOA'
        rs.append(recordSet)
        long_txt = "v=spf1 ip4:10.10.0.0/24 ip4:10.10.1.0/24 ip4:10.10.2.0/24"
        long_txt += " ip4:10.10.3.0/24 ip4:10.10.4.0/24 ip4:10.10.5.0/24 "
        long_txt += " 10.6.0/24 ip4:10.10.7.0/24 ip4:10.10.8.0/24 "
        long_txt += " ip4:10.10.10.0/24 ip4:10.10.11.0/24 ip4:10.10.12.0/24"
        long_txt += " ip4:10.10.13.0/24 ip4:10.10.14.0/24 ip4:10.10.15.0/24"
        long_txt += " ip4:10.10.16.0/24 ip4:10.10.17.0/24 ip4:10.10.18.0/24"
        long_txt += " ip4:10.10.19.0/24 ip4:10.10.20.0/24  ~all"
        recordSet = RecordSet(
            txt_records=[
                TxtRecord(value='sample value1'),
                TxtRecord(value=long_txt),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'txt3', 18, 'TXT'
        recordSet.target_resource = SubResource()
        rs.append(recordSet)

        record_list = provider.dns_client.record_sets.list
        record_list.return_value = rs

        zone_list = provider.dns_client.private_zones.list_by_resource_group
        zone_list.return_value = [zone_private]

        exists = provider.populate(zone_private)

        self.assertEqual(len(zone_private.records), 17)
        self.assertTrue(exists)

    def test_azure_zones(self):
        provider = self._get_provider()

        zone_list = provider.dns_client.private_zones.list_by_resource_group
        zone_1 = AzurePrivateZone(location='global')
        # This is far from ideal but the
        # zone constructor doesn't let me set it on creation
        zone_1.name = "zone-1"
        zone_2 = AzurePrivateZone(location='global')
        # This is far from ideal but the
        # zone constructor doesn't let me set it on creation
        zone_2.name = "zone-2"
        zone_list.return_value = [zone_1, zone_2, zone_1]

        zones = provider._azure_zones
        self.assertTrue(zone_1.name in zones)
        self.assertTrue(zone_2.name in zones)

        # This should be returning two zones since two zones are the same
        self.assertEqual(len(provider._azure_zones), 2)

    def test_bad_zone_response(self):
        provider = self._get_provider()

        _get = provider.dns_client.private_zones.get
        _get.side_effect = CloudError(Mock(status=404), 'Azure Error')
        self.assertEqual(provider._check_zone('unit.test', create=False), None)

    def test_simple_process_desired_zone(self):
        # simple records should not get changed by _process_desired_zone
        zone1 = Zone(zone_private.name, sub_zones=[])
        record1 = Record.new(
            zone1,
            'foo',
            data={'type': 'CNAME', 'ttl': 86400, 'value': 'one.unit.tests.'},
        )
        zone1.add_record(record1)
        zone2 = self._get_provider()._process_desired_zone(zone1.copy())
        record2 = list(zone2.records)[0]
        self.assertTrue(record1.data, record2.data)

    def test_apply(self):
        provider = self._get_provider()

        expected_n = len(octo_records)
        half = int(expected_n / 2)
        changes = [Create(r) for r in octo_records[:half]] + [
            Update(r, r) for r in octo_records[half:]
        ]
        deletes = [Delete(r) for r in octo_records]

        self.assertEqual(
            expected_n, provider.apply(Plan(None, zone_public, changes, True))
        )
        self.assertEqual(
            expected_n,
            provider.apply(Plan(zone_public, zone_public, deletes, True)),
        )

    def test_create_zone(self):
        provider = self._get_provider()

        changes = []
        for i in octo_records:
            changes.append(Create(i))
        desired = Zone('unit2.test.', [])

        err_msg = 'The Resource \'Microsoft.Network/dnszones/unit2.test\' '
        err_msg += 'under resource group \'mock_rg\' was not found.'
        _get = provider.dns_client.zones.get
        _get.side_effect = CloudError(Mock(status=404), err_msg)

        expected_n = len(octo_records)
        self.assertEqual(
            expected_n, provider.apply(Plan(None, desired, changes, True))
        )

    def test_check_zone_no_create(self):
        provider = self._get_provider()

        rs = []
        recordSet = RecordSet(a_records=[ARecord(ipv4_address='1.1.1.1')])
        recordSet.name, recordSet.ttl, recordSet.type = 'a1', 0, 'A'
        rs.append(recordSet)
        recordSet = RecordSet(
            a_records=[
                ARecord(ipv4_address='1.1.1.1'),
                ARecord(ipv4_address='2.2.2.2'),
            ]
        )
        recordSet.name, recordSet.ttl, recordSet.type = 'a2', 1, 'A'
        rs.append(recordSet)

        record_list = provider.dns_client.record_sets.list_by_dns_zone
        record_list.return_value = rs

        err_msg = 'The Resource \'Microsoft.Network/dnszones/unit3.test\' '
        err_msg += 'under resource group \'mock_rg\' was not found.'
        _get = provider.dns_client.zones.get
        _get.side_effect = CloudError(Mock(status=404), err_msg)

        exists = provider.populate(Zone('unit3.test.', []))
        self.assertFalse(exists)

        self.assertEqual(len(zone_private.records), 0)
