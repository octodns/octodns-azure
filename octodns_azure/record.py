#
#
#

from octodns.equality import EqualityTupleMixin
from octodns.record import Record, ValuesMixin
from octodns.record.validator import (
    RecordValidator,
    ValidationReason,
    ValueValidator,
)

_TM_PROFILE_PROVIDER = '/providers/microsoft.network/trafficmanagerprofiles/'


def _is_tm_profile_id(resource_id):
    return _TM_PROFILE_PROVIDER in resource_id.lower()


class _AzureAliasValueValidator(ValueValidator):
    TYPES = ('A', 'AAAA', 'CNAME')

    def validate(self, value_cls, data, _type):
        if not isinstance(data, (list, tuple)):
            data = (data,)

        def reason(msg):
            return ValidationReason(msg, validator_id=self.id)

        reasons = []
        types = []
        for value in data:
            if not isinstance(value, dict):
                reasons.append(reason(f'invalid value "{value}"'))
                continue

            typ = value.get('type')
            if not typ:
                reasons.append(reason('missing type'))
            elif typ not in self.TYPES:
                reasons.append(reason(f'invalid type "{typ}"'))
            else:
                types.append(typ)

            target = value.get('target-resource')
            if not target:
                reasons.append(reason('missing target-resource'))
            elif not isinstance(target, str) or not target.lower().startswith(
                '/subscriptions/'
            ):
                reasons.append(
                    reason(
                        f'invalid target-resource "{target}", expected an '
                        'Azure resource id starting with /subscriptions/'
                    )
                )
            elif _is_tm_profile_id(target):
                # Traffic Manager profiles are owned by octoDNS through dynamic
                # records, pointing at one here would fight with that
                reasons.append(
                    reason(
                        f'target-resource "{target}" is a Traffic Manager '
                        'profile, use a dynamic record instead'
                    )
                )

        # each value maps to an Azure recordset of that type at the record's
        # name, there can only be one of each
        for typ in sorted(set(types)):
            if types.count(typ) > 1:
                reasons.append(reason(f'duplicate type "{typ}"'))
        if 'CNAME' in types and len(types) > 1:
            reasons.append(reason('CNAME cannot be combined with other types'))

        return reasons


class _AzureAliasRootCnameValidator(RecordValidator):
    def validate(self, record_cls, name, fqdn, data, disabled=None):
        if name:
            return []
        values = data.get('values', data.get('value', []))
        if not isinstance(values, (list, tuple)):
            values = [values]
        for value in values:
            if isinstance(value, dict) and value.get('type') == 'CNAME':
                return [
                    ValidationReason(
                        'root CNAME not allowed', validator_id=self.id
                    )
                ]
        return []


class _AzureAliasValue(EqualityTupleMixin, dict):
    VALIDATORS = [_AzureAliasValueValidator('azure-alias-value')]

    @classmethod
    def process(cls, values):
        return [cls(v) for v in values]

    def __init__(self, value):
        super().__init__()
        self['type'] = value['type']
        self['target-resource'] = value['target-resource']

    @property
    def _type(self):
        return self['type']

    @property
    def target_resource(self):
        return self['target-resource']

    @property
    def data(self):
        return {'type': self._type, 'target-resource': self.target_resource}

    def _equality_tuple(self):
        # Azure resource ids are case-insensitive and Azure doesn't always hand
        # them back with the casing they were created with
        return (self._type, self.target_resource.lower())

    def __hash__(self):
        return hash(self._equality_tuple())

    def __repr__(self):
        return f'{self._type} {self.target_resource}'


class AzureAliasRecord(ValuesMixin, Record):
    '''
    Azure alias recordsets that point at resources octoDNS doesn't manage,
    e.g. Front Door or CDN endpoints, public IPs, or other recordsets in the
    zone. Each value is a separate A, AAAA, or CNAME Azure recordset at the
    record's name.
    '''

    _type = 'AzureProvider/ALIAS'
    _value_type = _AzureAliasValue

    VALIDATORS = [_AzureAliasRootCnameValidator('azure-alias-root-cname')]


Record.register_type(AzureAliasRecord)
