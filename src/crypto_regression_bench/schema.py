"""Bounded strict AES-GCM Wycheproof v1 profile; no input code or schema loading."""
from dataclasses import dataclass
import json

KNOWN_FLAGS = frozenset({'CounterWrap', 'Ktv', 'LongIv', 'ModifiedTag', 'Pseudorandom', 'SmallIv', 'SpecialCase', 'ZeroLengthIv'})
RESULTS = ('valid', 'invalid', 'acceptable')
HEX_FIELDS = ('key', 'iv', 'aad', 'msg', 'ct', 'tag')


class Problem(Exception):
    def __init__(self, code, location='$', position=None):
        self.code, self.location, self.position = code, location, position


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 1024 * 1024
    nesting: int = 12
    json_nodes: int = 30000
    string_chars: int = 32768
    groups: int = 256
    cases: int = 2048
    field_bytes: int = 16384
    decoded_bytes: int = 1024 * 1024
    operations: int = 4096
    report_bytes: int = 1024 * 1024

    def validate(self):
        maximum = Limits()
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= getattr(maximum, name):
                raise ValueError('limits must be positive integers no greater than defaults')
        if self.report_bytes < 4096:
            raise ValueError('report_bytes must be at least 4096')


@dataclass(frozen=True)
class Case:
    tc_id: int
    group: int
    index: int
    expected: str
    flags_known: bool
    key: bytes
    iv: bytes
    aad: bytes
    msg: bytes
    ct: bytes
    tag: bytes
    key_bits: int
    iv_bits: int
    tag_bits: int

    @property
    def location(self):
        return f'$.testGroups[{self.group}].tests[{self.index}]'


@dataclass(frozen=True)
class Corpus:
    cases: tuple
    groups: int
    algorithm_supported: bool
    notes_known: bool


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Problem('duplicate_json_key')
        result[key] = value
    return result


def _constant(value):
    raise Problem('nonfinite_json_number')


def _object(value, required, optional=(), where='$'):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise Problem('object_shape', where)


def _integer(value, minimum, maximum, where):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Problem('integer_shape', where)


def _string(value, where, nonempty=False):
    if type(value) is not str or (nonempty and not value):
        raise Problem('string_shape', where)


def _strings(value, where):
    if type(value) is not list:
        raise Problem('string_array_shape', where)
    for item in value:
        _string(item, where)


def _depth_scan(text, maximum):
    # Preflight only: JSON parser still validates grammar and matched brackets.
    quoted = escaped = False
    depth = 0
    for offset, ch in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch in '[{':
            depth += 1
            if depth > maximum:
                raise Problem('nesting_limit', position={'character_offset': offset})
        elif ch in ']}':
            depth -= 1


def _tree_budget(root, limits):
    pending = [root]
    nodes = 0
    while pending:
        value = pending.pop()
        nodes += 1
        if nodes > limits.json_nodes:
            raise Problem('json_node_limit')
        if type(value) is dict:
            pending.extend(value.keys())
            pending.extend(value.values())
        elif type(value) is list:
            pending.extend(value)
        elif type(value) is str and len(value) > limits.string_chars:
            raise Problem('string_limit')


def parse_corpus(data, limits):
    try:
        text = data.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise Problem('utf8_error', position={'byte_offset': exc.start}) from None
    _depth_scan(text, limits.nesting)
    try:
        root = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except json.JSONDecodeError as exc:
        raise Problem('json_syntax', position={'byte_offset': len(text[:exc.pos].encode('utf-8')), 'line': exc.lineno, 'character_column': exc.colno}) from None
    except (RecursionError, ValueError):
        raise Problem('json_parse_error') from None
    _tree_budget(root, limits)
    _object(root, ('algorithm', 'schema', 'numberOfTests', 'header', 'notes', 'testGroups'), ('generatorVersion',))
    _string(root['algorithm'], '$.algorithm', True)
    if root['schema'] != 'aead_test_schema_v1.json':
        raise Problem('unsupported_schema', '$.schema')
    _integer(root['numberOfTests'], 1, limits.cases, '$.numberOfTests')
    _strings(root['header'], '$.header')
    if 'generatorVersion' in root:
        _string(root['generatorVersion'], '$.generatorVersion')
    notes = root['notes']
    if type(notes) is not dict:
        raise Problem('notes_shape', '$.notes')
    for name, note in notes.items():
        _object(note, ('bugType',), ('description', 'effect', 'links', 'cves'), '$.notes[*]')
        for key, value in note.items():
            if key in ('links', 'cves'):
                _strings(value, '$.notes[*].'+key)
            else:
                _string(value, '$.notes[*].'+key)
    groups = root['testGroups']
    if type(groups) is not list or not 1 <= len(groups) <= limits.groups:
        raise Problem('group_limit_or_shape', '$.testGroups')
    cases, seen, decoded = [], set(), 0
    for gi, group in enumerate(groups):
        where = f'$.testGroups[{gi}]'
        _object(group, ('type', 'source', 'keySize', 'ivSize', 'tagSize', 'tests'), where=where)
        if group['type'] != 'AeadTest':
            raise Problem('unsupported_group_type', where+'.type')
        _object(group['source'], ('name', 'version'), where=where+'.source')
        for key in ('name', 'version'):
            _string(group['source'][key], where+'.source.'+key, True)
        for key in ('keySize', 'ivSize', 'tagSize'):
            _integer(group[key], 0, limits.field_bytes * 8, where+'.'+key)
            if group[key] % 8:
                raise Problem('nonbyte_bit_size', where+'.'+key)
        if type(group['tests']) is not list or not group['tests']:
            raise Problem('test_array_shape', where+'.tests')
        for ti, test in enumerate(group['tests']):
            loc = where+f'.tests[{ti}]'
            if len(cases) >= limits.cases:
                raise Problem('case_limit', loc)
            _object(test, ('tcId', 'comment', 'flags', 'result', *HEX_FIELDS), where=loc)
            _integer(test['tcId'], 1, 10**9, loc+'.tcId')
            if test['tcId'] in seen:
                raise Problem('duplicate_tc_id', loc+'.tcId')
            seen.add(test['tcId'])
            _string(test['comment'], loc+'.comment')
            _strings(test['flags'], loc+'.flags')
            if len(set(test['flags'])) != len(test['flags']):
                raise Problem('duplicate_flag', loc+'.flags')
            if type(test['result']) is not str or test['result'] not in RESULTS:
                raise Problem('unsupported_expected_result', loc+'.result')
            values = {}
            for key in HEX_FIELDS:
                value = test[key]
                _string(value, loc+'.'+key)
                if len(value) % 2 or any(ch not in '0123456789abcdefABCDEF' for ch in value):
                    raise Problem('invalid_hex', loc+'.'+key)
                if len(value) // 2 > limits.field_bytes:
                    raise Problem('field_limit', loc+'.'+key)
                values[key] = bytes.fromhex(value)
                decoded += len(values[key])
                if decoded > limits.decoded_bytes:
                    raise Problem('decoded_limit', loc)
            for key, size in (('key', 'keySize'), ('iv', 'ivSize'), ('tag', 'tagSize')):
                if len(values[key]) * 8 != group[size]:
                    raise Problem('group_size_mismatch', loc+'.'+key)
            if len(values['ct']) != len(values['msg']):
                raise Problem('aead_length_profile', loc+'.ct')
            cases.append(Case(test['tcId'], gi, ti, test['result'], all(f in KNOWN_FLAGS and f in notes for f in test['flags']), **values, key_bits=group['keySize'], iv_bits=group['ivSize'], tag_bits=group['tagSize']))
    if len(cases) != root['numberOfTests']:
        raise Problem('declared_count_mismatch', '$.numberOfTests')
    return Corpus(tuple(cases), len(groups), root['algorithm'] == 'AES-GCM', not notes.keys() - KNOWN_FLAGS)
