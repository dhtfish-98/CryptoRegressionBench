"""Offline schema validation, real execution, conservative reproducible accounting."""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
import json
import os
import platform
import stat
import sys
from .adapter import Adapter, Observation, PINNED_VERSION
from .schema import Limits, Problem, RESULTS, parse_corpus

CORPUS_COMMIT = '3fa63dd0344abb611f1fb1d77e119938603ea230'
CORPUS_SHA256 = '985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7'


def read_local(path, limits):
    try:
        name = os.fspath(path)
    except TypeError:
        raise Problem('input_path_type') from None
    if type(name) is not str or not name or name in ('-',) or name.startswith('@') or '://' in name or '\x00' in name:
        raise Problem('local_regular_file_required')
    if any(type(getattr(os, flag, None)) is not int or getattr(os, flag, 0) <= 0
           for flag in ('O_NOFOLLOW', 'O_NONBLOCK')):
        raise Problem('safe_open_flags_unavailable')
    try:
        if stat.S_ISLNK(os.lstat(name).st_mode):
            raise Problem('input_symlink')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(name, flags)
        with os.fdopen(fd, 'rb') as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise Problem('local_regular_file_required')
            if before.st_size > limits.input_bytes:
                raise Problem('input_limit')
            data = handle.read(limits.input_bytes + 1)
            after = os.fstat(handle.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or len(data) != before.st_size:
                raise Problem('input_changed')
            if len(data) > limits.input_bytes:
                raise Problem('input_limit')
            return data
    except (OSError, UnicodeError):
        raise Problem('input_io_error') from None


def _base(limits):
    return {'tool':'CryptoRegressionBench', 'version':'0.1.3', 'status':'OPEN', 'schema_complete':False, 'execution_complete':False, 'detail_complete':True, 'corpus':{'identity':'UNOBSERVED', 'fixed_commit':CORPUS_COMMIT, 'fixed_file':'testvectors_v1/aes_gcm_test.json'}, 'library':{'adapter':'cryptography.AESGCM', 'required_version':PINNED_VERSION, 'status':'UNOBSERVED'}, 'counts':{'groups':0, 'cases':0, 'operations':0}, 'operation_count_complete':True, 'expected_results':{r:{'total':0, 'matched':0, 'mismatched':0, 'accepted':0, 'rejected':0, 'skipped':0, 'error':0} for r in RESULTS}, 'execution_results':{'matched':0, 'mismatched':0, 'acceptable':0, 'skipped':0, 'error':0}, 'cases':[], 'diagnostics':[], 'limits':asdict(limits), 'library_overall_security':'OPEN', 'application_eligibility':'OPEN', 'vulnerability_discovery':'NOT_ESTABLISHED'}


def _diagnostic(report, code, location='$', position=None):
    item = {'code':code, 'location':location}
    if position is not None:
        item['position'] = position
    report['diagnostics'].append(item)


def _finish(report, limits):
    fail = report['execution_results']['mismatched'] > 0
    opened = bool(report['diagnostics']) or not report['execution_complete'] or report['execution_results']['skipped'] > 0 or report['execution_results']['error'] > 0 or report['corpus']['identity'] != 'FIXED_OFFICIAL_BYTES'
    report['status'] = 'FAIL' if fail else ('OPEN' if opened else 'PASS')
    if len(json.dumps(report, ensure_ascii=True, separators=(',', ':')).encode()) > limits.report_bytes:
        report['cases'] = next(([c] for c in report['cases'] if c['outcome'] == 'mismatched'), [])
        report['detail_complete'] = False
        _diagnostic(report, 'report_limit')
        if not fail:
            report['status'] = 'OPEN'
    return report


def argument_report():
    """Fixed private CLI error, without attempting corpus or library access."""
    limits = Limits()
    report = _base(limits)
    _diagnostic(report, 'invalid_arguments')
    return _finish(report, limits)


def run_vectors(path=None, *, limits=None):
    if limits is None:
        limits = Limits()
    elif type(limits) is not Limits:
        raise TypeError('limits must be Limits or None')
    limits.validate()
    report = _base(limits)
    if path is None:
        path = Path(__file__).parent / 'data' / 'aes_gcm_test.json'
    try:
        data = read_local(path, limits)
        digest = sha256(data).hexdigest()
        report['corpus'].update({'sha256':digest, 'bytes':len(data), 'identity':'FIXED_OFFICIAL_BYTES' if digest == CORPUS_SHA256 else 'UNVERIFIED_LOCAL_BYTES'})
        corpus = parse_corpus(data, limits)
    except Problem as exc:
        _diagnostic(report, exc.code, exc.location, exc.position)
        return _finish(report, limits)
    report['schema_complete'] = True
    report['counts'].update({'groups':corpus.groups, 'cases':len(corpus.cases)})
    if not corpus.notes_known:
        _diagnostic(report, 'unknown_note_flags', '$.notes')
    for case in corpus.cases:
        report['expected_results'][case.expected]['total'] += 1
    try:
        adapter = Adapter()
        report['library'].update({'actual_version':adapter.version, 'openssl_backend':adapter.openssl, 'python_version':platform.python_version(), 'platform':sys.platform, 'status':'READY' if adapter.ready else 'VERSION_MISMATCH'})
    except Exception:
        adapter = None
        report['library']['status'] = 'ADAPTER_INITIALIZATION_ERROR'
    execution_gap = False
    for case in corpus.cases:
        item = {'tcId':case.tc_id, 'group_index':case.group, 'case_index':case.index, 'location':case.location, 'expected':case.expected, 'outcome':'error', 'decryption':'not_run', 'encryption':'not_run', 'operations':0, 'code':'adapter_error'}
        if not corpus.algorithm_supported:
            item.update(outcome='skipped', code='unsupported_algorithm')
        elif not case.flags_known:
            item.update(outcome='skipped', code='unknown_flags')
        elif adapter is None or not adapter.ready:
            item['code'] = 'adapter_initialization_or_version_error'
        else:
            unsupported = adapter.support(case)
            required = 1 if case.expected == 'invalid' else 2
            if unsupported:
                item.update(outcome='skipped', code=unsupported)
            elif report['counts']['operations'] + required > limits.operations:
                item.update(outcome='skipped', code='operation_limit')
            else:
                try:
                    observed = adapter.observe(case)
                    if type(observed) is not Observation or observed.decrypted not in ('matching','mismatching','tag_rejected','parameter_rejected','error') or observed.encrypted not in ('matching','mismatching','not_run','error') or type(observed.operations) is not int or not 0 <= observed.operations <= required:
                        raise ValueError('invalid adapter observation')
                    if observed.decrypted == 'parameter_rejected' and (case.iv or case.expected != 'invalid'):
                        raise ValueError('unexpected parameter rejection')
                except Exception:
                    observed = Observation('error', 'not_run', 0)
                    report['operation_count_complete'] = False
                item.update(decryption=observed.decrypted, encryption=observed.encrypted, operations=observed.operations)
                if 'error' in (observed.decrypted, observed.encrypted):
                    item['code'] = 'adapter_operation_error'
                elif case.expected == 'invalid':
                    rejected = observed.decrypted in ('tag_rejected', 'parameter_rejected')
                    item.update(outcome='matched' if rejected else 'mismatched', code='expected_rejection' if rejected else 'unexpected_acceptance')
                elif case.expected == 'valid':
                    match = observed.decrypted == observed.encrypted == 'matching'
                    item.update(outcome='matched' if match else 'mismatched', code='expected_outputs' if match else 'unexpected_rejection_or_output')
                elif observed.encrypted == 'mismatching':
                    item.update(outcome='mismatched', code='unexpected_acceptable_output')
                elif observed.decrypted in ('tag_rejected', 'parameter_rejected'):
                    item.update(outcome='acceptable', code='acceptable_rejection')
                else:
                    match = observed.decrypted == observed.encrypted == 'matching'
                    item.update(outcome='acceptable' if match else 'mismatched', code='acceptable_acceptance' if match else 'unexpected_acceptable_output')
        report['cases'].append(item)
        outcome = item['outcome']
        report['counts']['operations'] += item['operations']
        report['execution_results'][outcome] += 1
        bucket = report['expected_results'][case.expected]
        if outcome == 'acceptable':
            bucket['rejected' if item['code'] == 'acceptable_rejection' else 'accepted'] += 1
        else:
            bucket[outcome] += 1
        if outcome in ('error', 'skipped'):
            execution_gap = True
    report['execution_complete'] = not execution_gap
    return _finish(report, limits)
