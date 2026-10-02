import copy
from dataclasses import replace
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.request
from crypto_regression_bench import Limits, run_vectors
from crypto_regression_bench.adapter import Adapter, Observation
from crypto_regression_bench.cli import main
from crypto_regression_bench.runner import CORPUS_SHA256


def official():
    from crypto_regression_bench import runner
    return json.loads((Path(runner.__file__).parent/'data/aes_gcm_test.json').read_bytes())


def fixture():
    data=official()
    data['testGroups']=[copy.deepcopy(data['testGroups'][0])]
    data['testGroups'][0]['tests']=[copy.deepcopy(data['testGroups'][0]['tests'][0])]
    data['numberOfTests']=1
    return data


def flip(value):
    data=bytearray.fromhex(value)
    data[0]^=1
    return data.hex()


class BenchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.path=self.root/'private-input.json'

    def run_data(self,data,limits=None):
        raw=data if isinstance(data,bytes) else json.dumps(data).encode()
        self.path.write_bytes(raw)
        r=run_vectors(self.path,limits=limits)
        self.assertEqual(self.path.read_bytes(),raw)
        self.assertEqual(r['library_overall_security'],'OPEN')
        self.assertEqual(r['application_eligibility'],'OPEN')
        self.assertNotIn(str(self.path),json.dumps(r))
        return r

    def one(self,data=None):
        r=self.run_data(data or fixture())
        self.assertEqual(r['status'],'OPEN') # local edited bytes not pinned provenance
        self.assertEqual(len(r['cases']),1)
        return r['cases'][0]

    def issue(self,data,code,limits=None):
        r=self.run_data(data,limits)
        self.assertEqual(r['status'],'OPEN')
        self.assertIn(code,{d['code'] for d in r['diagnostics']})
        self.assertFalse(r['schema_complete'])
        self.assertEqual(r['counts']['operations'],0)
        return r

    def test_complete_official_corpus_and_each_test_id(self):
        r=run_vectors()
        self.assertEqual(r['corpus']['sha256'],CORPUS_SHA256)
        self.assertEqual(r['corpus']['identity'],'FIXED_OFFICIAL_BYTES')
        self.assertTrue(r['schema_complete']);self.assertFalse(r['execution_complete'])
        self.assertEqual(r['status'],'OPEN')
        self.assertEqual(r['counts'],{'groups':45,'cases':316,'operations':491})
        self.assertEqual(r['execution_results'],{'matched':289,'mismatched':0,'acceptable':0,'skipped':27,'error':0})
        self.assertEqual(r['expected_results']['valid']['total'],229)
        self.assertEqual(r['expected_results']['valid']['matched'],202)
        self.assertEqual(r['expected_results']['invalid']['matched'],87)
        self.assertEqual(r['expected_results']['acceptable']['total'],0)
        self.assertEqual(len({c['tcId'] for c in r['cases']}),316)
        self.assertEqual({c['tcId'] for c in r['cases']},set(range(1,317)))
        self.assertEqual(sum(c['operations'] for c in r['cases']),491)
        for expected,b in r['expected_results'].items():
            self.assertEqual(b['total'],sum(v for k,v in b.items() if k!='total'))
        self.assertEqual(sum(r['execution_results'].values()),316)

    def test_copied_official_bytes_have_same_repeatable_report(self):
        from crypto_regression_bench import runner
        source=Path(runner.__file__).parent/'data/aes_gcm_test.json'
        self.path.write_bytes(source.read_bytes());before=sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(run_vectors(),run_vectors(self.path))
        self.assertEqual(run_vectors(),run_vectors())
        self.assertEqual(sha256(self.path.read_bytes()).hexdigest(),before)

    def test_valid_really_encrypts_and_decrypts(self):
        adapter=Adapter();real=adapter.aesgcm
        calls=[]
        class Wrapped:
            def __init__(self,key):self.cipher=real(key)
            def decrypt(self,*args):calls.append('decrypt');return self.cipher.decrypt(*args)
            def encrypt(self,*args):calls.append('encrypt');return self.cipher.encrypt(*args)
        adapter.aesgcm=Wrapped
        with mock.patch('crypto_regression_bench.runner.Adapter',return_value=adapter):
            c=self.one()
        self.assertEqual(c['outcome'],'matched');self.assertEqual(c['decryption'],'matching');self.assertEqual(c['encryption'],'matching')
        self.assertEqual(calls,['decrypt','encrypt'])

    def test_actual_invalid_tag_contrast(self):
        d=fixture();t=d['testGroups'][0]['tests'][0];t['tag']=flip(t['tag']);t['result']='invalid'
        c=self.one(d)
        self.assertEqual(c['outcome'],'matched');self.assertEqual(c['decryption'],'tag_rejected');self.assertEqual(c['operations'],1)

    def test_mutated_valid_tag_is_failure_not_crypto_error(self):
        d=fixture();t=d['testGroups'][0]['tests'][0];t['tag']=flip(t['tag'])
        r=self.run_data(d);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['execution_results']['mismatched'],1)
        self.assertEqual(r['cases'][0]['decryption'],'tag_rejected')

    def test_expected_plaintext_is_compared(self):
        d=fixture();t=d['testGroups'][0]['tests'][0];t['msg']=flip(t['msg'])
        r=self.run_data(d);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['cases'][0]['decryption'],'mismatching');self.assertEqual(r['cases'][0]['encryption'],'mismatching')

    def test_expected_ciphertext_encryption_is_compared(self):
        d=fixture();t=d['testGroups'][0]['tests'][0];t['ct']=flip(t['ct'])
        r=self.run_data(d);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['cases'][0]['encryption'],'mismatching')

    def test_invalid_that_decrypts_is_failure(self):
        d=fixture();d['testGroups'][0]['tests'][0]['result']='invalid'
        r=self.run_data(d);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['cases'][0]['code'],'unexpected_acceptance')

    def test_acceptable_real_acceptance_and_rejection_are_separate(self):
        for reject in (False,True):
            d=fixture();t=d['testGroups'][0]['tests'][0];t['result']='acceptable'
            if reject:t['tag']=flip(t['tag'])
            r=self.run_data(d);self.assertEqual(r['status'],'OPEN');self.assertEqual(r['execution_results']['acceptable'],1)
            self.assertEqual(r['expected_results']['acceptable']['rejected' if reject else 'accepted'],1)
            self.assertEqual(r['execution_results']['mismatched'],0)
            if reject:self.assertEqual(r['cases'][0]['encryption'],'not_run')

    def test_acceptable_decrypt_rejection_with_matching_encryption(self):
        d=fixture();d['testGroups'][0]['tests'][0]['result']='acceptable'
        with mock.patch.object(Adapter,'observe',return_value=Observation('tag_rejected','matching',2)):
            r=self.run_data(d)
        self.assertEqual(r['execution_results']['acceptable'],1)
        self.assertEqual(r['expected_results']['acceptable']['rejected'],1)
        self.assertEqual(r['status'],'OPEN')

    def test_acceptable_output_mismatch_is_failure(self):
        d=fixture();d['testGroups'][0]['tests'][0]['result']='acceptable'
        for observed in [Observation('mismatching','matching',2),Observation('tag_rejected','mismatching',2)]:
            with mock.patch.object(Adapter,'observe',return_value=observed):r=self.run_data(d)
            self.assertEqual(r['status'],'FAIL');self.assertEqual(r['execution_results']['mismatched'],1)

    def test_known_zero_nonce_invalid_executes_api_rejection(self):
        d=fixture();g=d['testGroups'][0];g['ivSize']=0;t=g['tests'][0];t['iv']='';t['result']='invalid'
        c=self.one(d);self.assertEqual(c['decryption'],'parameter_rejected');self.assertEqual(c['outcome'],'matched');self.assertEqual(c['operations'],1)

    def test_nonce_tag_and_key_unsupported_are_skipped(self):
        for field,size,value in [('ivSize',8,'iv'),('ivSize',1032,'iv'),('tagSize',96,'tag'),('keySize',64,'key')]:
            d=fixture();g=d['testGroups'][0];g[field]=size;g['tests'][0][value]='00'*(size//8)
            with mock.patch.object(Adapter,'observe',side_effect=AssertionError('must not run')):c=self.one(d)
            self.assertEqual(c['outcome'],'skipped');self.assertEqual(c['operations'],0)

    def test_zero_nonce_valid_is_skipped_not_failed(self):
        d=fixture();g=d['testGroups'][0];g['ivSize']=0;g['tests'][0]['iv']=''
        self.assertEqual(self.one(d)['outcome'],'skipped')

    def test_unsupported_algorithm_skips_all_with_tc_id(self):
        d=fixture();d['algorithm']='unsupported-private-name'
        c=self.one(d);self.assertEqual(c['tcId'],1);self.assertEqual(c['code'],'unsupported_algorithm');self.assertEqual(c['outcome'],'skipped')

    def test_adapter_valueerror_and_unexpected_errors_not_invalid_rejection(self):
        for expected in ('valid','invalid','acceptable'):
            d=fixture();d['testGroups'][0]['tests'][0]['result']=expected
            for exc in (ValueError('private-secret'),RuntimeError('private-secret')):
                adapter=Adapter();adapter.aesgcm=mock.Mock(side_effect=exc)
                with mock.patch('crypto_regression_bench.runner.Adapter',return_value=adapter):r=self.run_data(d)
                self.assertEqual(r['status'],'OPEN');self.assertEqual(r['execution_results']['error'],1);self.assertEqual(r['execution_results']['matched'],0)
                self.assertNotIn('private-secret',json.dumps(r))

    def test_adapter_initialization_and_version_mismatch_are_errors(self):
        with mock.patch('crypto_regression_bench.runner.Adapter',side_effect=ImportError('private')):r=self.run_data(fixture())
        self.assertEqual(r['execution_results']['error'],1)
        adapter=Adapter();adapter.ready=False;adapter.version='different-test-version'
        with mock.patch('crypto_regression_bench.runner.Adapter',return_value=adapter):r=self.run_data(fixture())
        self.assertEqual(r['execution_results']['error'],1);self.assertEqual(r['counts']['operations'],0);self.assertEqual(r['library']['status'],'VERSION_MISMATCH')

    def test_constructor_error_zero_iv_is_not_successful_invalid_rejection(self):
        d=fixture();g=d['testGroups'][0];g['ivSize']=0;t=g['tests'][0];t['iv']='';t['result']='invalid'
        adapter=Adapter();adapter.aesgcm=mock.Mock(side_effect=ValueError('private'))
        with mock.patch('crypto_regression_bench.runner.Adapter',return_value=adapter):r=self.run_data(d)
        self.assertEqual(r['execution_results']['error'],1);self.assertEqual(r['execution_results']['matched'],0);self.assertEqual(r['counts']['operations'],0)

    def test_adapter_invalid_observation_and_unexpected_parameter_rejection(self):
        d=fixture();d['testGroups'][0]['tests'][0]['result']='invalid'
        for value in (None,Observation('parameter_rejected','not_run',1),Observation('matching','not_run',True)):
            with mock.patch.object(Adapter,'observe',return_value=value):r=self.run_data(d)
            self.assertEqual(r['execution_results']['error'],1);self.assertFalse(r['operation_count_complete'])

    def test_actual_whole_corpus_operation_count_is_instrumented(self):
        adapter=Adapter();real=adapter.aesgcm;calls=[]
        class Wrapped:
            def __init__(self,key):self.cipher=real(key)
            def decrypt(self,*args):calls.append('decrypt');return self.cipher.decrypt(*args)
            def encrypt(self,*args):calls.append('encrypt');return self.cipher.encrypt(*args)
        adapter.aesgcm=Wrapped
        with mock.patch('crypto_regression_bench.runner.Adapter',return_value=adapter):r=run_vectors()
        self.assertEqual(calls.count('decrypt'),289);self.assertEqual(calls.count('encrypt'),202)
        self.assertEqual(len(calls),r['counts']['operations']);self.assertTrue(r['operation_count_complete'])

    def test_json_depth_scan_ignores_escaped_quotes_and_brackets_in_strings(self):
        d=fixture();d['header']=['[[[{{{'+chr(34)+'[[[{{{'+chr(92)+'private']
        self.assertEqual(self.one(d)['outcome'],'matched')

    def test_whole_adapter_failure_retains_error(self):
        with mock.patch.object(Adapter,'observe',side_effect=RuntimeError('private')):r=self.run_data(fixture())
        self.assertEqual(r['status'],'OPEN');self.assertEqual(r['execution_results']['error'],1)

    def test_nonbyte_library_return_is_error(self):
        adapter=Adapter();adapter.aesgcm=mock.Mock(return_value=mock.Mock(decrypt=mock.Mock(return_value=None)))
        with mock.patch('crypto_regression_bench.runner.Adapter',return_value=adapter):r=self.run_data(fixture())
        self.assertEqual(r['execution_results']['error'],1)

    def test_unknown_flags_not_accepted_even_if_notes_describe_them(self):
        d=fixture();d['testGroups'][0]['tests'][0]['flags']=['private-unknown'];d['notes']['private-unknown']={'bugType':'BASIC'}
        c=self.one(d);self.assertEqual(c['outcome'],'skipped');self.assertEqual(c['code'],'unknown_flags')
        r=self.run_data(d);self.assertIn('unknown_note_flags',{x['code'] for x in r['diagnostics']});self.assertNotIn('private-unknown',json.dumps(r))

    def test_missing_known_note_makes_flag_open(self):
        d=fixture();d['notes']={}
        self.assertEqual(self.one(d)['code'],'unknown_flags')

    def test_unknown_schema_group_and_expected_are_open_no_execution(self):
        d=fixture();d['schema']='private-schema';self.issue(d,'unsupported_schema')
        d=fixture();d['testGroups'][0]['type']='other';self.issue(d,'unsupported_group_type')
        d=fixture();d['testGroups'][0]['tests'][0]['result']='other';self.issue(d,'unsupported_expected_result')

    def test_duplicate_json_keys_and_nonfinite_numbers(self):
        self.issue(b'{"schema":1,"schema":2}','duplicate_json_key')
        self.issue(b'{"private":NaN}','nonfinite_json_number')

    def test_duplicate_tc_id_declared_count_and_duplicate_flags(self):
        d=fixture();d['testGroups'][0]['tests']*=2;d['numberOfTests']=2;self.issue(d,'duplicate_tc_id')
        d=fixture();d['numberOfTests']=2;self.issue(d,'declared_count_mismatch')
        d=fixture();d['testGroups'][0]['tests'][0]['flags']=['Ktv','Ktv'];self.issue(d,'duplicate_flag')

    def test_strict_unknown_fields_and_missing_fields(self):
        for loc in ('root','group','case','source','note'):
            for remove in (False,True):
                d=fixture();g=d['testGroups'][0]
                obj={'root':d,'group':g,'case':g['tests'][0],'source':g['source'],'note':d['notes']['Ktv']}[loc]
                if remove:obj.pop(next(iter(obj)))
                else:obj['private-unknown']='private-secret'
                self.issue(d,'object_shape')

    def test_strict_integer_fields_reject_bool_string_negative(self):
        for value in (True,'1',-1,0,1.5):
            d=fixture();d['numberOfTests']=value;self.issue(d,'integer_shape')
            d=fixture();d['testGroups'][0]['tests'][0]['tcId']=value;self.issue(d,'integer_shape')
        d=fixture();d['testGroups'][0]['ivSize']=95;self.issue(d,'nonbyte_bit_size')

    def test_hex_rejects_whitespace_odd_and_nonhex_with_location(self):
        for value in ('0','00 11','private','zz'):
            d=fixture();d['testGroups'][0]['tests'][0]['key']=value;r=self.issue(d,'invalid_hex')
            self.assertEqual(r['diagnostics'][0]['location'],'$.testGroups[0].tests[0].key')
            if value=='private':self.assertNotIn(value,json.dumps(r))

    def test_group_bit_width_and_aead_length_are_verified(self):
        d=fixture();d['testGroups'][0]['keySize']=256;self.issue(d,'group_size_mismatch')
        d=fixture();d['testGroups'][0]['tests'][0]['ct']='';self.issue(d,'aead_length_profile')

    def test_json_utf8_truncation_and_empty_are_open(self):
        for raw,code in [(b'','json_syntax'),(b'\xff','utf8_error'),(b'{','json_syntax'),(b'[]','object_shape'),(b'{}','object_shape')]:self.issue(raw,code)
        r=self.issue(b'{"private":\n','json_syntax');self.assertEqual(r['diagnostics'][0]['position']['line'],2)

    def test_all_limits_are_effective(self):
        d=fixture()
        cases=[('input_bytes',10,'input_limit'),('nesting',2,'nesting_limit'),('json_nodes',2,'json_node_limit'),('string_chars',2,'string_limit'),('field_bytes',1,'integer_shape'),('decoded_bytes',1,'decoded_limit')]
        for name,value,code in cases:
            with self.subTest(name=name):self.issue(d,code,replace(Limits(),**{name:value}))
        two=fixture();two['testGroups'].append(copy.deepcopy(two['testGroups'][0]));two['testGroups'][1]['tests'][0]['tcId']=2;two['numberOfTests']=2
        self.issue(two,'group_limit_or_shape',replace(Limits(),groups=1))
        self.issue(two,'integer_shape',replace(Limits(),cases=1))
        r=self.run_data(fixture(),replace(Limits(),operations=1));self.assertEqual(r['cases'][0]['code'],'operation_limit');self.assertEqual(r['counts']['operations'],0)

    def test_field_limit_on_non_group_aad(self):
        d=fixture();d['testGroups'][0]['tests'][0]['aad']='00'*33
        self.issue(d,'field_limit',replace(Limits(),field_bytes=32))

    def test_case_budget_and_empty_group_no_clean_result(self):
        d=fixture();d['testGroups'][0]['tests']=[];self.issue(d,'test_array_shape')
        d=fixture();d['testGroups']=[];self.issue(d,'group_limit_or_shape')
        d=fixture();d['testGroups'][0]['tests']*=2
        self.issue(d,'case_limit',replace(Limits(),cases=1))

    def test_report_budget_preserves_first_failure_and_truthful_totals(self):
        d=fixture();t=d['testGroups'][0]['tests'][0];t['tag']=flip(t['tag'])
        tests=[copy.deepcopy(t) for _ in range(30)]
        for i,t in enumerate(tests):t['tcId']=i+1
        d['testGroups'][0]['tests']=tests;d['numberOfTests']=30
        r=self.run_data(d,replace(Limits(),report_bytes=4096));self.assertEqual(r['status'],'FAIL');self.assertFalse(r['detail_complete']);self.assertEqual(r['execution_results']['mismatched'],30);self.assertEqual(len(r['cases']),1);self.assertEqual(r['cases'][0]['tcId'],1)
        self.assertLessEqual(len(json.dumps(r,separators=(',',':')).encode()),4096)
        d=official();r=self.run_data(d,replace(Limits(),report_bytes=4096));self.assertEqual(r['status'],'OPEN');self.assertEqual(r['counts']['cases'],316)

    def test_bad_limits_types_are_rejected(self):
        for bad in (False,0,{},[], ''):
            with self.assertRaises(TypeError):run_vectors(self.path,limits=bad)
        for limits in (replace(Limits(),cases=True),replace(Limits(),cases=0),replace(Limits(),cases=2049),replace(Limits(),report_bytes=1)):
            with self.assertRaises(ValueError):run_vectors(self.path,limits=limits)

    def test_local_only_paths_symlink_fifo_and_directories(self):
        self.path.write_text('{}');link=self.root/'link';link.symlink_to(self.path);fifo=self.root/'fifo';os.mkfifo(fifo)
        for path in ('-','@private-list','https://private.invalid/test.json',self.root,self.root/'absent',link,fifo,b'bytes'):
            r=run_vectors(path);self.assertEqual(r['status'],'OPEN');self.assertFalse(r['schema_complete']);self.assertEqual(r['counts']['operations'],0)

    def test_changing_snapshot_and_private_exceptions_open(self):
        self.path.write_text('{}')
        real=os.fstat;calls=[]
        def changing(fd):
            s=real(fd);calls.append(s)
            if len(calls)==1:return s
            class Changed:
                st_dev=s.st_dev;st_ino=s.st_ino;st_size=s.st_size;st_mtime_ns=s.st_mtime_ns+1;st_ctime_ns=s.st_ctime_ns
            return Changed()
        with mock.patch('crypto_regression_bench.runner.os.fstat',side_effect=changing):r=run_vectors(self.path)
        self.assertEqual(r['diagnostics'][0]['code'],'input_changed')
        with mock.patch('crypto_regression_bench.runner.os.open',side_effect=OSError('private-secret')):r=run_vectors(self.path)
        self.assertNotIn('private-secret',json.dumps(r))

    def test_report_does_not_emit_raw_vector_or_private_metadata(self):
        d=fixture();g=d['testGroups'][0];g['source']['name']='private-source';t=g['tests'][0];t['comment']='private-comment'
        r=self.run_data(d);text=json.dumps(r)
        for value in [t[k] for k in ('key','iv','aad','msg','ct','tag') if t[k]]+['private-source','private-comment']:self.assertNotIn(value,text)

    def test_no_network_process_input_code_or_external_schema(self):
        d=fixture();d['header']=['__import__("os").system("private-command")']
        with mock.patch.object(socket,'create_connection',side_effect=AssertionError('network')),mock.patch.object(urllib.request,'urlopen',side_effect=AssertionError('url')),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('process')):
            self.assertEqual(self.one(d)['outcome'],'matched')

    def test_cli_actual_statuses_version_and_removed_options(self):
        for data,exit_code in [(fixture(),2),(None,2)]:
            if data:self.path.write_text(json.dumps(data))
            with mock.patch('sys.stdout',new_callable=io.StringIO) as out:
                self.assertEqual(main([str(self.path)] if data else []),exit_code);self.assertEqual(json.loads(out.getvalue())['status'],'OPEN')
        d=fixture();d['testGroups'][0]['tests'][0]['tag']=flip(d['testGroups'][0]['tests'][0]['tag']);self.path.write_text(json.dumps(d))
        with mock.patch('sys.stdout',new_callable=io.StringIO):self.assertEqual(main([str(self.path)]),1)
        for flag in ('--download','--update','--plugin','--output','--algorithm','--vector-url'):
            with mock.patch('sys.stdout',new_callable=io.StringIO) as out, mock.patch('sys.stderr',new_callable=io.StringIO) as err:
                self.assertEqual(main([flag]),2)
            self.assertEqual(json.loads(out.getvalue())['status'],'OPEN')
            self.assertEqual(err.getvalue(),'')

    def test_private_cli_argument_errors_have_fixed_json_without_execution(self):
        for args in [['--private-argument-marker'], ['private-path', 'private-extra'],
                     ['--output=private-output-path']]:
            with mock.patch('sys.stdout',new_callable=io.StringIO) as out, mock.patch('sys.stderr',new_callable=io.StringIO) as err, mock.patch('crypto_regression_bench.runner.Adapter',side_effect=AssertionError('must not initialize')):
                self.assertEqual(main(args),2)
            report=json.loads(out.getvalue())
            self.assertEqual(report['status'],'OPEN')
            self.assertEqual(report['counts']['operations'],0)
            self.assertEqual(report['diagnostics'][0]['code'],'invalid_arguments')
            self.assertEqual(report['application_eligibility'],'OPEN')
            self.assertEqual(err.getvalue(),'')
            self.assertNotIn('private-',out.getvalue())

    def test_unencodable_local_path_is_private_open(self):
        with mock.patch('crypto_regression_bench.runner.Adapter',side_effect=AssertionError('must not initialize')):
            report=run_vectors('\ud800')
        self.assertEqual(report['status'],'OPEN')
        self.assertEqual(report['diagnostics'][0]['code'],'input_io_error')
        self.assertEqual(report['counts']['operations'],0)
        self.assertFalse(report['schema_complete'])


if __name__=='__main__':unittest.main()
