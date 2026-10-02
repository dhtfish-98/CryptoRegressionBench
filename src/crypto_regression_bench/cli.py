import argparse
import json
from . import __version__
from .runner import run_vectors


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline real AES-GCM library regression on a fixed bundled corpus or one explicit local JSON; no network or input execution.')
    parser.add_argument('corpus', nargs='?', help='Explicit local regular JSON file; default is fixed bundled official corpus')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    report = run_vectors(args.corpus)
    print(json.dumps(report, ensure_ascii=True, separators=(',', ':')))
    return {'PASS':0, 'FAIL':1, 'OPEN':2}[report['status']]
