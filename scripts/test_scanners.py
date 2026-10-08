"""Scanner adapter tests: no real scanner binary and no network access are required."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.engine import SEVERITIES
from backend.scanners import (ROOT, advisory_severity, command, dependencies, run_local,
                              run_osv, safe_path)


class AdvisorySeverity(unittest.TestCase):
    def test_advisory_vocabulary_is_translated(self):
        # OSV returns GitHub's wording, where MODERATE is what this engine calls MEDIUM.
        self.assertEqual(advisory_severity('CRITICAL'), 'CRITICAL')
        self.assertEqual(advisory_severity('HIGH'), 'HIGH')
        self.assertEqual(advisory_severity('MODERATE'), 'MEDIUM')
        self.assertEqual(advisory_severity('MEDIUM'), 'MEDIUM')
        self.assertEqual(advisory_severity('LOW'), 'LOW')

    def test_casing_and_padding_are_tolerated(self):
        for value in ('moderate', ' Moderate ', 'MoDeRaTe'):
            with self.subTest(value=value):
                self.assertEqual(advisory_severity(value), 'MEDIUM')

    def test_missing_or_unrecognised_severity_stays_unknown(self):
        for value in (None, '', '   ', 'SEVERE', 'informational', 0):
            with self.subTest(value=value):
                self.assertEqual(advisory_severity(value), 'UNKNOWN')

    def test_every_result_is_a_modelled_severity(self):
        for value in ('CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'nonsense', None):
            with self.subTest(value=value):
                self.assertIn(advisory_severity(value), SEVERITIES)


class SafePath(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'source'
        self.workspace.mkdir()

    def test_absolute_path_inside_the_workspace_becomes_relative(self):
        self.assertEqual(safe_path(str(self.workspace / 'app' / 'main.py'), self.workspace), 'app/main.py')

    def test_absolute_path_outside_the_workspace_is_dropped(self):
        self.assertIsNone(safe_path(str(self.root / 'elsewhere.py'), self.workspace))

    def test_relative_path_is_normalised_to_posix(self):
        self.assertEqual(safe_path('app\\main.py' if os.name == 'nt' else 'app/main.py', self.workspace),
                         'app/main.py')

    def test_traversal_is_dropped(self):
        self.assertIsNone(safe_path('../escape.py', self.workspace))
        self.assertIsNone(safe_path('app/../../escape.py', self.workspace))


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)

    def write(self, relative, content):
        target = self.workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')

    def test_exact_npm_versions_are_collected(self):
        self.write('package.json', json.dumps({
            'dependencies': {'lodash': '4.17.20', 'react': '19.2.0'},
            'devDependencies': {'vite': '7.1.12'},
        }))
        packages, skipped = dependencies(self.workspace)
        self.assertEqual([(e, n, v) for e, n, v, _ in packages],
                         [('npm', 'lodash', '4.17.20'), ('npm', 'react', '19.2.0'), ('npm', 'vite', '7.1.12')])
        self.assertEqual(skipped, 0)

    def test_ranges_and_tags_are_skipped_not_guessed(self):
        self.write('package.json', json.dumps({
            'dependencies': {'a': '^4.17.0', 'b': '~1.0.0', 'c': '>=2.0.0', 'd': 'latest', 'e': '1.0'},
        }))
        packages, skipped = dependencies(self.workspace)
        self.assertEqual(packages, [])
        self.assertEqual(skipped, 5)

    def test_prerelease_pins_are_supported(self):
        self.write('package.json', json.dumps({'dependencies': {'pkg': '1.0.0-beta.1'}}))
        packages, skipped = dependencies(self.workspace)
        self.assertEqual([n for _, n, _, _ in packages], ['pkg'])
        self.assertEqual(skipped, 0)

    def test_requirements_pins_are_collected(self):
        self.write('requirements.txt', '\n'.join([
            '# comment line',
            '',
            'fastapi==0.135.1',
            '  uvicorn==0.41.0  ',
            'python-multipart==0.0.32',
        ]))
        packages, skipped = dependencies(self.workspace)
        self.assertEqual([(e, n, v) for e, n, v, _ in packages], [
            ('PyPI', 'fastapi', '0.135.1'),
            ('PyPI', 'python-multipart', '0.0.32'),
            ('PyPI', 'uvicorn', '0.41.0'),
        ])
        self.assertEqual(skipped, 0)

    def test_unpinned_requirements_are_counted_as_skipped(self):
        self.write('requirements.txt', 'uvicorn>=0.41.0\nfastapi\n-e .\n')
        packages, skipped = dependencies(self.workspace)
        self.assertEqual(packages, [])
        self.assertEqual(skipped, 3)

    def test_manifests_are_found_in_subdirectories_and_paths_are_relative(self):
        self.write('services/api/requirements.txt', 'fastapi==0.135.1\n')
        packages, _ = dependencies(self.workspace)
        self.assertEqual([p for _, _, _, p in packages], ['services/api/requirements.txt'])

    def test_unrelated_files_are_ignored(self):
        self.write('setup.py', 'install_requires=["requests==2.0.0"]')
        self.write('Pipfile', 'requests = "==2.0.0"')
        self.assertEqual(dependencies(self.workspace), ([], 0))

    def test_identical_entries_are_deduplicated(self):
        self.write('package.json', json.dumps({
            'dependencies': {'lodash': '4.17.20'},
            'devDependencies': {'lodash': '4.17.20'},
        }))
        packages, _ = dependencies(self.workspace)
        self.assertEqual(len(packages), 1)


class AdapterContracts(unittest.TestCase):
    def test_missing_binary_reports_unavailable_without_findings(self):
        with patch('backend.scanners.executable', return_value=Path('no-such-scanner')):
            for name in ('Semgrep', 'Gitleaks'):
                with self.subTest(name=name):
                    findings, status, message, version = run_local(name, {'id': 'x'}, Path('.'))
                    self.assertEqual(findings, [])
                    self.assertEqual(status, 'Unavailable')
                    self.assertIsNone(version)
                    self.assertIn(name, message)

    def test_dependency_lookup_disabled_is_skipped_not_failed(self):
        findings, status, message, version = run_osv({'dependency_lookup': False}, Path('.'))
        self.assertEqual(findings, [])
        self.assertEqual(status, 'Skipped')
        self.assertEqual(version, 'OSV API v1')
        self.assertIn('not enabled', message)

    def test_too_many_packages_warns_instead_of_failing(self):
        # A documented coverage limit must not be reported as a scanner failure.
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            pinned = {'pkg-%03d' % i: '1.0.%d' % i for i in range(101)}
            (workspace / 'package.json').write_text(json.dumps({'dependencies': pinned}), encoding='utf-8')
            findings, status, message, _ = run_osv({'dependency_lookup': True}, workspace)
        self.assertEqual(findings, [])
        self.assertEqual(status, 'Warning')
        self.assertIn('101', message)


class Subprocess(unittest.TestCase):
    def test_output_is_captured(self):
        code, out, err = command([sys.executable, '-c', 'print("scanner output")'], ROOT, 60)
        self.assertEqual(code, 0)
        self.assertIn('scanner output', out)
        self.assertEqual(err.strip(), '')

    def test_non_zero_exit_is_reported(self):
        code, _, _ = command([sys.executable, '-c', 'raise SystemExit(3)'], ROOT, 60)
        self.assertEqual(code, 3)

    def test_runaway_process_times_out(self):
        with self.assertRaises(TimeoutError):
            command([sys.executable, '-c', 'import time; time.sleep(60)'], ROOT, 2)

    def test_credential_environment_is_scrubbed(self):
        probe = 'import os;print(os.environ.get("SEMGREP_APP_TOKEN","ABSENT"),os.environ.get("GITLEAKS_CONFIG","ABSENT"))'
        with patch.dict(os.environ, {'SEMGREP_APP_TOKEN': 'synthetic-token', 'GITLEAKS_CONFIG': 'C:/evil.toml'}):
            _, out, _ = command([sys.executable, '-c', probe], ROOT, 60)
        self.assertEqual(out.split(), ['ABSENT', 'ABSENT'])

    def test_telemetry_is_disabled_for_children(self):
        probe = 'import os;print(os.environ.get("SEMGREP_SEND_METRICS"),os.environ.get("SEMGREP_ENABLE_VERSION_CHECK"))'
        _, out, _ = command([sys.executable, '-c', probe], ROOT, 60)
        self.assertEqual(out.split(), ['off', '0'])


if __name__ == '__main__':
    unittest.main()
