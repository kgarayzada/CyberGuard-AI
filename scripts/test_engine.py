"""Scoring and normalization tests. Every value here is synthetic."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.engine import REMEDIATION, SEVERITIES, normalize, now, security_score

PLAIN = {'id': 'assessment-one'}
LOADED = {'id': 'assessment-two', 'environment': 'Production', 'criticality': 'Critical'}


def finding(assessment=PLAIN, severity='HIGH', category='SQL Injection', **extra):
    return normalize(assessment, 'Semgrep', 'rule-id', 'A title', severity, category,
                     'src/app.py', 7, 7, **extra)


class Severity(unittest.TestCase):
    def test_known_severities_are_upper_cased(self):
        for value in ('critical', 'High', 'medium', 'LOW', 'unknown'):
            with self.subTest(value=value):
                self.assertEqual(finding(severity=value)['severity'], value.upper())

    def test_unsupported_words_become_unknown(self):
        # An advisory vocabulary this engine does not model must never be guessed at.
        for value in ('MODERATE', 'SEVERE', 'INFO', '', None):
            with self.subTest(value=value):
                self.assertEqual(finding(severity=value)['severity'], 'UNKNOWN')

    def test_baseline_points_per_severity(self):
        expected = {'CRITICAL': 75, 'HIGH': 60, 'MEDIUM': 35, 'LOW': 15, 'UNKNOWN': 25}
        for severity, points in expected.items():
            with self.subTest(severity=severity):
                factors = finding(severity=severity)['risk_factors']
                self.assertEqual(factors[0]['value'], points)
                self.assertEqual(factors[0]['source'], 'Scanner-derived')


class RiskFactors(unittest.TestCase):
    def labels(self, f):
        return [x['label'] for x in f['risk_factors']]

    def test_scanner_factors_accumulate(self):
        self.assertEqual(finding(severity='HIGH')['contextual_risk_score'], 60)
        self.assertEqual(finding(severity='HIGH', confidence='HIGH')['contextual_risk_score'], 65)
        self.assertEqual(finding(severity='HIGH', category='Credential Exposure')['contextual_risk_score'], 75)
        self.assertEqual(finding(severity='MEDIUM', category='Vulnerable Dependency')['contextual_risk_score'], 40)

    def test_low_confidence_adds_nothing(self):
        for value in ('LOW', 'MEDIUM', None):
            with self.subTest(value=value):
                self.assertEqual(finding(confidence=value)['contextual_risk_score'], 60)

    def test_user_context_is_labelled_separately(self):
        f = finding(assessment=LOADED)
        user = [x for x in f['risk_factors'] if x['source'] == 'User-provided']
        self.assertEqual([x['value'] for x in user], [3, 8])
        self.assertEqual(f['contextual_risk_score'], 60 + 3 + 8)

    def test_low_criticality_contributes_no_factor(self):
        f = finding(assessment={'id': 'x', 'criticality': 'Low'})
        self.assertNotIn('Low business criticality', self.labels(f))
        self.assertEqual(f['contextual_risk_score'], 60)

    def test_non_production_environment_contributes_nothing(self):
        for environment in ('Development', 'Testing', 'Staging', None):
            with self.subTest(environment=environment):
                f = finding(assessment={'id': 'x', 'environment': environment})
                self.assertEqual(f['contextual_risk_score'], 60)

    def test_score_is_capped_at_one_hundred(self):
        f = finding(assessment=LOADED, severity='CRITICAL', category='Credential Exposure', confidence='HIGH')
        self.assertEqual(sum(x['value'] for x in f['risk_factors']), 106)
        self.assertEqual(f['contextual_risk_score'], 100)


class Fingerprints(unittest.TestCase):
    def test_user_context_does_not_change_the_fingerprint(self):
        # Two scans of the same code must dedupe even with different user context.
        self.assertEqual(finding(assessment=PLAIN)['fingerprint'],
                         finding(assessment=LOADED)['fingerprint'])

    def test_location_changes_the_fingerprint(self):
        base = finding()['fingerprint']
        moved = normalize(PLAIN, 'Semgrep', 'rule-id', 'A title', 'HIGH', 'SQL Injection', 'src/app.py', 9, 9)
        other_file = normalize(PLAIN, 'Semgrep', 'rule-id', 'A title', 'HIGH', 'SQL Injection', 'src/other.py', 7, 7)
        other_rule = normalize(PLAIN, 'Semgrep', 'other-rule', 'A title', 'HIGH', 'SQL Injection', 'src/app.py', 7, 7)
        self.assertEqual(len({base, moved['fingerprint'], other_file['fingerprint'], other_rule['fingerprint']}), 4)

    def test_package_version_participates(self):
        old = normalize(PLAIN, 'OSV dependency analysis', 'GHSA-x', 'summary', 'HIGH',
                        'Vulnerable Dependency', 'package.json', package='lodash', vulnerable_version='4.17.20')
        new = normalize(PLAIN, 'OSV dependency analysis', 'GHSA-x', 'summary', 'HIGH',
                        'Vulnerable Dependency', 'package.json', package='lodash', vulnerable_version='4.17.21')
        self.assertNotEqual(old['fingerprint'], new['fingerprint'])

    def test_id_is_scoped_to_the_assessment(self):
        f = finding()
        self.assertTrue(f['id'].startswith('assessment-one-'))
        self.assertEqual(f['id'], 'assessment-one-' + f['fingerprint'][:16])
        self.assertEqual(f['assessment_id'], 'assessment-one')


class Disclosure(unittest.TestCase):
    def test_evidence_is_always_withheld(self):
        for category in ('Credential Exposure', 'SQL Injection', 'Vulnerable Dependency'):
            with self.subTest(category=category):
                self.assertEqual(finding(category=category)['evidence'],
                                 '[REDACTED: source text withheld to prevent credential disclosure]')

    def test_long_text_is_truncated(self):
        f = normalize(PLAIN, 'Semgrep', 'rule', 'T' * 600, 'HIGH', 'SQL Injection', description='D' * 9000)
        self.assertEqual(len(f['title']), 500)
        self.assertEqual(len(f['description']), 8000)

    def test_description_falls_back_to_the_title(self):
        self.assertEqual(normalize(PLAIN, 'S', 'r', 'Only a title', 'LOW', 'X')['description'], 'Only a title')

    def test_only_plain_https_references_survive(self):
        kept = normalize(PLAIN, 'S', 'r', 't', 'LOW', 'X', references=[
            'https://osv.dev/vulnerability/GHSA-x',
            'https://example.test',
            'http://example.test/',
            'https://user@credentials.test/',
            'javascript:alert(1)',
            'not a url',
            None,
        ])['references']
        self.assertEqual(kept, ['https://osv.dev/vulnerability/GHSA-x', 'https://example.test'])

    def test_reference_list_is_bounded(self):
        many = ['https://example.test/%d' % i for i in range(25)]
        self.assertEqual(len(normalize(PLAIN, 'S', 'r', 't', 'LOW', 'X', references=many)['references']), 10)


class Remediation(unittest.TestCase):
    def test_known_categories_use_the_curated_text(self):
        for category, text in REMEDIATION.items():
            with self.subTest(category=category):
                self.assertEqual(finding(category=category)['remediation'], text)

    def test_unknown_category_falls_back(self):
        self.assertTrue(finding(category='Something New')['remediation'].startswith('Review the scanner rule'))

    def test_explicit_remediation_wins(self):
        self.assertEqual(finding(remediation='Do the thing.')['remediation'], 'Do the thing.')


class Score(unittest.TestCase):
    def risks(self, *values):
        return [{'contextual_risk_score': v} for v in values]

    def test_no_findings_scores_one_hundred(self):
        self.assertEqual(security_score([]), 100)

    def test_single_finding_uses_the_documented_formula(self):
        self.assertEqual(security_score(self.risks(60)), 58)   # 100 - .65*60 - 2.88
        self.assertEqual(security_score(self.risks(100)), 27)  # 100 - 65 - 8

    def test_a_dominant_finding_outweighs_a_minor_one(self):
        self.assertLess(security_score(self.risks(90)), security_score(self.risks(20)))

    def test_accumulation_lowers_the_score(self):
        self.assertLess(security_score(self.risks(60, 60)), security_score(self.risks(60)))

    def test_accumulated_penalty_is_bounded(self):
        # 100 maximal findings: 65 from the worst plus the 35-point accumulation cap.
        self.assertEqual(security_score(self.risks(*([100] * 100))), 0)

    def test_score_stays_in_range(self):
        for case in ([0], [100], [1] * 500, [100] * 500, [37, 42, 99]):
            with self.subTest(case=case[:3]):
                self.assertTrue(0 <= security_score(self.risks(*case)) <= 100)


class Metadata(unittest.TestCase):
    def test_findings_start_open(self):
        self.assertEqual(finding()['status'], 'OPEN')

    def test_timestamps_are_utc_iso8601(self):
        self.assertTrue(now().endswith('+00:00'))
        self.assertEqual(finding()['created_at'][:4], now()[:4])

    def test_every_severity_constant_is_modelled(self):
        for severity in SEVERITIES:
            with self.subTest(severity=severity):
                self.assertEqual(finding(severity=severity)['severity'], severity)


if __name__ == '__main__':
    unittest.main()
