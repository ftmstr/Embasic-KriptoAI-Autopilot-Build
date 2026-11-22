"""RC665 wholly invented, bounded hostile GitHub Actions log fixtures."""
import hashlib
import unittest
from safe_public_ci.ci_hosted_unittest_log_gate import (
    HostedLogRejected, verify_hosted_unittest_log,
)

P = '2026-11-09T01:02:03.1234567Z '
A = 'test_toy.Alpha.test_alpha'
B = 'test_toy.Beta.test_beta'
S = 'test_rc656_snapshot_package.RC656SnapshotTests.test_integrity_actual_public_source_files_without_export'
ROSTER = (A, B)
CMD = 'python -m unittest discover -s tests -v'
START = '##[group]Run ' + CMD
ANSI = '\x1b[36;1m' + CMD + '\x1b[0m'
END = '##[endgroup]'
TAIL = ('Post job cleanup.', 'Cleaning up orphan processes')


def digest_roster(ids):
    return hashlib.sha256('\n'.join(ids).encode('ascii')).hexdigest()


def fixture(ids=ROSTER, *, pre=('Current runner version: 2.338.2',),
            group=START, cmd=ANSI, safe='  SAFE_TEST_ONLY: 1',
            head_extra=(), outcome=None, tail=TAIL, extra=(), bom=False):
    body = [*pre, group, cmd, 'shell: /usr/bin/bash -e {0}', 'env:', safe,
            *head_extra, END]
    for identity in ids:
        method = identity.rsplit('.', 1)[-1]
        body.append('%s (%s) ... ok' % (method, identity))
    body.extend(outcome if outcome is not None else (
        '', '-' * 70,
        'Ran %d %s in 0.123s' % (len(ids), 'test' if len(ids) == 1 else 'tests'),
        '', 'OK'))
    body.extend(tail)
    body.extend(extra)
    return (('\ufeff' if bom else '') + '\n'.join(P + x for x in body) + '\n').encode('utf-8')


def run(raw=None, roster=ROSTER, *, expected_log=None, expected_roster=None):
    if raw is None:
        raw = fixture()
    return verify_hosted_unittest_log(
        raw, trusted_log_sha256=(hashlib.sha256(raw).hexdigest() if expected_log is None else expected_log),
        trusted_case_ids=roster,
        trusted_roster_sha256=(digest_roster(roster) if expected_roster is None else expected_roster),
    )


class HostedLogEnvelopeTests(unittest.TestCase):
    def reject(self, raw, **kwargs):
        with self.assertRaises(HostedLogRejected):
            run(raw, **kwargs)

    def test_01_valid_invented_hosted_log_is_not_authenticated(self):
        result = run()
        self.assertEqual(result['status'], 'HOSTED_LOG_STRUCTURE_ONLY_NOT_AUTHENTICATED')
        self.assertEqual(result['tests'], 2)
        self.assertFalse(result['release_ready'])
        self.assertFalse(result['live_trading_allowed'])

    def test_02_valid_github_bom_accepted(self):
        self.assertEqual(run(fixture(bom=True))['tests'], 2)

    def test_03_github_command_ansi_accepted_only_in_header(self):
        self.assertEqual(run(fixture(cmd=ANSI))['tests'], 2)

    def test_04_accepted_clean_command_without_ansi(self):
        self.assertEqual(run(fixture(cmd=CMD))['tests'], 2)

    def test_05_missing_step_group_rejected(self):
        self.reject(fixture(group='unrelated fake step'))

    def test_06_success_quoted_before_unittest_step_not_counted(self):
        d = fixture(pre=('test_fake (test_toy.Fake.test_fake) ... ok',))
        self.assertEqual(run(d)['tests'], 2)

    def test_07_no_safe_env_rejected(self):
        self.reject(fixture(safe=''))

    def test_08_safe_env_disabled_rejected(self):
        self.reject(fixture(safe='  SAFE_TEST_ONLY: 0'))

    def test_09_mismatched_python_command_rejected(self):
        self.reject(fixture(cmd='python -m unittest discover -s other -v'))

    def test_10_terminal_escape_in_test_output_rejected(self):
        d = fixture().replace(b'test_alpha (', b'\x1b[31mtest_alpha (')
        self.reject(d)

    def test_11_osc_escape_in_prelude_rejected(self):
        self.reject(fixture(pre=('\x1b]0;BAD\x07',)))

    def test_12_nested_test_step_rejected(self):
        self.reject(fixture(head_extra=(START,)))

    def test_13_duplicate_case_rejected(self):
        self.reject(fixture(ids=(A, A)))

    def test_14_success_summary_cannot_overclaim_count(self):
        self.reject(fixture(outcome=('Ran 3 tests in 0.1s', 'OK')))

    def test_15_singular_grammar_mismatch_rejected(self):
        self.reject(fixture(outcome=('Ran 2 test in 0.1s', 'OK')))

    def test_16_missing_ok_rejected(self):
        self.reject(fixture(outcome=('Ran 2 tests in 0.1s',)))

    def test_17_duplicate_ok_after_success_rejected(self):
        self.reject(fixture(extra=('OK',)))

    def test_18_missing_termination_footer_rejected(self):
        self.reject(fixture(tail=()))

    def test_19_missing_post_job_cleanup_rejected(self):
        self.reject(fixture(tail=('Cleaning up orphan processes',)))

    def test_20_workflow_error_before_tests_rejected(self):
        self.reject(fixture(pre=('##[error]synthetic failure',)))

    def test_21_workflow_error_after_tests_rejected(self):
        self.reject(fixture(extra=('Error: Process completed with exit code 1.',)))

    def test_22_skipped_test_rejected(self):
        self.reject(fixture(extra=('test_gamma (test_toy.Gamma.test_gamma) ... skipped',)))

    def test_23_substituted_roster_rejected(self):
        self.reject(fixture(ids=(A, 'test_toy.Gamma.test_gamma')))

    def test_24_wrong_roster_digest_rejected(self):
        self.reject(fixture(), expected_roster='f' * 64)

    def test_25_wrong_log_sha256_rejected(self):
        self.reject(fixture(), expected_log='f' * 64)

    def test_26_backwards_timestamp_rejected(self):
        d = fixture().splitlines(keepends=True)
        d[1] = d[1].replace(b'2026-11-09', b'2026-11-08')
        self.reject(b''.join(d))

    def test_27_invalid_calendar_date_rejected(self):
        self.reject(fixture().replace(b'2026-11-09', b'2026-02-29'))

    def test_28_wrong_method_name_rejected(self):
        self.reject(fixture().replace(b'test_alpha (' + A.encode(), b'test_beta (' + A.encode()))

    def test_29_unapproved_split_stdout_rejected(self):
        d = fixture().replace(('test_alpha (' + A + ') ... ok').encode(),
                              ('test_alpha (' + A + ')\n' + P + 'Fake ... ok').encode())
        self.reject(d)

    def test_30_known_rc656_split_accepted(self):
        method = S.rsplit('.', 1)[-1]
        d = fixture(ids=(S,), outcome=('Ran 1 test in 0.12s', 'OK'))
        d = d.replace(('%s (%s) ... ok' % (method, S)).encode(),
                      ('%s (%s)\n%s%s' % (method, S, P,
                       'Measure this checkout only; do not publish an artifact or include private code. ... ok')).encode())
        self.assertEqual(run(d, (S,))['tests'], 1)

    def test_31_rc656_split_incomplete_rejected(self):
        method = S.rsplit('.', 1)[-1]
        d = fixture(ids=(S,), outcome=('Ran 1 test in 0.12s', 'OK'))
        d = d.replace(('%s (%s) ... ok' % (method, S)).encode(),
                      ('%s (%s)' % (method, S)).encode())
        self.reject(d, roster=(S,))

    def test_32_non_utf8_rejected(self):
        self.reject(fixture() + b'\xff')

    def test_33_too_many_bytes_rejected(self):
        self.reject(fixture() + b'x' * 262144)

    def test_34_nonbytes_type_rejected(self):
        with self.assertRaises(HostedLogRejected):
            verify_hosted_unittest_log('not bytes', trusted_log_sha256='f' * 64,
                                       trusted_case_ids=ROSTER,
                                       trusted_roster_sha256=digest_roster(ROSTER))

    def test_35_unsorted_roster_rejected(self):
        self.reject(fixture(), roster=(B, A))

    def test_36_unknown_case_after_ok_rejected(self):
        self.reject(fixture(extra=('test_gamma (test_toy.Gamma.test_gamma) ... ok',)))

    def test_37_duplicate_test_step_after_ok_rejected(self):
        self.reject(fixture(extra=(START,)))

    def test_38_single_test_correct_grammar_accepted(self):
        self.assertEqual(run(fixture(ids=(A,)), (A,))['tests'], 1)


    def test_39_november_calendar_boundary_valid(self):
        self.assertEqual(run(fixture())['tests'], 2)

    def test_40_december_calendar_boundary_valid(self):
        d = fixture().replace(b'2026-11-09', b'2026-12-31')
        self.assertEqual(run(d)['tests'], 2)

    def test_41_month_thirteen_rejected(self):
        self.reject(fixture().replace(b'2026-11-09', b'2026-13-09'))

    def test_42_leap_day_2028_accepted(self):
        d = fixture().replace(b'2026-11-09', b'2028-02-29')
        self.assertEqual(run(d)['tests'], 2)


if __name__ == '__main__':
    unittest.main()
