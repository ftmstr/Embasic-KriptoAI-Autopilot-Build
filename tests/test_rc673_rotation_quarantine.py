"""Invented, no-key RC673 root rotation and conflicting issuer adversaries."""
import copy
import unittest

from safe_public_ci.ci_rotation_quarantine_gate import (
    RotationQuarantined, rotation_intent_sha256,
    check_synthetic_rotation_quarantine,
)

D = lambda x: x * 64
OLD = D('1')
NEW = D('2')
CONTEXT = D('3')
SOURCE = D('4')
FLOW = D('5')
ROSTER = D('6')
NEXT = D('7')
NONCE = D('8')
LOGS = (D('9'), D('a'))
ROLES = ('owner', 'independent_reviewer', 'incumbent_custodian')
ACTORS = ('owner_alice', 'reviewer_bob', 'custodian_carol')


def inputs():
    claim = {
        'repository': 'ftmstr/Embasic-KriptoAI-Autopilot-Build',
        'branch': 'validation/rc654-pr1-rc653-combined-ci',
        'previous_context_sha256': CONTEXT,
        'old_authority_id': 'old_authority', 'old_authority_epoch': 3,
        'old_authority_root_sha256': OLD,
        'new_authority_id': 'new_authority', 'new_authority_epoch': 4,
        'new_authority_root_sha256': NEW,
        'git_sha': 'a' * 40, 'source_sha256': SOURCE,
        'workflow_sha256': FLOW, 'roster_sha256': ROSTER,
        'cas_generation': 12, 'next_cas_generation': 13,
        'next_cas_root_sha256': NEXT, 'run_ids': (300, 400),
        'job_ids': (500, 600), 'log_sha256': LOGS,
        'run_attempts': (1, 1), 'nonce_sha256': NONCE,
        'ack_state': 'NOT_SUBMITTED', 'approval_claims': (),
        'release_ready': False, 'live_trading_allowed': False,
    }
    digest = rotation_intent_sha256(claim)
    claim['approval_claims'] = tuple((role, actor, digest)
                                     for role, actor in zip(ROLES, ACTORS))
    pins = {
        'previous_context_sha256': CONTEXT,
        'old_authority_id': 'old_authority', 'old_authority_epoch': 3,
        'old_authority_root_sha256': OLD, 'git_sha': 'a' * 40,
        'source_sha256': SOURCE, 'workflow_sha256': FLOW,
        'roster_sha256': ROSTER, 'cas_generation': 12,
        'previous_run_ids': (200, 300),
        'previous_job_ids': (400, 500),
        'run_ids': (300, 400), 'job_ids': (500, 600),
        'log_sha256': LOGS, 'consumed_nonce_sha256': (),
        'previous_log_sha256': (),
        'recent_authority_root_sha256': (OLD,),
        'owner_actor': ACTORS[0], 'reviewer_actor': ACTORS[1],
        'incumbent_actor': ACTORS[2], 'intent_sha256': digest,
    }
    return claim, pins


def bind_claims(c, p):
    """Simulate maliciously changing both claims and all matching pins."""
    digest = rotation_intent_sha256(c)
    c['approval_claims'] = tuple((role, actor, digest)
                                 for role, actor in zip(ROLES, ACTORS))
    p['intent_sha256'] = digest


class RC673QuarantineAdversaries(unittest.TestCase):
    def bad(self, mutate):
        c, p = inputs()
        mutate(c, p)
        with self.assertRaises(RotationQuarantined):
            check_synthetic_rotation_quarantine(c, pinned=p)

    def test_01_proposal_only_not_authenticated(self):
        c, p = inputs()
        result = check_synthetic_rotation_quarantine(c, pinned=p)
        self.assertEqual(result['status'], 'ROTATION_QUARANTINED_NOT_AUTHENTICATED')
        self.assertFalse(result['external_authorization_verified'])
        self.assertFalse(result['release_ready'])
        self.assertFalse(result['live_trading_allowed'])

    def test_02_deterministic_intent(self):
        c, _ = inputs()
        self.assertEqual(rotation_intent_sha256(c), rotation_intent_sha256(c))

    def test_03_new_root_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['new_authority_root_sha256'] = D('f')
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_04_source_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['source_sha256'] = D('f')
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_05_workflow_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['workflow_sha256'] = D('f')
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_06_roster_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['roster_sha256'] = D('f')
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_07_old_context_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['previous_context_sha256'] = D('f')
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_08_nonce_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['nonce_sha256'] = D('f')
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_09_run_id_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['run_ids'] = (300, 401)
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_10_log_order_modifies_intent(self):
        c, _ = inputs()
        original = rotation_intent_sha256(c)
        c['log_sha256'] = tuple(reversed(LOGS))
        self.assertNotEqual(original, rotation_intent_sha256(c))

    def test_11_lost_ack_remains_quarantined(self):
        c, p = inputs()
        c['ack_state'] = 'ACK_LOST_UNRESOLVED'
        bind_claims(c, p)
        self.assertEqual(check_synthetic_rotation_quarantine(c, pinned=p)
                         ['status'], 'ROTATION_QUARANTINED_NOT_AUTHENTICATED')

    def test_12_malicious_forged_matching_pins_still_quarantined(self):
        c, p = inputs()
        c['source_sha256'] = D('f')
        p['source_sha256'] = D('f')
        bind_claims(c, p)
        result = check_synthetic_rotation_quarantine(c, pinned=p)
        self.assertFalse(result['external_authorization_verified'])

    def test_13_invalid_repo(self):
        self.bad(lambda c, p: c.update(repository='not-public'))

    def test_14_main_branch_forbidden(self):
        self.bad(lambda c, p: c.update(branch='main'))

    def test_15_malformed_git_sha(self):
        self.bad(lambda c, p: c.update(git_sha='g' * 40))

    def test_16_git_pin_mismatch(self):
        self.bad(lambda c, p: p.update(git_sha='f' * 40))

    def test_17_wrong_source_pin(self):
        self.bad(lambda c, p: p.update(source_sha256=D('f')))

    def test_18_wrong_workflow_pin(self):
        self.bad(lambda c, p: p.update(workflow_sha256=D('f')))

    def test_19_wrong_roster_pin(self):
        self.bad(lambda c, p: p.update(roster_sha256=D('f')))

    def test_20_wrong_prior_context_pin(self):
        self.bad(lambda c, p: p.update(previous_context_sha256=D('f')))

    def test_21_wrong_prior_root_pin(self):
        self.bad(lambda c, p: p.update(old_authority_root_sha256=D('f')))

    def test_22_old_authority_id_changed(self):
        self.bad(lambda c, p: c.update(old_authority_id='other'))

    def test_23_pinned_old_authority_id_changed(self):
        self.bad(lambda c, p: p.update(old_authority_id='other'))

    def test_24_pinned_epoch_changed(self):
        self.bad(lambda c, p: p.update(old_authority_epoch=4))

    def test_25_epoch_jump_rejected(self):
        self.bad(lambda c, p: c.update(new_authority_epoch=5))

    def test_26_epoch_backwards_rejected(self):
        self.bad(lambda c, p: c.update(new_authority_epoch=2))

    def test_27_same_root_rejected(self):
        self.bad(lambda c, p: c.update(new_authority_root_sha256=OLD))

    def test_28_same_issuer_id_rejected(self):
        self.bad(lambda c, p: c.update(new_authority_id='old_authority'))

    def test_29_aba_prior_root_rejected(self):
        self.bad(lambda c, p: p.update(recent_authority_root_sha256=(OLD, NEW)))

    def test_30_consumed_nonce_rejected(self):
        self.bad(lambda c, p: p.update(consumed_nonce_sha256=(NONCE,)))

    def test_31_previous_log_reused(self):
        self.bad(lambda c, p: p.update(previous_log_sha256=(LOGS[0],)))

    def test_32_duplicate_same_os_log_rejected(self):
        self.bad(lambda c, p: c.update(log_sha256=(LOGS[0], LOGS[0])))

    def test_33_old_run_id_rejected(self):
        self.bad(lambda c, p: p.update(previous_run_ids=(300, 300)))

    def test_34_old_job_id_rejected(self):
        self.bad(lambda c, p: p.update(previous_job_ids=(500, 500)))

    def test_35_different_run_id_from_pins_rejected(self):
        self.bad(lambda c, p: c.update(run_ids=(301, 400)))

    def test_36_different_job_id_from_pins_rejected(self):
        self.bad(lambda c, p: c.update(job_ids=(501, 600)))

    def test_37_wrong_log_rebind_rejected(self):
        self.bad(lambda c, p: c.update(log_sha256=(D('f'), LOGS[1])))

    def test_38_missing_reviewer_claim_rejected(self):
        self.bad(lambda c, p: c.update(approval_claims=c['approval_claims'][:2]))

    def test_39_same_owner_and_reviewer_rejected(self):
        self.bad(lambda c, p: p.update(reviewer_actor=ACTORS[0]))

    def test_40_same_owner_and_custodian_rejected(self):
        self.bad(lambda c, p: p.update(incumbent_actor=ACTORS[0]))

    def test_41_conflicting_issuer_role_rejected(self):
        def mutate(c, p):
            a = list(c['approval_claims'])
            a[1] = ('owner', a[1][1], a[1][2])
            c['approval_claims'] = tuple(a)
        self.bad(mutate)

    def test_42_wrong_issuer_actor_rejected(self):
        def mutate(c, p):
            a = list(c['approval_claims'])
            a[1] = (a[1][0], 'other', a[1][2])
            c['approval_claims'] = tuple(a)
        self.bad(mutate)

    def test_43_wrong_approval_digest_rejected(self):
        def mutate(c, p):
            a = list(c['approval_claims'])
            a[2] = (a[2][0], a[2][1], D('f'))
            c['approval_claims'] = tuple(a)
        self.bad(mutate)

    def test_44_claim_list_wrong_type(self):
        self.bad(lambda c, p: c.update(approval_claims=list(c['approval_claims'])))

    def test_45_extra_metadata_rejected(self):
        self.bad(lambda c, p: c.update(signing_secret='invented'))

    def test_46_release_ready_true_rejected(self):
        self.bad(lambda c, p: c.update(release_ready=True))

    def test_47_live_trading_true_rejected(self):
        self.bad(lambda c, p: c.update(live_trading_allowed=True))

    def test_48_forged_applied_ack_rejected(self):
        self.bad(lambda c, p: c.update(ack_state='ACK_APPLIED'))

    def test_49_second_run_attempt_rejected(self):
        self.bad(lambda c, p: c.update(run_attempts=(1, 2)))

    def test_50_boolean_attempt_rejected(self):
        self.bad(lambda c, p: c.update(run_attempts=(True, 1)))

    def test_51_history_list_wrong_type_rejected(self):
        self.bad(lambda c, p: p.update(previous_log_sha256=[]))

    def test_52_duplicate_recent_roots_rejected(self):
        self.bad(lambda c, p: p.update(recent_authority_root_sha256=(OLD, OLD)))

    def test_53_epoch_type_bool_rejected(self):
        self.bad(lambda c, p: c.update(old_authority_epoch=True))

    def test_54_generation_jump_rejected(self):
        self.bad(lambda c, p: c.update(next_cas_generation=14))

    def test_55_inconsistent_generation_pin_rejected(self):
        self.bad(lambda c, p: p.update(cas_generation=11))

    def test_56_conflicting_intent_pin_rejected(self):
        self.bad(lambda c, p: p.update(intent_sha256=D('f')))

    def test_57_oversized_consumed_nonce_history_rejected(self):
        self.bad(lambda c, p: p.update(consumed_nonce_sha256=(NONCE,) * 1025))

    def test_58_missing_external_pin_rejected(self):
        self.bad(lambda c, p: p.pop('intent_sha256'))

    def test_59_wrong_actor_type_rejected(self):
        self.bad(lambda c, p: p.update(owner_actor=True))

    def test_60_full_attacker_control_cannot_set_authorized_result(self):
        c, p = inputs()
        c['new_authority_root_sha256'] = D('f')
        c['nonce_sha256'] = D('e')
        bind_claims(c, p)
        out = check_synthetic_rotation_quarantine(c, pinned=p)
        self.assertEqual(out['status'], 'ROTATION_QUARANTINED_NOT_AUTHENTICATED')
        self.assertFalse(out['external_authorization_verified'])


if __name__ == '__main__':
    unittest.main()
