"""RC707: precise external evidence requests, never an evidence acceptance engine.

All records here are public GitHub observations.  No access to private keys,
GitHub Support, cloud accounts, raw-log issuer signatures, trading or models.
A generated request or its local hash NEVER promotes any external trust gate.
"""
import hashlib
import json

REPOSITORY = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
SOURCE_SHA = '3e3395fff90010f50a0b4e262bc2299337c6cbad'
PROVIDER_LOGS = {
    'ubuntu': (44575994515, 135743537628,
               '.github/workflows/rc654-validation-synthetic.yml',
               '140264aaf07f3130a23606254f545b4ff77b1971'),
    'windows': (44575994468, 135743537077,
                '.github/workflows/rc658-windows-synthetic.yml',
                '254ac4f4ea821a05ee4730c3828d4de1b96a0e72'),
}
# Requests are actionable procurement specifications, not verified observations.
REQUIREMENTS = (
    ('owner_oob_ed25519', 'Independently held owner-authority OOB key, scoped delegation, and signed revocation chronology'),
    ('reviewer_oob_ed25519', 'Distinct independent reviewer-admin OOB key and signed approval; prove administrative separation'),
    ('provider_raw_ubuntu', 'GitHub-origin signed exact ORIGINAL RAW complete Ubuntu job log, plus verifiable signing-key chain'),
    ('provider_raw_windows', 'GitHub-origin signed exact ORIGINAL RAW complete Windows job log, plus verifiable signing-key chain'),
    ('independent_time_revocation', 'Independently authenticated non-rewindable time and key rotation/revocation history'),
    ('witnessed_historical_merkle', 'Historical independently pinned C2SP signed checkpoints, independent witness cosignature and RFC6962 inclusion/consistency'),
    ('separate_admin_durable_mrsc_cas', 'Actual three-Region DynamoDB MRSC, separate-admin two-physical-host fenced CAS race and PITR anti-restore drill'),
    ('authenticated_recipient_ack', 'Remote recipient-authenticated idempotency ACK and loss-of-response reconciliation'),
)


def _digest(value):
    """Hash a public *request* only; never represent it as signed evidence."""
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True,
                           separators=(',', ':'), allow_nan=False).encode('ascii')
    return hashlib.sha256(b'KRIPTOAI-RC707-PROCUREMENT-ONLY\x00' + canonical).hexdigest()


def escalation_packet(platform):
    """Generate a reproducible official-support request; do not submit it."""
    if type(platform) is not str or platform not in PROVIDER_LOGS:
        raise ValueError('only_pinned_real_os_jobs')
    run_id, job_id, path, blob = PROVIDER_LOGS[platform]
    subject = {'repository': REPOSITORY, 'branch': BRANCH,
               'head_sha': SOURCE_SHA, 'platform': platform,
               'run_id': run_id, 'job_id': job_id, 'run_attempt': 1,
               'workflow_path': path, 'workflow_git_blob_sha1': blob,
               'observed_run_and_job': 'completed/success',
               'successful_job_steps': 9, 'total_job_steps': 9,
               'unittest_cases': 3205, 'rc706_cases': 11}
    requirements = (
        'Confirm whether GitHub can independently issue a provider-origin digital signature '
        'covering the byte-for-byte ORIGINAL RAW COMPLETE job log, not redirected readable '
        'plaintext, reserialized logs, workflow-run ZIP, artifact hash, or an attested artifact. '
        'If possible provide the exact original byte stream or its binding digest, byte boundary '
        'and canonicalization specification, complete-log completeness guarantee, algorithm, '
        'signature, issuer identity/key chain, OOB-verifiable root, signing time, revocation '
        'status, and reproducible verification procedure. Bind the signature to the above '
        'repository, HEAD, attempt, workflow, run ID and job ID. If unsupported, explicitly '
        'confirm the limitation and indicate an official escalation/product route. Never '
        'replace the strict RAW-log criterion with a weaker attestation.'
    )
    ticket = ('Subject: GitHub Actions ORIGINAL RAW full job-log provider signature capability — '
              + platform + '\n\n' + 'Public evidence subject:\n'
              + json.dumps(subject, sort_keys=True, indent=2) + '\n\nRequest:\n'
              + requirements + '\n\n'
              + 'This is a capability inquiry; no provider signature or authenticated proof is claimed.\n')
    packet = {'scope': subject, 'provider': 'GITHUB_SUPPORT_OFFICIAL_ESCALATION',
              'request': requirements, 'ticket_text': ticket,
              'not_submitted': True, 'signature_obtained': False,
              'original_raw_full_log_verified': False,
              'authority': 'BLOCKED', 'live': 'DISABLED'}
    return {**packet, 'request_sha256': _digest(packet)}


def remaining_gate_handoff():
    """Eight fixed acquisition tasks. Neither a ticket nor an SHA is authority."""
    return tuple({'gate': gate, 'required_external_evidence': needed,
                  'status': 'BLOCKED', 'independently_verified': False}
                 for gate, needed in REQUIREMENTS)


def safety_state():
    return {'external_verified': 0, 'external_required': 8,
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
