"""RC708: public-only verified-scope escalation paths, not provider evidence.

No network, support API, provider credentials, key material, AWS, trading or fit.
An official ticket or staff reply is not a cryptographic provider-signed RAW log.
"""
import hashlib
import json

REPO = 'ftmstr/Embasic-KriptoAI-Autopilot-Build'
BRANCH = 'validation/rc654-pr1-rc653-combined-ci'
BASE_SHA = 'f7cb5328ac1d7c83ab36744e6f83516f524a6881'
PINNED = {
    'ubuntu': (44611783408, 135870006293,
               '.github/workflows/rc654-validation-synthetic.yml',
               '140264aaf07f3130a23606254f545b4ff77b1971'),
    'windows': (44611783309, 135870006799,
                '.github/workflows/rc658-windows-synthetic.yml',
                '254ac4f4ea821a05ee4730c3828d4de1b96a0e72'),
}
CHANNELS = {
    'paid_support': ('GitHub Support portal', 'https://support.github.com/',
                     'Only if the connected account has an eligible paid GitHub product'),
    'free_community': ('GitHub Community discussions',
                       'https://github.com/orgs/community/discussions',
                       'General technical question route for GitHub Free; public thread is not an authenticated vendor issuance'),
}
OFFICIAL_DOCS = (
    'https://docs.github.com/en/support/contacting-github-support/creating-a-support-ticket',
    'https://docs.github.com/en/rest/actions/workflow-jobs',
    'https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations',
)
GATES = ('owner_oob_ed25519', 'reviewer_oob_ed25519',
         'provider_raw_ubuntu', 'provider_raw_windows',
         'independent_time_revocation', 'witnessed_historical_merkle',
         'separate_admin_durable_mrsc_cas', 'authenticated_recipient_ack')


def _sha(label, data):
    packed = json.dumps(data, sort_keys=True, separators=(',', ':'),
                        ensure_ascii=True, allow_nan=False).encode('ascii')
    return hashlib.sha256(b'RC708-UNSUBMITTED-' + label.encode('ascii') +
                          b'\x00' + packed).hexdigest()


def support_packet(platform, channel):
    """Create a public-metadata-only request, never claim plan or submission."""
    if type(platform) is not str or platform not in PINNED:
        raise ValueError('unknown_pinned_platform')
    if type(channel) is not str or channel not in CHANNELS:
        raise ValueError('unknown_support_channel')
    run, job, workflow, workflow_blob = PINNED[platform]
    name, url, eligibility = CHANNELS[channel]
    identity = {'repository': REPO, 'branch': BRANCH, 'source_sha': BASE_SHA,
                'run_attempt': 1, 'platform': platform,
                'run_id': run, 'job_id': job, 'workflow_path': workflow,
                'workflow_git_blob_sha1': workflow_blob,
                'run_and_job': 'completed/success', 'completed_success_steps': 9,
                'total_steps': 9, 'unittest_passes': 3212, 'rc707_passes': 7}
    topic = 'GitHub Actions original RAW complete job log: provider-issued signature availability'
    question = (
        'For the exact PUBLIC workflow run and job above, does GitHub issue a '
        'provider-origin cryptographic signature covering every byte of the '
        'ORIGINAL RAW COMPLETE job log? The ordinary job-log REST endpoint '
        'returns redirected readable plaintext, and artifact attestations '
        'bind artifact subjects, not the original complete RAW job log. '
        'If the stronger provider-signed RAW log is available, please specify '
        'its official acquisition process, canonical byte preimage, completeness '
        'guarantee, verified issuer signing-key chain/root and revocation, '
        'signature, timestamp, and how to independently verify binding to '
        'repo/commit/workflow/attempt/run/job. Otherwise explicitly identify '
        'that it is unsupported and any formal escalation/product pathway. '
        'A staff/community answer alone does not meet the cryptographic gate.'
    )
    text = ('Subject: ' + topic + ' (' + platform + ')\n\n' +
            'Source identity (public only):\n' + json.dumps(identity, indent=2, sort_keys=True) +
            '\n\nQuestion:\n' + question + '\n\n' +
            'Do not include credentials, private logs, signatures, OOB keys or personal data.\n')
    record = {'channel': channel, 'channel_name': name, 'channel_url': url,
              'eligibility_is_not_verified': True, 'eligibility_rule': eligibility,
              'subject': identity, 'request_text': text,
              'official_documentation': OFFICIAL_DOCS,
              'submitted': False, 'support_reply_received': False,
              'provider_signature_received': False, 'provider_raw_verified': False,
              'external_gate': 'BLOCKED', 'actual_support_case_id': None}
    return {**record, 'request_digest_sha256': _sha('REQUEST', record)}


def classify_unverified_response(platform, channel, answer_class):
    """Triage a *claimed* response; never promote to trusted evidence.

    Does not accept arbitrary text, links or authentication claims; no proof
    can be imported by caller metadata. A vendor answer about capability may
    guide procurement but cannot be the provider's RAW-log signature.
    """
    support_packet(platform, channel)
    if type(answer_class) is not str or answer_class not in (
            'UNSUBMITTED', 'USER_REPORT_ONLY', 'UNAUTHENTICATED_REPLY',
            'DOCUMENTED_UNSUPPORTED', 'POSSIBLE_ESCALATION'):
        raise ValueError('untrusted_reply_class')
    return {'platform': platform, 'channel': channel,
            'reply_class': answer_class, 'provider_signature_verified': False,
            'authenticated_provider_raw_log': False,
            'owner_reviewer_oob_authenticated': False,
            'historical_rekor_authenticated': False,
            'mrsc_multihost_authenticated': False, 'remote_ack_authenticated': False,
            'external_gates_verified': 0, 'external_total': len(GATES),
            'auth': 'NO-GO', 'final': 'SEALED', 'live': 'DISABLED',
            'single_fit': 'UNUSED', 'net20': 'NOT_TESTED'}
