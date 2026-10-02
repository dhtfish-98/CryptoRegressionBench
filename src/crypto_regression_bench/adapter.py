"""Actual pinned-library AES-GCM adapter, with authentication and errors distinct."""
from dataclasses import dataclass

PINNED_VERSION = '47.0.0'


@dataclass(frozen=True)
class Observation:
    decrypted: str
    encrypted: str
    operations: int


class Adapter:
    def __init__(self):
        import cryptography
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.version = cryptography.__version__
        self.openssl = backend.openssl_version_text()
        self.ready = self.version == PINNED_VERSION
        self.aesgcm, self.invalid_tag = AESGCM, InvalidTag

    @staticmethod
    def support(case):
        if case.key_bits not in (128, 192, 256) or case.tag_bits != 128:
            return 'unsupported_parameter_profile'
        if not 8 <= len(case.iv) <= 128 and not (not case.iv and case.expected == 'invalid'):
            return 'unsupported_nonce_profile'
        return None

    def observe(self, case):
        # ValueError is counted as rejection only for the exact known zero-IV
        # invalid API boundary. Other adapter/library exceptions are ERROR.
        zero_boundary = not case.iv and case.expected == 'invalid'
        try:
            cipher = self.aesgcm(case.key)
        except Exception:
            return Observation('error', 'not_run', 0)
        try:
            output = cipher.decrypt(case.iv, case.ct + case.tag, case.aad)
            if type(output) is not bytes:
                return Observation('error', 'not_run', 1)
            decrypted = 'matching' if output == case.msg else 'mismatching'
        except self.invalid_tag:
            decrypted = 'tag_rejected'
        except ValueError:
            decrypted = 'parameter_rejected' if zero_boundary else 'error'
        except Exception:
            decrypted = 'error'
        if case.expected == 'invalid' or decrypted == 'error' or (case.expected == 'acceptable' and decrypted in ('tag_rejected', 'parameter_rejected')):
            return Observation(decrypted, 'not_run', 1)
        try:
            output = cipher.encrypt(case.iv, case.msg, case.aad)
            if type(output) is not bytes:
                encrypted = 'error'
            else:
                encrypted = 'matching' if output == case.ct + case.tag else 'mismatching'
        except self.invalid_tag:
            encrypted = 'error'
        except Exception:
            encrypted = 'error'
        return Observation(decrypted, encrypted, 2)
