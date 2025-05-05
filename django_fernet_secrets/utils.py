import os
from pathlib import Path
from cryptography.fernet import Fernet

from django.conf import settings

from django_fernet_secrets.exceptions import DjangoFernetSecretsException
from django_fernet_secrets.settings import ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME


def generate_secret_credential_encryption_key():
    """
    Generates a fresh fernet key. Keep this some place safe! If you lose it you'll no
    longer be able to decrypt messages; if anyone else gains access to it, they'll be
    able to decrypt all of your messages, and they'll also be able forge arbitrary
    messages that will be authenticated and decrypted.
    """
    return Fernet.generate_key().decode("utf-8")


def get_secret_credential_encryption_key():
    if not os.environ.get("SECRET_CREDENTIAL_ENCRYPTION_KEY"):
        assert False, "Environment variable 'SECRET_CREDENTIAL_ENCRYPTION_KEY' is not set."

    return os.environ["SECRET_CREDENTIAL_ENCRYPTION_KEY"]


def encrypt_secret_credential(plain_text, encryption_key=None):
    encryption_key = encryption_key or get_secret_credential_encryption_key()
    f = Fernet(encryption_key.encode("utf-8"))
    return f.encrypt(plain_text.encode("utf-8")).decode("utf-8")


def decrypt_secret_credential(encrypted_text, encryption_key=None):
    encryption_key = encryption_key or get_secret_credential_encryption_key()
    f = Fernet(encryption_key.encode("utf-8"))
    return f.decrypt(encrypted_text.encode("utf-8")).decode("utf-8")


def check_if_conf_file_is_git_ignored():
    gitignore = Path(f"{os.path.dirname(settings.BASE_DIR)}/.gitignore").read_text()
    is_file_git_ignored = ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME in gitignore
    if not is_file_git_ignored:
        raise DjangoFernetSecretsException(f"""
        Encryption keys are stored in "{ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME}".
        Please add "{ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME}" to .gitignore to continue.
        """)
