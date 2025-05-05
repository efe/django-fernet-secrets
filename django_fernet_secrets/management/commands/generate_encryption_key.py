import json
import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from django_fernet_secrets.utils import ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME
from django_fernet_secrets.utils import generate_secret_credential_encryption_key, check_if_conf_file_is_git_ignored


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument(
            '--env',
            dest='env',
        )

    def handle(self, *args, **options):
        check_if_conf_file_is_git_ignored()

        environment = options["env"]
        assert environment, "env is required"
        secret_encryption_key = generate_secret_credential_encryption_key()

        secrets_file_path = f"{os.path.dirname(settings.BASE_DIR)}/{ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME}"
        if os.path.exists(secrets_file_path):
            secrets_by_environment = json.loads(Path(secrets_file_path).read_text())
            if environment in secrets_by_environment:
                raise CommandError(
                    f"There is an existing secret key for this environment. Go to file {secrets_file_path} and delete the {environment} key and try again."
                )

            secrets_by_environment[environment] = secret_encryption_key
        else:
            secrets_by_environment = {
                environment: secret_encryption_key
            }

        Path(secrets_file_path).write_text(json.dumps(secrets_by_environment))

        print(f"""
        Keep this some place safe! If you lose it you’ll no longer be able to decrypt messages.

        Your encryption key is "{secret_encryption_key}". This is also stored in {secrets_file_path}.
        """)
