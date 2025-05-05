import json
import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from django_fernet_secrets.settings import ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME
from django_fernet_secrets.utils import encrypt_secret_credential, check_if_conf_file_is_git_ignored


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument(
            '--plaintext',
            dest='plaintext',
        )
        parser.add_argument(
            '--env',
            dest='env',
        )

    def handle(self, *args, **options):
        check_if_conf_file_is_git_ignored()

        plaintext = options["plaintext"]
        env = options["env"]

        assert plaintext, "plaintext is required"
        assert env, "env is required"

        secrets_file_path = f"{os.path.dirname(settings.BASE_DIR)}/{ENCRYPTION_KEY_BY_ENVIRONMENT_FILE_NAME}"
        if os.path.exists(secrets_file_path):
            secrets_by_environment = json.loads(Path(secrets_file_path).read_text())
            if env not in secrets_by_environment:
                raise CommandError(f"Secret key for {env} could not be found in {secrets_file_path}. You need to run 'generate_encryption_key' command for the environment {environment}")
            else:
                encryption_key = secrets_by_environment[env]
        else:
            raise CommandError(f"Secrets by environment file '{secrets_file_path}' does not exists.")

        print(f"Your encrypted text is: {encrypt_secret_credential(plaintext, encryption_key)}")
