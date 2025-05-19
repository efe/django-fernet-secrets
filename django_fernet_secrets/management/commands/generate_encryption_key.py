import os
from dotenv import dotenv_values, set_key

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from django_fernet_secrets.utils import ENCRYPTION_KEY_ENVIRONMENT_FILE_NAME
from django_fernet_secrets.utils import generate_secret_credential_encryption_key, check_if_conf_file_is_git_ignored


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument(
            '--env',
            dest='env',
            required=True,
            help='Specify the environment (e.g. development, production)'
        )

    def handle(self, *args, **options):
        check_if_conf_file_is_git_ignored()

        env = options["env"]

        secret_encryption_key = generate_secret_credential_encryption_key()
        secrets_file_path = f"{os.path.dirname(settings.BASE_DIR)}/{ENCRYPTION_KEY_ENVIRONMENT_FILE_NAME}"

        env_dict = dotenv_values(secrets_file_path)

        if env_dict.get(env):
            raise CommandError(
                f"Secret key for {env} already exists in {secrets_file_path}."
            )

        set_key(secrets_file_path, env, secret_encryption_key)

        print(f"Encryption key of {env} environment is stored in {secrets_file_path}.")
