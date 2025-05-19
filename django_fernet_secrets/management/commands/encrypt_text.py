from django.core.management.base import BaseCommand

from django_fernet_secrets.utils import encrypt_secret_credential, check_if_conf_file_is_git_ignored, get_encryption_key


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument(
            '--plaintext',
            dest='plaintext',
            required=True,
            help='Specify the plaintext value to encrypt.'
        )
        parser.add_argument(
            '--env',
            dest='env',
            required=True,
            help='Specify the environment (e.g. development, production)'
        )

    def handle(self, *args, **options):
        check_if_conf_file_is_git_ignored()

        plaintext = options["plaintext"]
        env = options["env"]

        encryption_key = get_encryption_key(environment=env)

        encrypted_text = encrypt_secret_credential(plaintext, encryption_key)
        print(f"Your encrypted text is: {encrypted_text}")
