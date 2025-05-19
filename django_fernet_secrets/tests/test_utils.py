from unittest import mock

from cryptography.fernet import Fernet
from django.test import TestCase, override_settings

from django_fernet_secrets.exceptions import DjangoFernetSecretsException
from django_fernet_secrets.utils import (
    generate_secret_credential_encryption_key,
    get_encryption_key,
    encrypt_secret_credential,
    decrypt_secret_credential,
)


class TestGenerateSecretCredentialEncryptionKey(TestCase):

    def test_generate_key(self):
        # Test that we get a valid Fernet key
        key = generate_secret_credential_encryption_key()

        # Check that the key is a string
        self.assertIsInstance(key, str)

        # Check that it's a valid Fernet key by trying to initialize a Fernet instance
        try:
            Fernet(key.encode("utf-8"))
        except Exception as e:
            self.fail(f"Generated key is not a valid Fernet key: {e}")

    def test_generate_unique_keys(self):
        # Test that each call generates a unique key
        key1 = generate_secret_credential_encryption_key()
        key2 = generate_secret_credential_encryption_key()
        self.assertNotEqual(key1, key2)


class TestGetEncryptionKey(TestCase):

    @mock.patch("django_fernet_secrets.utils.dotenv_values")
    @mock.patch("os.path.exists")
    def test_get_encryption_key_success(self, mock_exists, mock_dotenv_values):
        # Set up mocks
        mock_exists.return_value = True
        mock_dotenv_values.return_value = {"test": "test-encryption-key"}

        # Call the function
        key = get_encryption_key("test")

        # Validate results
        self.assertEqual(key, "test-encryption-key")
        mock_exists.assert_called_once()
        mock_dotenv_values.assert_called_once()

    @mock.patch("os.path.exists")
    def test_file_not_found(self, mock_exists):
        # Set up mock
        mock_exists.return_value = False

        # Call the function and check for exception
        with self.assertRaises(DjangoFernetSecretsException) as context:
            get_encryption_key("test")

        self.assertIn("does not exists", str(context.exception))

    @mock.patch("django_fernet_secrets.utils.dotenv_values")
    @mock.patch("os.path.exists")
    def test_key_not_found_for_environment(self, mock_exists, mock_dotenv_values):
        # Set up mocks
        mock_exists.return_value = True
        mock_dotenv_values.return_value = {"prod": "prod-key"}

        # Call the function and check for exception
        with self.assertRaises(DjangoFernetSecretsException) as context:
            get_encryption_key("test")

        self.assertIn("could not be found", str(context.exception))


class TestEncryptDecryptSecretCredential(TestCase):

    @mock.patch("django_fernet_secrets.utils.get_encryption_key")
    def test_encrypt_decrypt_cycle(self, mock_get_encryption_key):
        # Generate a valid key for testing
        test_key = Fernet.generate_key().decode("utf-8")
        mock_get_encryption_key.return_value = test_key

        # Test full cycle of encryption and decryption
        plain_text = "my-secret-value"
        encrypted = encrypt_secret_credential(plain_text, "test")
        decrypted = decrypt_secret_credential(encrypted, "test")

        # Verify that decryption returns the original text
        self.assertEqual(decrypted, plain_text)

        # Verify the encrypted value is different from plain text
        self.assertNotEqual(encrypted, plain_text)

        # Verify mock was called correctly
        mock_get_encryption_key.assert_called_with(environment="test")

    @mock.patch("django_fernet_secrets.utils.get_encryption_key")
    def test_encrypt_produces_different_values(self, mock_get_encryption_key):
        # Generate a valid key for testing
        test_key = Fernet.generate_key().decode("utf-8")
        mock_get_encryption_key.return_value = test_key

        # Even with the same input, encryption should produce different outputs
        plain_text = "my-secret-value"
        encrypted1 = encrypt_secret_credential(plain_text, "test")
        encrypted2 = encrypt_secret_credential(plain_text, "test")

        self.assertNotEqual(encrypted1, encrypted2)

    @mock.patch("django_fernet_secrets.utils.get_encryption_key")
    def test_decrypt_invalid_token(self, mock_get_encryption_key):
        # Generate a valid key for testing
        test_key = Fernet.generate_key().decode("utf-8")
        mock_get_encryption_key.return_value = test_key

        # Attempt to decrypt an invalid token
        with self.assertRaises(Exception):
            decrypt_secret_credential("not-a-valid-token", "test")

    @mock.patch("django_fernet_secrets.utils.get_encryption_key")
    def test_decrypt_with_wrong_key(self, mock_get_encryption_key):
        # First encrypt with one key
        key1 = Fernet.generate_key().decode("utf-8")
        mock_get_encryption_key.return_value = key1
        plain_text = "my-secret-value"
        encrypted = encrypt_secret_credential(plain_text, "test")

        # Then try to decrypt with a different key
        key2 = Fernet.generate_key().decode("utf-8")
        mock_get_encryption_key.return_value = key2

        with self.assertRaises(Exception):
            decrypt_secret_credential(encrypted, "test")
