# django-fernet-secrets

A package to simplify secret management for Django projects. Instead of encyrpting every "secret" with a different encryption key, this package encyrpts all secrets with a single master key.

## Getting Started

### Generate the encryption_key

```python
python manage.py generate_encryption_key --env production
```

### Encrypt Text

```python
python manage.py encrypt_text --text sk_live_Gx4mWEgHtCMr4DYMUIqfIrsz --env production
```

### Usage

```
# settings.py

STRIPE_KEY = decrypt_secret_credential("....")
```
