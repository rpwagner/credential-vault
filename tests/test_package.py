def test_package_imports() -> None:
    import credential_vault

    assert credential_vault.__name__ == "credential_vault"
