import hashlib

_executados: set[str] = set()


def _chave(*args) -> str:
    return hashlib.sha256("|".join(str(a).lower() for a in args).encode()).hexdigest()


def ja_executado(*args) -> bool:
    return _chave(*args) in _executados


def registrar(*args) -> None:
    _executados.add(_chave(*args))
