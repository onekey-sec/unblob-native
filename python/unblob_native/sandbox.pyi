import os

class AccessFS:
    @staticmethod
    def read(access_dir: os.PathLike | str) -> AccessFS: ...
    @staticmethod
    def read_write(access_dir: os.PathLike | str) -> AccessFS: ...
    @staticmethod
    def make_reg(access_dir: os.PathLike | str) -> AccessFS: ...
    @staticmethod
    def make_dir(access_dir: os.PathLike | str) -> AccessFS: ...

def restrict_access(*args: AccessFS) -> None: ...

class SandboxError(Exception): ...
