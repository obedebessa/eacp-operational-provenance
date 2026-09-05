"""Local regular-file boundaries. The directory/OS owner remains trusted."""
import os
import stat
from pathlib import Path

from .common import HardeningError


def read_regular(path, *, max_bytes=2 * 1024 * 1024):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise HardeningError('input must be a bounded regular file')
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HardeningError('input exceeds size limit')
    return data


def private_file(path, *, exclusive=False):
    flags = os.O_CREAT | os.O_RDWR | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    if exclusive:
        flags |= os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077
                or hasattr(os, 'getuid') and info.st_uid != os.getuid()):
            raise HardeningError('private owner-only regular file required')
    except BaseException:
        os.close(fd)
        raise
    return fd


def check_sidecars(path):
    # SQLite opens these by pathname. Reject existing redirected/loose sidecars.
    # No protection against an adversary controlling the parent directory.
    for suffix in ('-wal', '-shm', '-journal'):
        side = Path(str(path) + suffix)
        if side.exists() or side.is_symlink():
            fd = private_file(side)
            os.close(fd)
