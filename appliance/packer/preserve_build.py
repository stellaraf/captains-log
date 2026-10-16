"""Retain exact build-file inodes independently of Packer cleanup.

Links are live while the builder writes. They are recovery material, not verified
snapshots, until the writer has exited and image consistency has been checked.
"""
from pathlib import Path
import os
import stat

NAMES = ('nebulalog-rocky9.qcow2', 'nebulalog-rocky9.qcow2-1', 'efivars.fd')


class RecoveryLinks:
    def __init__(self, source, recovery):
        self.source, self.recovery = Path(source), Path(recovery)
        if (not self.source.is_absolute() or not self.recovery.is_absolute()
                or self.source == self.recovery or self.recovery.is_relative_to(self.source)
                or self.source.is_relative_to(self.recovery)):
            raise ValueError('Separate absolute build and recovery directories are required')
        self.recovery.mkdir(mode=0o700)  # Exclusive; never adopt existing artifacts.
        self.identities = set()
        self.records = []

    def capture(self):
        if not self.source.exists():
            return list(self.records)
        info = self.source.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('Build output must be an owned nonsymlink directory')
        for name in NAMES:
            path = self.source / name
            try:
                before = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                raise ValueError('Recovery accepts owned regular build artifacts only')
            identity = (name, before.st_dev, before.st_ino)
            if identity in self.identities:
                continue
            target = self.recovery / (name + '.generation-' + str(len(self.records) + 1).zfill(3))
            try:
                os.link(path, target, follow_symlinks=False)
            except FileNotFoundError:
                continue  # Replacement between lstat/link; reobserve next pass.
            linked = target.lstat()
            if not stat.S_ISREG(linked.st_mode) or linked.st_uid != os.getuid():
                raise ValueError('Recovery link changed type or ownership')
            actual = (name, linked.st_dev, linked.st_ino)
            self.identities.add(actual)
            self.records.append({'source_name':name, 'recovery_file':str(target),
                                 'device':linked.st_dev, 'inode':linked.st_ino,
                                 'consistent_image_verified':False})
        return list(self.records)
