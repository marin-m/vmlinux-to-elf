#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from os.path import dirname, realpath, exists
from enum import Enum

from peewee import (
    SqliteDatabase,
    Model,
    CompositeKey,
    Check,
    TextField,
    IntegerField,
    DateField,
    DateTimeField,
    BooleanField,
    ForeignKeyField,
)

DB_FOLDER = dirname(realpath(__file__))
DB_PATH = realpath(DB_FOLDER + '/database.sqlite3')

db = SqliteDatabase(DB_PATH)


class Base(Model):
    class Meta:
        database = db
        legacy_table_names = False


class KernelVersion(Base):
    version_string = TextField(primary_key=True)  # Git tag
    kernel_source = TextField(
        constraints=[Check("kernel_source in ('git', 'tarball')")]
    )

    browse_url = TextField(null=True)
    download_url = TextField()
    git_commit = TextField(null=True)

    release_date = DateTimeField()


class EMachineValue(Base):
    elf_machine_int = IntegerField(index=True)
    elf_machine_str = TextField(primary_key=True)


class KnownArchitecture(Base):
    architecture_code = TextField(primary_key=True)
    has_32bit_class = BooleanField(default=False)
    has_64bit_class = BooleanField(default=False)
    has_msb_class = BooleanField(default=False)
    has_lsb_class = BooleanField(default=False)


class ArchitectureEMachineLink(Base):
    architecture = ForeignKeyField(
        KnownArchitecture, backref='e_machine_links'
    )
    e_machine = ForeignKeyField(EMachineValue, backref='arch_code_links')

    class Meta:
        primary_key = CompositeKey('architecture', 'e_machine')


class KernelSupportedArch(Base):
    release = ForeignKeyField(KernelVersion, backref='supported_archs')
    architecture = ForeignKeyField(KnownArchitecture)

    class Meta:
        primary_key = CompositeKey('release', 'architecture')


class KernelRelevantFile(Base):
    release = ForeignKeyField(KernelVersion, backref='relevant_files')

    file_name = TextField()
    # data = TextField()
    architecture_code = TextField(index=True, null=True)
    vcs_browser_url = TextField(null=True)


class KernelVersionDependency(Base):
    # Parsed from the `Documentation/Changes` kernel files:

    kernel_release = ForeignKeyField(KernelVersion, backref='dependencies')
    source_file = ForeignKeyField(KernelRelevantFile, backref='extracted_info')

    dependency_name = TextField()
    minimal_version = TextField()
    base_command = TextField(index=True)
    version_command = TextField()
    dependency_is_optional = BooleanField()

    class Meta:
        primary_key = CompositeKey('kernel_release', 'base_command')


class DebianRelease(Base):
    docker_archive_name = TextField(primary_key=True)
    debian_version_name = TextField(index=True)
    debian_version_number = TextField(index=True)
    debian_release_date = DateField(index=True)


db.connect()
