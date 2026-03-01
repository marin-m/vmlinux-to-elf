#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from gi.repository import GObject


class RecoveredSymbolRow(GObject.Object):
    __gtype_name__ = 'RecoveredSymbolRow'

    def __init__(self, name: str, type: str, address: str):
        super().__init__()
        self._name = name
        self._type = type
        self._address = address

    @GObject.Property(type=str)
    def name(self):
        return self._name

    @GObject.Property(type=str)
    def type(self):
        return self._type

    @GObject.Property(type=str)
    def address(self):
        return self._address
