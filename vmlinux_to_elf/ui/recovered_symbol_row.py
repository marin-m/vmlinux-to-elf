#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from gi.repository import GObject


class RecoveredSymbolRow(GObject.Object):
    def __init__(self, name: str, type: str, address: str):
        super().__init__()
        self.name = name
        self.type = type
        self.address = address

    @GObject.Property(type=str)
    def prop_name(self):
        return self.name

    @GObject.Property(type=str)
    def prop_type(self):
        return self.type

    @GObject.Property(type=str)
    def prop_address(self):
        return self.address
