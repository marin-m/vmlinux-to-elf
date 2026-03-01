#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from gi.repository import GObject


class DetectedTokenRow(GObject.Object):
    def __init__(self, token: str, offset: str):
        super().__init__()
        self.token = token
        self.offset = type

    @GObject.Property(type=str)
    def prop_token(self):
        return self.token

    @GObject.Property(type=str)
    def prop_offset(self):
        return self.offset
