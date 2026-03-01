#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from gi.repository import GObject


class DetectedTokenRow(GObject.Object):
    __gtype_name__ = 'DetectedTokenRow'

    def __init__(self, token: str, offset: str):
        super().__init__()
        self._token = token
        self._offset = offset

    @GObject.Property(type=str)
    def token(self):
        return self._token

    @GObject.Property(type=str)
    def offset(self):
        return self._offset
