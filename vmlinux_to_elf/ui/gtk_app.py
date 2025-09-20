#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from os.path import dirname, realpath
from typing import Optional

SCRIPT_DIR = dirname(realpath(__file__))

# Based on https://github.com/Taiko2k/GTK4PythonTutorial?tab=readme-ov-file#ui-from-graphical-designer

import sys
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio

from vmlinux_to_elf.core.kallsyms import KallsymsFinder, obtain_raw_kernel_from_file
from vmlinux_to_elf.core.architecture_detecter import ArchitectureGuessError

class AppStateMachine:
    pass # XX

class MyApp(Adw.Application):
    kernel_path : Optional[str] = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect('activate', self.on_activate)
    
    def update_state(self):
        pass # XX
    
    def connect_signals(self):

        self.file_picker_button : Adw.ActionRow = self.builder.get_object('file_picker_button')
        self.file_picker_button.connect('activated', self.pick_file)

        # TODO set up callbacks for syncing interface elements between them
        # + a correct model object?
    
    def init_arch_list(self):

        self.arch_combo : Adw.ComboRow = self.builder.get_object('architecture_combo')

        arch_model = Gtk.StringList()

        arch_model.append('x86')
        arch_model.append('ARM')
        # WIP add all supported architectures

        self.arch_combo.set_model(arch_model)

    def on_activate(self, app):
        # Create a Builder object, in order
        # to parse the Cambalache-produced UI file

        self.builder = Gtk.Builder()
        self.builder.add_from_file(SCRIPT_DIR + "/gui.ui")
        
        # Connect UI signals

        self.connect_signals()

        # WIP set the architecture ListModel+ListItemFactory into the Adw.ComboRow for the architecture list

        self.init_arch_list()

        # Obtain and show the main window

        self.win : Adw.ApplicationWindow = self.builder.get_object("main_window")
        self.win.set_application(self)  # Application will close once it no longer has active windows attached to it

        # TODO Remove the singleton behavior later?

        self.win.present()

    def pick_file(self, button : Adw.ActionRow):
        file_picker = Gtk.FileDialog()
        file_picker.set_filters(Gio.ListStore())
        file_picker.open(self.win, callback = self.file_picked)
    
    def file_picked(self, file_dialog : Gtk.FileDialog, task : Gio.Task):
        result : Gio.File = file_dialog.open_finish(task)
        self.update_kernel_path(result.get_path())
    
    def update_kernel_path(self, path : Optional[str]):
        if path:
            self.kernel_path = path
            self.file_picker_button.set_title('Kernel blob')
            self.file_picker_button.set_subtitle(path)
            
            # TODO use parallel thread (!! SEE .ODT)

            with open(path, 'rb') as kernel_bin:
                
                bit_size = None # TODO add widget
                override_relative = False # TODO add widget
                
                try:
                    kallsyms = KallsymsFinder(obtain_raw_kernel_from_file(kernel_bin.read()), bit_size, override_relative)
                
                except ArchitectureGuessError:
                    print('[!] The architecture of your kernel could not be guessed ' +
                        'successfully. Please specify the --bit-size argument manually ' +
                        '(use --help for its precise specification).')
                    # TODO Do actual error handling
                    return
                
                except Exception:
                    # TODO Do actual error handling (for all Python exceptions too?
                    # show a popup when wrong?)
                    return
                kernel_string_row = self.builder.get_object('kernel_string_row')
                kernel_string_row.set_visible(True)
                kernel_string_row.set_subtitle(kallsyms.version_string)


def main():            

    app = MyApp(application_id="com.example.GtkApplication")
    app.run(sys.argv)
