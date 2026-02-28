#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from os.path import dirname, realpath
from threading import Thread
from os import access, W_OK
from typing import Optional
from subprocess import run
from shutil import which

SCRIPT_DIR = dirname(realpath(__file__))
ASSETS_DIR = realpath(SCRIPT_DIR + '/assets')
RESOURCES_PATH = realpath(ASSETS_DIR + '/vmlinux-to-elf.gresource')

# Based on https://github.com/Taiko2k/GTK4PythonTutorial?tab=readme-ov-file#ui-from-graphical-designer

import sys
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Gdk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, GLib, Gdk, Adw, Gio

from vmlinux_to_elf.core.vmlinuz_decompressor import (
    obtain_raw_kernel_from_file,
)
from vmlinux_to_elf.core.kallsyms import KallsymsFinder
from vmlinux_to_elf.core.architecture_detecter import ArchitectureGuessError


class AppStateMachine:
    pass  # XX


class MyApp(Adw.Application):
    kernel_path: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
        theme.add_resource_path('/re/fossplant/vmlinux-to-elf/')

        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        # Create a Builder object, in order
        # to parse the Cambalache-produced UI file

        self.builder = Gtk.Builder()
        self.builder.add_from_resource('/re/fossplant/vmlinux-to-elf/gui.ui')

        # Connect UI signals

        self.connect_signals()

        # WIP set the architecture ListModel+ListItemFactory into the Adw.ComboRow for the architecture list

        self.init_arch_list()

        # Obtain and show the main window

        self.win: Adw.ApplicationWindow = self.builder.get_object(
            'main_window'
        )
        self.win.set_application(
            self
        )  # Application will close once it no longer has active windows attached to it

        # Connect UI actions

        self.connect_actions()

        self.win.present()

    def connect_signals(self):

        def pick_file(button: Adw.ActionRow):

            def file_picked(file_dialog: Gtk.FileDialog, task: Gio.Task):
                result: Gio.File = file_dialog.open_finish(task)
                self.update_kernel_path(result.get_path())

            file_picker = Gtk.FileDialog()
            file_picker.set_filters(Gio.ListStore())
            file_picker.open(self.win, callback=file_picked)

        self.file_picker_button: Adw.ActionRow = self.builder.get_object(
            'file_picker_button'
        )
        self.file_picker_button.connect('activated', pick_file)

        # TODO set up callbacks for syncing interface elements between them
        # + a correct model object?

    def connect_actions(self):

        def show_about(*args):
            self.builder.get_object('about_dialog').present()

        self.add_simple_action('show-about', show_about)

    def add_simple_action(self, name, callback):

        action = Gio.SimpleAction.new(name, None)
        action.connect('activate', callback)
        self.win.add_action(action)

    def init_arch_list(self):

        self.arch_combo: Adw.ComboRow = self.builder.get_object(
            'architecture_combo'
        )

        arch_model = Gtk.StringList()

        arch_model.append('x86')
        arch_model.append('ARM')
        # WIP add all supported architectures

        self.arch_combo.set_model(arch_model)

    def update_kernel_path(self, path: Optional[str]):
        if path:
            self.kernel_path = path
            self.file_picker_button.set_title('Kernel blob')
            self.file_picker_button.set_subtitle(path)

            # xx show spinner

            def detection_thread():

                with open(path, 'rb') as kernel_bin:
                    bit_size = None  # TODO add widget
                    override_relative = False  # TODO add widget

                    try:
                        kallsyms = KallsymsFinder(
                            obtain_raw_kernel_from_file(kernel_bin.read()),
                            bit_size,
                            override_relative,
                        )

                    except ArchitectureGuessError:
                        print(
                            '[!] The architecture of your kernel could not be guessed '
                            + 'successfully. Please specify the --bit-size argument manually '
                            + '(use --help for its precise specification).'
                        )
                        # TODO Do actual error handling
                        return

                    except Exception:
                        # TODO Do actual error handling (for all Python exceptions too?
                        # show a popup when wrong?)
                        return
                    
                    # GLib.idle_add(xx) <-- call back the main thread for safety?

                    # xx hide spinner

                    # xx set and show metadata

                    kernel_string_row = self.builder.get_object(
                        'kernel_string_row'
                    )
                    kernel_string_row.set_visible(True)
                    kernel_string_row.set_subtitle(kallsyms.version_string)
            
            thread = Thread(target = detection_thread)
            thread.daemon = True
            thread.start()


def main():

    if access(RESOURCES_PATH, W_OK) and which('glib-compile-resources'):
        run(['glib-compile-resources', RESOURCES_PATH + '.xml'],
            cwd = ASSETS_DIR)

    GLib.set_prgname('re.fossplant.vmlinux-to-elf')

    Gio.resources_register(
        Gio.resource_load(RESOURCES_PATH)
    )

    app = MyApp(
        application_id='re.fossplant.vmlinux-to-elf',
        flags=Gio.ApplicationFlags.NON_UNIQUE
    )
    app.run(sys.argv)


if __name__ == '__main__':
    main()
