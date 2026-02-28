#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from os import stat, scandir, access, W_OK
from os.path import dirname, realpath
from threading import Thread
from typing import Optional
from subprocess import run
from shutil import which
from re import sub
import logging

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
from vmlinux_to_elf.core.kallsyms import (
    KallsymsFinder,
    KallsymsNotFoundException
)
from vmlinux_to_elf.core.architecture_detecter import (
    ArchitectureGuessError,
    ArchitectureName,
    ElfMachine,
    architecture_to_readable_name,
)


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

        # Connect UI actions

        self.connect_actions()

        self.win.present()

    def connect_signals(self):

        pass

        # TODO set up callbacks for syncing interface elements between them
        # + a correct model object?

    def connect_actions(self):

        def show_about(*args):
            self.builder.get_object('about_dialog').present()

        self.add_simple_action('show-about', show_about)

        def pick_file(*args):

            def file_picked(file_dialog: Gtk.FileDialog, task: Gio.Task):
                try:
                    result: Gio.File = file_dialog.open_finish(task)
                except GLib.GError as err: # Dismissed by user
                    if err.message != 'Dismissed by user':
                        raise
                else:
                    self.update_kernel_path(result.get_path())

            file_picker = Gtk.FileDialog()
            file_picker.set_filters(Gio.ListStore())
            file_picker.open(self.win, callback=file_picked)

        self.add_simple_action('pick-file', pick_file)

    def add_simple_action(self, name, callback):

        action = Gio.SimpleAction.new(name, None)
        action.connect('activate', callback)
        self.win.add_action(action)

    def init_arch_list(self):

        self.arch_combo: Adw.ComboRow = self.builder.get_object(
            'architecture_combo'
        )

        arch_model = Gtk.StringList()

        for arch, readable_name in architecture_to_readable_name.items():
            arch_model.append(readable_name)

        self.arch_combo.set_model(arch_model)

        self.e_machine_combo: Adw.ComboRow = self.builder.get_object(
            'e_machine_combo'
        )

        e_machine_model = Gtk.StringList()

        for e_machine in ElfMachine:
            e_machine_model.append(e_machine.name)

        self.e_machine_combo.set_model(e_machine_model)

    def update_kernel_path(
        self,
        path: Optional[str],
        is_64_bits : Optional[bool] = None,
        manual_preset : Optional[ArchitectureName] = None
    ):

        # TODO : Do re-entrance to this function with
        # combo box setting callbacks

        if path:
            self.kernel_path = path

            self.file_picker_button: Adw.ActionRow = self.builder.get_object(
                'file_picker_button'
            )
            self.file_picker_button.set_title('Kernel blob')
            self.file_picker_button.set_subtitle(path)

            selection_spinner_row = self.builder.get_object(
                'selection_spinner_row'
            )
            selection_spinner_row.set_visible(True)

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

                    except (ValueError, KallsymsNotFoundException):
                        raise

                    except ArchitectureGuessError:
                        logging.error(
                            '[!] The architecture of your kernel could not be guessed '
                            + 'successfully. Please specify the --bit-size argument manually '
                            + '(use --help for its precise specification).'
                        )
                        # TODO Do actual error handling
                        raise

                    except Exception:
                        # TODO Do actual error handling (for all Python exceptions too?
                        # show a popup when wrong?)

                        raise

                    finally:

                        def hide_spinner_cb(*args):
                            selection_spinner_row = self.builder.get_object(
                                'selection_spinner_row'
                            )
                            selection_spinner_row.set_visible(False)

                        GLib.idle_add(hide_spinner_cb)

                    # xx set and show metadata

                    def update_ui_cb(*args):
                        # Display the kernel version string

                        kernel_string_row = self.builder.get_object(
                            'kernel_string_row'
                        )
                        kernel_string_row.set_visible(True)
                        kernel_string_row.set_subtitle(kallsyms.version_string)

                        # Display the "Analysis options" UI block

                        analysis_options = self.builder.get_object(
                            'analysis_options'
                        )
                        analysis_options.set_visible(True)

                        # Show guessed architecture

                        key = architecture_to_readable_name[
                            kallsyms.architecture
                        ]

                        architecture_combo = self.builder.get_object(
                            'architecture_combo'
                        )
                        architecture_combo.set_title(
                            sub(
                                r': .+?\)',
                                ': %s)' % key,
                                architecture_combo.get_title()
                            )
                        )
                        architecture_combo.set_selected(
                            architecture_combo.get_model().find(key)
                        )

                        # Show guessed ELF Machine

                        key = ElfMachine(kallsyms.elf_machine).name

                        e_machine_combo = self.builder.get_object(
                            'e_machine_combo'
                        )
                        e_machine_combo.set_title(
                            sub(
                                r': .+?\)',
                                ': %s)' % key,
                                e_machine_combo.get_title()
                            )
                        )
                        e_machine_combo.set_selected(
                            e_machine_combo.get_model().find(key)
                        )

                        # Show guessed bitness

                        is_64_bits = kallsyms.is_64_bits

                        bitness_switch = self.builder.get_object(
                            'bitness_switch'
                        )
                        bitness_switch.set_title(
                            sub(
                                r': .+?\)',
                                ': %s)' % ('yes' if is_64_bits else 'no'),
                                bitness_switch.get_title()
                            )
                        )
                        bitness_switch.set_active(is_64_bits)

                        # Show guessed base address

                        if kallsyms.kernel_text_candidate:
                            base_address_entry = self.builder.get_object(
                                'base_address_entry'
                            )
                            base_address_entry.set_title(
                                sub(
                                    r': .+?\)',
                                    ': %08x)' % kallsyms.kernel_text_candidate,
                                    base_address_entry.get_title()
                                )
                            )
                            base_address_entry.set_text(
                                '%08x' % kallsyms.kernel_text_candidate
                            )

                        # Show "Detect symbols button" pointing to view #2

                        detect_symbols_bar = self.builder.get_object(
                            'detect_symbols_bar'
                        )
                        detect_symbols_bar.set_revealed(True)

                    GLib.idle_add(update_ui_cb)

            thread = Thread(target=detection_thread)
            thread.daemon = True
            thread.start()


def main():

    if (
        access(RESOURCES_PATH, W_OK)
        and which('glib-compile-resources')
        and max(meta.stat().st_mtime for meta in scandir(ASSETS_DIR))
        > stat(RESOURCES_PATH).st_mtime
    ):
        run(
            ['glib-compile-resources', RESOURCES_PATH + '.xml'], cwd=ASSETS_DIR
        )

    GLib.set_prgname('re.fossplant.vmlinux-to-elf')

    Gio.resources_register(Gio.resource_load(RESOURCES_PATH))

    app = MyApp(
        application_id='re.fossplant.vmlinux-to-elf',
        flags=Gio.ApplicationFlags.NON_UNIQUE,
    )
    app.run(sys.argv)


if __name__ == '__main__':
    main()
