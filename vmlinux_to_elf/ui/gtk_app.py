#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from os import stat, scandir, access, W_OK
from os.path import dirname, realpath
from argparse import ArgumentParser
from threading import Thread
from sys import stderr, argv
from typing import Optional
from subprocess import run
from shutil import which
from io import BytesIO
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

from vmlinux_to_elf.ui.recovered_symbol_row import RecoveredSymbolRow
from vmlinux_to_elf.ui.detected_token_row import DetectedTokenRow
from vmlinux_to_elf.core.vmlinuz_decompressor import (
    obtain_raw_kernel_from_file,
)
from vmlinux_to_elf.core.elf_symbolizer import ElfSymbolizer
from vmlinux_to_elf.core.kallsyms import (
    KallsymsFinder,
    KallsymsNotFoundException,
)
from vmlinux_to_elf.core.architecture_detecter import (
    ArchitectureGuessError,
    ArchitectureName,
    ElfMachine,
    architecture_to_readable_name,
)


class KallsymsLogHandler(logging.Handler):
    def __init__(self, text_buffer: Gtk.TextBuffer):
        logging.Handler.__init__(self)
        self.text_buffer = text_buffer
        self.raw_log = ''

    def emit(self, record: logging.LogRecord):
        self.raw_log += self.format(record) + '\n'

        def cb():
            self.text_buffer.set_text(self.raw_log)

        GLib.idle_add(cb)

    def flush(self):
        self.raw_log = ''

        def cb():
            self.text_buffer.set_text(self.raw_log)

        GLib.idle_add(cb)


class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
        theme.add_resource_path('/re/fossplant/vmlinux-to-elf/')

        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        # Application will close once it no longer has active windows attached to it

        MyWindow().set_application(self)


# Create a templated window object, in order
# to parse the Cambalache-produced UI file

if (
    access(RESOURCES_PATH, W_OK)
    and which('glib-compile-resources')
    and max(meta.stat().st_mtime for meta in scandir(ASSETS_DIR))
    > stat(RESOURCES_PATH).st_mtime
):
    run(['glib-compile-resources', RESOURCES_PATH + '.xml'], cwd=ASSETS_DIR)

Gio.resources_register(Gio.resource_load(RESOURCES_PATH))


@Gtk.Template(resource_path='/re/fossplant/vmlinux-to-elf/gui.ui')
class MyWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'MainWindow'
    kernel_path: Optional[str] = None
    raw_kernel: Optional[bytes] = None

    detect_symbols_bar: Gtk.ActionBar = Gtk.Template.Child()
    about_dialog: Adw.AboutDialog = Gtk.Template.Child()
    e_machine_combo: Adw.ComboRow = Gtk.Template.Child()
    file_picker_button: Adw.ActionRow = Gtk.Template.Child()
    selection_spinner_row: Adw.PreferencesRow = Gtk.Template.Child()
    kallsyms_debug_buffer: Gtk.TextBuffer = Gtk.Template.Child()
    hex_buffer: Gtk.TextBuffer = Gtk.Template.Child()
    offset_selection_split_view: Adw.OverlaySplitView = Gtk.Template.Child()
    kernel_string_row: Adw.PreferencesRow = Gtk.Template.Child()
    analysis_options: Adw.PreferencesGroup = Gtk.Template.Child()
    bitness_switch: Adw.SwitchRow = Gtk.Template.Child()
    base_address_entry: Adw.EntryRow = Gtk.Template.Child()
    symbol_table_selection_model: Gtk.SelectionModel = Gtk.Template.Child()
    symbol_table_model: Gio.ListStore = Gtk.Template.Child()
    offset_list_selection_model: Gtk.SelectionModel = Gtk.Template.Child()
    offset_list_model: Gio.ListStore = Gtk.Template.Child()
    offset_page_toast: Adw.ToastOverlay = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Log info to display in the Gtk.TextBuffer present in UI flow
        # screen #2

        logger = logging.getLogger()

        self.handler = KallsymsLogHandler(self.kallsyms_debug_buffer)
        self.handler.setLevel(logging.INFO)
        logger.addHandler(self.handler)

        # Set the architecture ListModel into the Adw.ComboRow for the
        # architecture list

        self.init_arch_list()

        # Connect UI actions

        self.connect_actions()

        # Show the main window

        self.detect_symbols_bar.set_revealed(False)
        self.present()

    def connect_actions(self):

        def show_about(*args):
            self.about_dialog.present(self)

        self.add_simple_action('show-about', show_about)

        def pick_file(*args):

            def file_picked(file_dialog: Gtk.FileDialog, task: Gio.Task):
                try:
                    result: Gio.File = file_dialog.open_finish(task)
                except GLib.GError as err:  # Dismissed by user
                    if err.message != 'Dismissed by user':
                        raise
                else:
                    self.update_kernel_path(
                        result.get_path(),
                        result.load_bytes(None)[0].get_data(),
                    )

            file_picker = Gtk.FileDialog()
            # file_picker.set_filters(Gio.ListStore())
            file_picker.open(self, callback=file_picked)

        self.add_simple_action('pick-file', pick_file)

        def copy_debug_information(*args):
            clipboard = Gdk.Display.get_default().get_clipboard()
            clipboard.set(self.handler.raw_log)
            toast = Adw.Toast.new('Debug information copied to clipboard')
            toast.set_timeout(3)
            self.offset_page_toast.add_toast(toast)

        self.add_simple_action(
            'copy-debug-information', copy_debug_information
        )

        def copy_offset_information(*args):
            raw_text = ''
            for index in range(self.offset_list_model.get_n_items()):
                item = self.offset_list_model.get_item(index)
                raw_text += '%s: %s\n' % (item.token, item.offset)
            clipboard = Gdk.Display.get_default().get_clipboard()
            clipboard.set(raw_text)
            toast = Adw.Toast.new('Offset information copied to clipboard')
            toast.set_timeout(3)
            self.offset_page_toast.add_toast(toast)

        self.add_simple_action(
            'copy-offset-information', copy_offset_information
        )

        def generate_elf_file(*args):
            print('TODO Implement generate_elf_file', args)

            def file_picked(file_dialog: Gtk.FileDialog, task: Gio.Task):
                try:
                    result: Gio.File = file_dialog.save_finish(task)
                except GLib.GError as err:  # Dismissed by user
                    if err.message != 'Dismissed by user':
                        raise
                else:
                    # TODO use some kind of thread + spinner

                    data = BytesIO()
                    ElfSymbolizer(
                        self.raw_kernel,
                        None,
                        data,
                        # TODO add more parameters
                    )

                    result.replace_contents(
                        data.getvalue(),
                        None,
                        False,
                        Gio.FileCreateFlags.NONE,
                        None,
                    )

                    # TODO popup if success or error
                    print('WIP OK')

            file_picker = Gtk.FileDialog()
            file_picker.set_initial_name(
                self.kernel_path.split('/').pop() + '-vmlinux.bin'
            )
            file_picker.save(self, callback=file_picked)

        self.add_simple_action('generate-elf-file', generate_elf_file)

        def export_symbols(*args):
            print('TODO Implement export_symbols', args)

        self.add_simple_action('export-symbols', export_symbols)

    def add_simple_action(self, name, callback):

        action = Gio.SimpleAction.new(name, None)
        action.connect('activate', callback)
        self.add_action(action)

    def init_arch_list(self):

        e_machine_model = Gtk.StringList()

        for e_machine in ElfMachine:
            e_machine_model.append(e_machine.name)

        self.e_machine_combo.set_model(e_machine_model)

    @Gtk.Template.Callback()
    def token_row_activated(self, *data):
        item: DetectedTokenRow = (
            self.offset_list_selection_model.get_selected_item()
        )
        text_buffer = '\nData for "%s" at %s:\n\n' % (item.token, item.offset)
        fd = BytesIO(self.raw_kernel)
        fd.seek(int(item.offset, 16))
        for i in range(100):
            for i in range(8):
                text_buffer += fd.read(1).hex() + ('\n' if i == 7 else ' ')
        self.hex_buffer.set_text(text_buffer)
        self.offset_selection_split_view.set_show_sidebar(True)

    @Gtk.Template.Callback()
    def symbol_row_activated(self, *data):
        print('TODO handle symbol_row_activated')

    @Gtk.Template.Callback()
    def sync_base_offset(self, *data):
        print('TODO handle sync_base_offset')

    def update_kernel_path(
        self,
        path: Optional[str],
        orig_data: Optional[bytes] = None,
        is_64_bits: Optional[bool] = None,
    ):

        if not path:
            return

        self.kernel_path = path
        if orig_data:
            self.kernel_orig_data = orig_data

        self.file_picker_button.set_title('Kernel blob')
        self.file_picker_button.set_subtitle(path)

        self.selection_spinner_row.set_visible(True)

        def detection_thread():

            bit_size = None
            if is_64_bits is not None:
                bit_size = 64 if is_64_bits else 32

            self.handler.flush()
            try:
                self.raw_kernel = obtain_raw_kernel_from_file(
                    self.kernel_orig_data
                )
                kallsyms = KallsymsFinder(
                    self.raw_kernel,
                    bit_size,
                )

            except ArchitectureGuessError:

                def update_ui_unknown_arch_cb(*args):

                    def bitness_pick_cb(source_obj, res, *data):
                        if dialog.choose_finish(res) == '32-bit':
                            self.update_kernel_path(path, None, False)
                        else:
                            self.update_kernel_path(path, None, True)

                    dialog = Adw.AlertDialog.new(
                        'The architecture of your kernel could not be guessed '
                        + 'successfully',
                        'Is your kernel 32-bit or 64-bit?',
                    )
                    dialog.add_response('32-bit', '32-bit')
                    dialog.add_response('64-bit', '64-bit')
                    dialog.set_default_response('32-bit')
                    dialog.set_close_response('32-bit')
                    dialog.choose(
                        self,
                        None,
                        bitness_pick_cb,
                    )

                GLib.idle_add(update_ui_unknown_arch_cb)

                raise

            except (
                ValueError,
                KallsymsNotFoundException,
                Exception,
            ) as err:
                # TODO Do actual error handling for all Python exceptions too?

                def update_ui_invalid_file_cb(err):

                    dialog = Adw.AlertDialog.new(
                        'Could not open kernel', str(err)
                    )
                    dialog.add_response('ok', 'Ok')
                    dialog.set_default_response('ok')
                    dialog.set_close_response('ok')
                    dialog.choose(
                        self,
                        None,
                        lambda source_obj, res, *data: dialog.choose_finish(
                            res
                        ),
                    )

                    # Hide the kernel version string

                    self.kernel_string_row.set_visible(False)

                    # Hide the "Analysis options" UI block

                    self.analysis_options.set_visible(False)

                    # Hide "Detect symbols button" pointing to view #2

                    self.detect_symbols_bar.set_revealed(False)

                GLib.idle_add(update_ui_invalid_file_cb, err)

                raise

            else:
                # Set and show metadata

                def update_ui_cb(*args):
                    # Display the kernel version string

                    self.kernel_string_row.set_visible(True)
                    self.kernel_string_row.set_subtitle(
                        kallsyms.version_string
                    )

                    # Display the "Analysis options" UI block

                    self.analysis_options.set_visible(True)

                    # Show guessed architecture

                    """
                    key = (
                        architecture_to_readable_name[
                            kallsyms.architecture
                        ]
                        if kallsyms.architecture
                        else 'Unknown'
                    )

                    self.architecture_combo.set_title(
                        'Architecture preset (auto-detect: %s)' % key
                    )
                    key = self.architecture_combo.get_model().find(key)
                    if key is not None:
                        self.architecture_combo.set_selected(key)
                    """

                    # Show guessed ELF Machine

                    key = (
                        ElfMachine(kallsyms.elf_machine).name
                        if kallsyms.elf_machine
                        else 'Unknown'
                    )

                    self.e_machine_combo.set_title(
                        'ELF machine (auto-detect: %s)' % key
                    )
                    key = self.e_machine_combo.get_model().find(key)
                    if key is not None:
                        self.e_machine_combo.set_selected(key)

                    # Show guessed bitness

                    is_64_bits = kallsyms.is_64_bits

                    self.bitness_switch.set_title(
                        '64-bit (auto-detect: %s)'
                        % ('yes' if is_64_bits else 'no')
                    )
                    self.bitness_switch.set_active(is_64_bits)

                    # Show guessed base address

                    if is_64_bits:
                        default_value = '%016x' % (
                            kallsyms.kernel_text_candidate or 0
                        )
                    else:
                        default_value = '%08x' % (
                            kallsyms.kernel_text_candidate or 0
                        )

                    self.base_address_entry.set_title(
                        'Base address, hexadecimal (auto-detect: %s)'
                        % default_value
                    )
                    self.base_address_entry.set_text(default_value)

                    # Show "Detect symbols button" pointing to view #2

                    self.detect_symbols_bar.set_revealed(True)

                    # Display detected offsets in view #2

                    data = {
                        'input_file_start': 0,
                        'kallsyms_addresses_or_offsets': kallsyms.kallsyms_addresses_or_offsets__offset,
                        'kallsyms_num_syms': kallsyms.kallsyms_num_syms__offset,
                        'kallsyms_names': kallsyms.kallsyms_names__offset,
                        'kallsyms_markers': kallsyms.kallsyms_markers__offset,
                        'kallsyms_token_table': kallsyms.kallsyms_token_table__offset,
                        'kallsyms_token_index': kallsyms.kallsyms_token_index__offset,
                        'kallsyms_token_index_end': kallsyms.kallsyms_token_index_end__offset,
                        'elf64_rela_start': kallsyms.elf64_rela_start,
                        'elf64_rela_end_excl': kallsyms.elf64_rela_end_excl,
                    }

                    selection_model = self.offset_list_selection_model

                    list_store = selection_model.get_model()
                    selection_model.set_model(None)
                    list_store.remove_all()

                    for key, value in data.items():
                        if value is not None:
                            list_store.append(
                                DetectedTokenRow(
                                    token=key,
                                    offset='%08x' % value,
                                )
                            )

                    selection_model.set_model(list_store)

                    # Prepare to display hex dump reacting to
                    # clicking offsets in view #2

                    self.offset_selection_split_view.set_show_sidebar(False)

                    # Display address in view #3

                    selection_model = self.symbol_table_selection_model

                    list_store = selection_model.get_model()
                    selection_model.set_model(None)
                    list_store.remove_all()

                    fmt = '%016x' if is_64_bits else '%08x'

                    for symbol in kallsyms.symbols:
                        list_store.append(
                            RecoveredSymbolRow(
                                name=symbol.name,
                                type=symbol.symbol_type.name,
                                address=fmt % symbol.virtual_address,
                            )
                        )

                    selection_model.set_model(list_store)

                GLib.idle_add(update_ui_cb)

            finally:

                def hide_spinner_cb(*args):
                    self.selection_spinner_row.set_visible(False)

                GLib.idle_add(hide_spinner_cb)

        thread = Thread(target=detection_thread)
        thread.daemon = True
        thread.start()


def main():
    """
    args = ArgumentParser()
    args.add_argument(
        '-v',
        '--verbose',
        help='Show extra debugging output',
        action='store_true',
    )

    args = args.parse_args()
    """

    logging.basicConfig(
        stream=stderr,
        # level=logging.DEBUG if args.verbose else logging.INFO,
        level=logging.INFO,
        format='%(message)s',
    )

    GLib.set_prgname('re.fossplant.vmlinux-to-elf')

    # TODO handle file open

    app = MyApp(
        application_id='re.fossplant.vmlinux-to-elf',
        flags=Gio.ApplicationFlags.NON_UNIQUE,
    )
    app.run(argv)


if __name__ == '__main__':
    main()
