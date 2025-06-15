#!/usr/bin/env python3
from typing import Optional

# Based on https://github.com/Taiko2k/GTK4PythonTutorial?tab=readme-ov-file#ui-from-graphical-designer

import sys
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio

from kallsyms_finder import KallsymsFinder, ArchitectureGuessError, obtain_raw_kernel_from_file

class MyApp(Adw.Application):
    kernel_path : Optional[str] = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        # Create a Builder
        self.builder = Gtk.Builder()
        self.builder.add_from_file("gui.ui")
        
        self.file_picker_button : Adw.ActionRow = self.builder.get_object('file_picker_button')
        self.file_picker_button.connect('activated', self.pick_file)

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
            
            # TODO use parallel thread

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

            

app = MyApp(application_id="com.example.GtkApplication")
app.run(sys.argv)
