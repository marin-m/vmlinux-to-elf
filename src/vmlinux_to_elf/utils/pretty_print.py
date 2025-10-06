#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-

from collections import OrderedDict


"""
    Pretty print a file name in an ASCII rectangle.
    
    :param header_text: The file name.
"""

def pretty_print_header(header_text):
    
    max_text_length = max(len(header_text), 72)
    
    print()
    print()
    
    print('+-%s-+' % ('-' * max_text_length))
    
    print('| %s |' % header_text.ljust(max_text_length))
    
    print('+-%s-+' % ('-' * max_text_length))


"""
    Turn a parsed C structure in a dict of human-readable key-value
    pairs, for displayal in ASCII tables
    
    :param ctypes_structure: A parsed ctypes structures to consume.
    
    :returns An OrderedDict of strings/strings.
"""

def structure_to_key_values_strings(ctypes_structure):
    
    key_values = OrderedDict()
    
    for key, ctype in (field[:2] for field in ctypes_structure._fields_):
        
        value = getattr(ctypes_structure, key)
        
        # Turn "key_name" into "Key name"
        
        pretty_key = key[0].upper() + key[1:]
        pretty_key = pretty_key.replace('_', ' ')
        
        # Stringify the value
        
        if type(value) == bytes: # Strings
            
            key_values[pretty_key] = value.decode('ascii')
        
        elif key in field_name_to_structure: # Integer enums
            
            try:
                enum_field = field_name_to_structure[key](value)
                
                key_values[pretty_key] = enum_field.name
            
            except ValueError:
            
                key_values[pretty_key] = str(value) + ' ?'
        
        elif type(value) == int: # Integer
            
            key_values[pretty_key] = '0x%08x' % value if value else 'N/A'
    
    return key_values


"""
    Return an ASCII table from a parsed C structure, with field names as
    column 1 and values as column 2.
"""

def pretty_print_structure(ctypes_structure):
    
    key_values = structure_to_key_values_strings(ctypes_structure)
    
    pretty_print_table(list(key_values.items()))


"""
    Return an ASCII table from an array of parsed C structures, with field names
    as row 1 and values as further rows.
"""

def pretty_print_array_of_structures(array_of_structures):
    
    if array_of_structures:
        
        key_values_pairs = [
            structure_to_key_values_strings(structure)
            
            for structure in array_of_structures
        ]
        
        pretty_print_table(
            [list(key_values_pairs[0].keys())] + # Row 1: field names
            
            [list(key_values.values()) for key_values in key_values_pairs] # Rows 2+: field values
        )


"""
    Return an ascii table from a list (rows) of list (columns) of strings (cells)
"""

def pretty_print_table(rows):
    
    # Calculate columns length
    
    number_of_columns = len(rows[0])
    
    column_to_max_length = [

        max(len(row[column]) for row in rows)
        
        for column in range(number_of_columns)
    ]
    
    # Do a nice table
    
    print()
    
    print('+-%s-+' % '---'.join('-' * max_len for max_len in column_to_max_length))
    
    for row in rows:
        
        print('| %s |' % ' | '.join(
        
            row[column].ljust(column_to_max_length[column])
            
            for column in range(number_of_columns))
        )
        
        print('+-%s-+' % '---'.join('-' * max_len for max_len in column_to_max_length))
        


from sys import path
from os.path import dirname, realpath

path.append(realpath(dirname(__file__)))

import elf

field_name_to_structure = {
    key.lower(): value for key, value in vars(elf).items()
    if 'FLAGS' not in key
}

