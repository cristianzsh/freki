"""
    Freki - malware analysis tool

    Copyright (C) 2020 Freki authors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import pefile

class PE:
    """Extracts PE information using the pefile library."""

    def __init__(self, _file):
        """Loads the PE file."""

        self.pe = pefile.PE(_file)
        self.info = {}

    def get_all(self):
        """Returns all available information."""

        self.get_pe_information()
        self.get_nt_header()
        self.get_file_header()
        self.get_optional_header()
        self.get_sections()
        self.get_imports()

        return self.info

    def get_pe_information(self):
        """Returns general information about the PE."""

        self.info["general"] = {}

        self.info["general"]["e_magic"] = hex(self.pe.DOS_HEADER.e_magic)
        self.info["general"]["e_lfnew"] = hex(self.pe.DOS_HEADER.e_lfanew)
        self.info["general"]["is_dll"] = self.pe.is_dll()
        self.info["general"]["is_exe"] = self.pe.is_exe()
        self.info["general"]["imphash"] = self.pe.get_imphash()
        self.info["general"]["warnings"] = self.pe.get_warnings()

        return self.info["general"]

    def get_nt_header(self):
        """Returns the PE NT header."""

        self.info["nt_header"] = {}

        self.info["nt_header"]["signature"] = hex(self.pe.NT_HEADERS.Signature)

        return self.info["nt_header"]

    def get_file_header(self):
        """Returns the PE file header."""

        self.info["file_header"] = {}

        if hex(self.pe.FILE_HEADER.Machine) == "0x14c":
            self.info["file_header"]["arch"] = "x86"
        else:
            self.info["file_header"]["arch"] = "x64"

        self.info["file_header"]["time_date_stamp"] = self.pe.FILE_HEADER.dump_dict()["TimeDateStamp"]["Value"].split("[")[1][:-1]
        self.info["file_header"]["number_sections"] = self.pe.FILE_HEADER.NumberOfSections
        self.info["file_header"]["characteristics_flags"] = hex(self.pe.FILE_HEADER.Characteristics)

        return self.info["file_header"]

    def get_optional_header(self):
        """Returns the PE optional header."""

        self.info["optional_header"] = {}

        self.info["optional_header"]["magic"] = hex(self.pe.OPTIONAL_HEADER.Magic)
        self.info["optional_header"]["image_base"] = hex(self.pe.OPTIONAL_HEADER.ImageBase)
        self.info["optional_header"]["file_alignment"] = hex(self.pe.OPTIONAL_HEADER.FileAlignment)
        self.info["optional_header"]["size_of_image"] = hex(self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.info["optional_header"]["dll_characteristics"] = hex(self.pe.OPTIONAL_HEADER.DllCharacteristics)
        self.info["optional_header"]["data_dir"] = {}

        for entry in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            self.info["optional_header"]["data_dir"][entry.name] = {"size" : entry.Size, "vaddress" : hex(entry.VirtualAddress)}

        return self.info["optional_header"]

    def get_sections(self):
        """Returns the PE sections."""

        self.info["sections"] = {}

        for section in self.pe.sections:
            self.info["sections"][section.Name.decode().rstrip("\x00")] = {"vsize" : hex(section.Misc_VirtualSize),
                                                                           "vaddress" : hex(section.VirtualAddress),
                                                                           "size_raw_data" : hex(section.SizeOfRawData),
                                                                           "pointer_to_raw" : hex(section.PointerToRawData),
                                                                           "characteristics" : hex(section.Characteristics),
                                                                           "entropy" : str(section.get_entropy())}

        return self.info["sections"]

    def get_imports(self):
        """Returns the PE imports."""

        self.info["imports"] = {}

        for item in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = item.dll.decode()
            self.info["imports"][dll_name] = []
            for i in item.imports:
                self.info["imports"][dll_name].append({"name" : i.name.decode(),
                                                       "address" : hex(i.address)})

        return self.info["imports"]
        