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

    def __init__(self, stream):
        """Loads the PE file."""

        self.pe = pefile.PE(data=stream)
        self.info = {}

    def get_all(self):
        """Returns all available information."""

        self.get_summary()
        self.get_dos_header()
        self.get_file_header()
        self.get_optional_header()
        self.get_sections()
        self.get_imports()

        return self.info

    def get_summary(self):
        """Returns general information about the PE."""

        self.info["summary"] = {}

        if hex(self.pe.FILE_HEADER.Machine) == "0x14c":
            self.info["summary"]["arch"] = "x86"
        else:
            self.info["summary"]["arch"] = "x64"

        self.info["summary"]["imphash"] = self.pe.get_imphash()
        self.info["summary"]["compilation_date"] = self.pe.FILE_HEADER.\
                                                   dump_dict()["TimeDateStamp"]\
                                                   ["Value"].split("[")[1][:-1]
        self.info["summary"]["is_dll"] = self.pe.is_dll()
        self.info["summary"]["is_exe"] = self.pe.is_exe()
        self.info["summary"]["warnings"] = self.pe.get_warnings()

        if hasattr(self.pe, "VS_VERSIONINFO"):
            for idx in range(len(self.pe.VS_VERSIONINFO)):
                if hasattr(self.pe, "FileInfo") and len(self.pe.FileInfo) > idx:
                    for entry in self.pe.FileInfo[idx]:
                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                for str_entry in sorted(list(st_entry.entries.items())):
                                    self.info["summary"]\
                                    [str_entry[0].decode("utf-8")] = str_entry[1].decode("utf-8")

        return self.info["summary"]

    def get_dos_header(self):
        """Returns the PE DOS header."""

        self.info["dos_header"] = {}

        self.info["dos_header"]["e_magic"] = hex(self.pe.DOS_HEADER.e_magic)
        self.info["dos_header"]["e_cblp"] = hex(self.pe.DOS_HEADER.e_cblp)
        self.info["dos_header"]["e_cp"] = hex(self.pe.DOS_HEADER.e_cp)
        self.info["dos_header"]["e_crlc"] = hex(self.pe.DOS_HEADER.e_crlc)
        self.info["dos_header"]["e_cparhdr"] = hex(self.pe.DOS_HEADER.e_cparhdr)
        self.info["dos_header"]["e_minalloc"] = hex(self.pe.DOS_HEADER.e_minalloc)
        self.info["dos_header"]["e_maxalloc"] = hex(self.pe.DOS_HEADER.e_maxalloc)
        self.info["dos_header"]["e_ss"] = hex(self.pe.DOS_HEADER.e_ss)
        self.info["dos_header"]["e_sp"] = hex(self.pe.DOS_HEADER.e_sp)
        self.info["dos_header"]["e_csum"] = hex(self.pe.DOS_HEADER.e_csum)
        self.info["dos_header"]["e_ip"] = hex(self.pe.DOS_HEADER.e_ip)
        self.info["dos_header"]["e_cs"] = hex(self.pe.DOS_HEADER.e_cs)
        self.info["dos_header"]["e_oemid"] = hex(self.pe.DOS_HEADER.e_oemid)
        self.info["dos_header"]["e_oeminfo"] = hex(self.pe.DOS_HEADER.e_oeminfo)
        self.info["dos_header"]["e_lfanew"] = hex(self.pe.DOS_HEADER.e_lfanew)

        return self.info["dos_header"]

    def get_file_header(self):
        """Returns the PE file header."""

        self.info["file_header"] = {}

        if hex(self.pe.FILE_HEADER.Machine) == "0x14c":
            self.info["file_header"]["arch"] = "x86"
        else:
            self.info["file_header"]["arch"] = "x64"

        self.info["file_header"]["number_sections"] = self.pe.FILE_HEADER.NumberOfSections
        self.info["file_header"]["time_date_stamp"] = self.pe.FILE_HEADER.dump_dict()\
                                                      ["TimeDateStamp"]["Value"].split("[")[1][:-1]
        self.info["file_header"]["pointer_symbol_table"] = hex(self.pe.FILE_HEADER.\
                                                               PointerToSymbolTable)
        self.info["file_header"]["number_symbols"] = hex(self.pe.FILE_HEADER.NumberOfSymbols)
        self.info["file_header"]["size_optional_header"] = hex(self.pe.FILE_HEADER.\
                                                               SizeOfOptionalHeader)
        self.info["file_header"]["characteristics"] = []

        for flag in pefile.IMAGE_CHARACTERISTICS.values():
            if not isinstance(flag, int) and getattr(self.pe.FILE_HEADER, flag):
                self.info["file_header"]["characteristics"].append(flag)

        return self.info["file_header"]

    def get_optional_header(self):
        """Returns the PE optional header."""

        self.info["optional_header"] = {}

        self.info["optional_header"]["magic"] = hex(self.pe.OPTIONAL_HEADER.Magic)
        self.info["optional_header"]["image_base"] = hex(self.pe.OPTIONAL_HEADER.ImageBase)
        self.info["optional_header"]["file_alignment"] = hex(self.pe.OPTIONAL_HEADER.FileAlignment)
        self.info["optional_header"]["size_of_image"] = hex(self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.info["optional_header"]["dll_characteristics"] = hex(self.pe.OPTIONAL_HEADER.\
                                                                  DllCharacteristics)
        self.info["optional_header"]["data_dir"] = {}

        for entry in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            self.info["optional_header"]["data_dir"]\
                     [entry.name] = {"size" : entry.Size, "vaddress" : hex(entry.VirtualAddress)}

        return self.info["optional_header"]

    def get_sections(self):
        """Returns the PE sections."""

        self.info["sections"] = {}

        for section in self.pe.sections:
            self.info["sections"][section.Name.decode().rstrip("\x00")] = \
                                                {"vsize" : hex(section.Misc_VirtualSize),
                                                 "vaddress" : hex(section.VirtualAddress),
                                                 "size_raw_data" : hex(section.SizeOfRawData),
                                                 "pointer_to_raw" : hex(section.PointerToRawData),
                                                 "characteristics" : hex(section.Characteristics),
                                                 "entropy" : str(round(section.get_entropy(), 2)),
                                                 "md5" : str(section.get_hash_md5())}

        return self.info["sections"]

    def get_imports(self):
        """Returns the PE imports."""

        self.info["imports"] = {}

        for item in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = item.dll.decode()
            self.info["imports"][dll_name] = []
            for i in item.imports:
                if not i.name:
                    continue

                self.info["imports"][dll_name].append({"name" : i.name.decode(),
                                                       "address" : hex(i.address)})

        return self.info["imports"]
        