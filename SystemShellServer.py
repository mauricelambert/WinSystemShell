#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    A local privilege escalation utility that allows elevating from an
#    administrator context to the SYSTEM account on Windows to perform
#    high-privilege operations.
#    Copyright (C) 2026  WinSystemShell

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

'''
A local privilege escalation utility that allows elevating from an
administrator context to the SYSTEM account on Windows to perform
high-privilege operations.
'''

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = '''
A local privilege escalation utility that allows elevating from an
administrator context to the SYSTEM account on Windows to perform
high-privilege operations.
'''
__url__ = "https://github.com/mauricelambert/WinSystemShell"

# __all__ = []

__license__ = "GPL-3.0 License"
__copyright__ = '''
WinSystemShell  Copyright (C) 2026  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
'''
copyright = __copyright__
license = __license__

from ctypes import (
    Structure, WinDLL, c_uint32, c_void_p, c_int, sizeof, byref, POINTER
)
from ctypes.wintypes import LPCWSTR, DWORD
from typing import Optional
from os import dup2, execvp
from sys import argv, exit


class SecurityAttributes(Structure):
    """
    Windows SECURITY_ATTRIBUTES structure.
    """

    _fields_ = [
        ("nLength", c_uint32),
        ("lpSecurityDescriptor", c_void_p),
        ("bInheritHandle", c_int),
    ]


class PipeServer:
    """
    Named pipe server redirect offering a real console process.
    """

    PIPE_ACCESS_INBOUND = 0x00000001
    PIPE_ACCESS_OUTBOUND = 0x00000002
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000

    INVALID_HANDLE_VALUE = c_void_p(-1).value

    O_RDONLY = 0
    O_WRONLY = 1

    def __init__(
        self,
        executable: str = "cmd.exe",
        pipe_in: str = r"\\.\pipe\stdin_pipe",
        pipe_out: str = r"\\.\pipe\stdout_pipe",
    ):
        """
        Initialize the server and create named pipes.
        """

        self.kernel32 = WinDLL("kernel32", use_last_error=True)
        self.advapi32 = WinDLL("advapi32", use_last_error=True)
        self.crt = self._load_crt()

        self.pipe_in = pipe_in
        self.pipe_out = pipe_out
        self.executable = executable

        self.sa = self._create_security_attributes()

        self.h_in = self._create_pipe(
            self.pipe_in,
            self.PIPE_ACCESS_INBOUND
        )
        self.h_out = self._create_pipe(
            self.pipe_out,
            self.PIPE_ACCESS_OUTBOUND
        )

    @staticmethod
    def _load_crt():
        """
        Load the C runtime library.
        """

        try:
            return WinDLL("ucrtbase")
        except OSError:
            return WinDLL("msvcrt")

    def _create_everyone_security_descriptor(self) -> c_void_p:
        """
        Create a SECURITY_DESCRIPTOR allowing Everyone full access.
        """

        ConvertStringSecurityDescriptorToSecurityDescriptorW = (
            self.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
        )
        ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
            LPCWSTR,
            DWORD,
            POINTER(c_void_p),
            POINTER(DWORD),
        )

        SDDL_EVERYONE = "D:(A;;GA;;;WD)"  # Everyone / Generic All

        p_sd = c_void_p()
        sd_size = DWORD()

        if not ConvertStringSecurityDescriptorToSecurityDescriptorW(
            SDDL_EVERYONE,
            1,  # SDDL_REVISION_1
            byref(p_sd),
            byref(sd_size),
        ):
            raise OSError(self.kernel32.GetLastError())

        return p_sd

    def _create_security_attributes(self) -> SecurityAttributes:
        """
        Create security attributes with explicit Everyone DACL.
        """

        sa = SecurityAttributes()
        sa.nLength = sizeof(sa)
        sa.lpSecurityDescriptor = self._create_everyone_security_descriptor()
        sa.bInheritHandle = 0  # bonne pratique : pas d’héritage
        return sa

    def _create_pipe(self, name: str, access: int) -> c_void_p:
        """
        Create a Windows named pipe.
        """

        handle = self.kernel32.CreateNamedPipeW(
            name,
            access,
            self.PIPE_TYPE_BYTE | self.PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            byref(self.sa),
        )

        if handle == self.INVALID_HANDLE_VALUE:
            raise OSError(self.kernel32.GetLastError())

        return handle

    def wait_for_client(self):
        """
        Wait for the client to connect to the pipes.
        """

        self.kernel32.ConnectNamedPipe(self.h_in, None)
        self.kernel32.ConnectNamedPipe(self.h_out, None)

    def redirect_stdio(self):
        """
        Redirect stdin, stdout and stderr to the pipes.
        """

        open_osfhandle = self.crt._open_osfhandle
        open_osfhandle.argtypes = (c_void_p, c_int)
        open_osfhandle.restype = c_int

        fd_in = open_osfhandle(self.h_in, self.O_RDONLY)
        fd_out = open_osfhandle(self.h_out, self.O_WRONLY)

        if fd_in < 0 or fd_out < 0:
            raise RuntimeError("open_osfhandle failed")

        dup2(fd_in, 0)
        dup2(fd_out, 1)
        dup2(fd_out, 2)

    def exec_shell(self):
        """
        Execute the real Windows shell with redirected IO.
        """

        execvp(self.executable, [self.executable])

    def run(self):
        """
        Run the server lifecycle.
        """

        self.wait_for_client()
        self.redirect_stdio()
        self.exec_shell()


def main() -> int:
    """
    Entry point.
    """

    executable = argv[1]
    pipe_in = argv[2]
    pipe_out = argv[3]

    server = PipeServer(executable, pipe_in, pipe_out)
    server.run()
    return 0


if __name__ == "__main__":
    exit(main())
