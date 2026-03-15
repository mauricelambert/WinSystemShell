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
    Structure, Union, WinDLL, c_void_p, c_uint32, c_ushort, c_int, c_wchar,
    create_string_buffer, byref
)
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from os.path import dirname, join, abspath, isfile
from string import ascii_letters, digits
from sys import executable, stdout, exit
from random import randrange, choices
from ctypes.wintypes import HANDLE
from urllib.request import urlopen
from shutil import copyfileobj
from subprocess import Popen
from typing import Tuple
from time import sleep
from re import match 


PIPEDIR: str = "\\\\.\\pipe\\"
SERVER_PATH: str = abspath(join(dirname(__file__), "SystemShellServer.py"))
CMD: str = r"C:\Windows\System32\cmd.exe"

class OVERLAPPED(Structure):
    """
    Represents the Windows OVERLAPPED structure for asynchronous I/O.
    """

    _fields_ = [
        ("Internal", c_void_p),
        ("InternalHigh", c_void_p),
        ("Offset", c_uint32),
        ("OffsetHigh", c_uint32),
        ("hEvent", c_void_p),
    ]

class KEY_EVENT_RECORD(Structure):
    """
    Represents a key event in the Windows console input.
    """

    _fields_ = [
        ("bKeyDown", c_int),
        ("wRepeatCount", c_ushort),
        ("wVirtualKeyCode", c_ushort),
        ("wVirtualScanCode", c_ushort),
        ("uChar", c_wchar),
        ("dwControlKeyState", c_uint32),
    ]

class INPUT_RECORD(Structure):
    """
    Represents a console input record.
    """

    class _U(Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]
    _fields_ = [
        ("EventType", c_ushort),
        ("Event", _U),
    ]

class PipeClient:
    """
    Client for communicating with a server via named pipes.
    """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_OVERLAPPED = 0x40000000
    STD_OUTPUT_HANDLE = -11
    STD_INPUT_HANDLE = -10
    WAIT_OBJECT_0 = 0
    ERROR_IO_PENDING = 997
    ERROR_BROKEN_PIPE = 109
    KEY_EVENT = 0x0001

    def __init__(
    	self,
    	executable: str = CMD,
    	server_path: str = SERVER_PATH,
    	schtasks: str = None,
    	pipein: str = None,
    	pipeout: str = None,
    ):
        """
        Initialize pipes and console handles, and start the server process.
        """

        self.executable = executable
        self.server_path = server_path
        self.schtasks = schtasks
        self.pipe_in = PIPEDIR + (pipein or self._gen_random_name())
        self.pipe_out = PIPEDIR + (pipeout or self._gen_random_name())
        
        self.kernel32 = WinDLL("kernel32", use_last_error=True)
        self.source_cp = self.kernel32.GetACP()
        self.destination_cp = self.kernel32.GetOEMCP()
        self._start_server()
        sleep(5)
        self.h_in = self._open_pipe(self.pipe_in, self.GENERIC_WRITE)
        self.h_out = self._open_pipe(self.pipe_out, self.GENERIC_READ)
        self.h_console_out = self.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
        self.h_console_in = self.kernel32.GetStdHandle(self.STD_INPUT_HANDLE)
        self.ov, self.buf = self.start_pipe_read()
        self.running = True

        self._input_buffer = ""

    @staticmethod
    def _gen_random_name() -> str:
        """
        Generate a random name.
        """

        return "".join(choices(ascii_letters + digits, k=randrange(1, 10)))

    def _start_server(self) -> None:
        """
        Launch the server process with pipe arguments.
        """
        
        server_cmd = f'"\"{executable}\" \"{self.server_path}\" \"{self.executable}\" \"{self.pipe_in}\" \"{self.pipe_out}\"'

        if self.schtasks is None:
            schtasks = r"C:\Windows\System32\schtasks.exe"
            task_cmd = (
                f'"{CMD}" /c '
                + server_cmd +
                f' & \"{schtasks}\" /delete /tn RunOnceSystem /f"'
            )
            
            if len(task_cmd) > 255:
                 task_cmd = server_cmd
            
            Popen(
                [
                   schtasks,
                   "/create",
                   "/tn", "RunOnceSystem",
                   "/tr", task_cmd,
                   "/sc", "once",
                   "/st", "00:00",
                   "/ru", "SYSTEM",
                   "/rl", "HIGHEST",
                   "/f"
                ],
                close_fds=True
            ).communicate()
            Popen([schtasks, "/run", "/tn", "RunOnceSystem"]).communicate()
        else:
            schtasks = self.schtasks
            task_cmd = server_cmd

            Popen([schtasks, self._gen_random_name(), self._gen_random_name(), CMD, "/c " + task_cmd]).communicate()

        # Popen(
            # [executable,
             # join(dirname(__file__), "server_test1.py"),
             # # str(self.source_cp),
             # self.executable,
             # self.pipe_in,
             # self.pipe_out],
            # stdin=None, stdout=None, stderr=None, close_fds=True
        # )

    def _open_pipe(self, name: str, access: int) -> HANDLE:
        """
        Open a named pipe for reading or writing.
        """

        handle = self.kernel32.CreateFileW(
            name, access, 0, None, self.OPEN_EXISTING,
            self.FILE_FLAG_OVERLAPPED, None
        )
        if not handle:
            raise OSError(self.kernel32.GetLastError())
        return handle

    def start_pipe_read(self) -> Tuple[OVERLAPPED, bytes]:
        """
        Start an asynchronous read from the output pipe.
        """

        ov = OVERLAPPED()
        ov.hEvent = self.kernel32.CreateEventW(None, True, False, None)
        buf = create_string_buffer(4096)
        ok = self.kernel32.ReadFile(self.h_out, buf, 4096, None, byref(ov))
        last_error = self.kernel32.GetLastError()
        if last_error == self.ERROR_BROKEN_PIPE:
            self.running = False
            return ov, buf
        if not ok and last_error != self.ERROR_IO_PENDING:
            raise OSError(self.kernel32.GetLastError())
        return ov, buf

    def run(self) -> int:
        """
        Run the main loop reading from the pipe and console.
        """
        
        while self.running:
            result = self.kernel32.WaitForSingleObject(self.ov.hEvent, 50)
            if result == self.WAIT_OBJECT_0:
                self._process_pipe_output()
                self.ov, self.buf = self.start_pipe_read()
            if not self._process_console_input():
                break
            
        return 0

    def _process_pipe_output(self) -> None:
        """
        Read data from the pipe and write it to the console.
        """

        read = c_uint32()
        self.kernel32.GetOverlappedResult(self.h_out, byref(self.ov), byref(read), False)
        if read.value == 0:
            return
        needed = self.kernel32.MultiByteToWideChar(
            self.destination_cp, 0, self.buf, read.value, None, 0
        )
        if needed:
            wbuf = (c_wchar * needed)()
            self.kernel32.MultiByteToWideChar(self.destination_cp, 0, self.buf,
                                              read.value, wbuf, needed)
            written = c_uint32()
            self.kernel32.WriteConsoleW(self.h_console_out, wbuf, needed, byref(written), None)
        # written = c_uint32()
        # self.kernel32.WriteConsoleW(self.h_console_out, self.buf.value.decode("oem"), read.value, byref(written), None)
        self.kernel32.ResetEvent(self.ov.hEvent)

    def _process_console_input(self) -> int:
        """
        Read console input and send key presses to the server.
        """
        
        def remove_line():
            stdout.write("\x08" * len(self._input_buffer) + " " * len(self._input_buffer) + "\x08" * len(self._input_buffer))
            self._input_buffer = ""
            stdout.flush()

        events = c_uint32()
        self.kernel32.GetNumberOfConsoleInputEvents(self.h_console_in, byref(events))
        if not events.value:
            return 4

        rec = INPUT_RECORD()
        read_ev = c_uint32()
        self.kernel32.ReadConsoleInputW(self.h_console_in, byref(rec), 1, byref(read_ev))
        if rec.EventType == self.KEY_EVENT and rec.Event.KeyEvent.bKeyDown:

            ch = rec.Event.KeyEvent.uChar
            if ch == '\r':
                line = self._input_buffer + '\r\n'
                data = line.encode("oem")
                # data = line.encode("mbcs")
                ov_in = OVERLAPPED()
                ov_in.hEvent = self.kernel32.CreateEventW(None, True, False, None)
                remove_line()
                self.kernel32.WriteFile(self.h_in, data, len(data), None, byref(ov_in))
                return 2
            elif ch == '\x08':
                if not self._input_buffer:
                    return 5
                self._input_buffer = self._input_buffer[:-1]
                stdout.write(ch + " ")
            elif ch == "\x1b":
                remove_line()
                return 3
            elif ch == "\x1A":
                return 0
            elif ch and ch != "\0" and ch != "\7" and ch != "\x09":
                self._input_buffer += ch
            
            stdout.write(ch)
            stdout.flush()
        return 1
        
def existing_file(path: str) -> str:
    """
    Validate that the given path points to an existing file.

    Args:
        path: Path to the file.

    Returns:
        The validated file path.

    Raises:
        ArgumentTypeError: If the file does not exist.
    """

    if not isfile(path):
        raise ArgumentTypeError(f"File does not exist: {path}")
    return path

def valid_windows_path(path: str) -> str:
    """
    Validate that the provided string looks like a valid Windows file path.

    This performs a basic validation by checking that the path starts
    with a drive letter followed by a backslash (e.g., C:\\).

    Args:
        path: Windows file path.

    Returns:
        The validated path.

    Raises:
        ArgumentTypeError: If the path does not match the expected format.
    """

    path = abspath(path)
    if not match("^[a-zA-Z]:\\\\", path):
        raise ArgumentTypeError(f"Invalid Windows path: {path}")
    return path

def valid_pipe_name(name: str) -> str:
    """
    Validate a Windows named pipe name.

    Only allows alphanumeric characters, dots, underscores,
    and hyphens. The full pipe path (\\\\.\\pipe\\) is not required.

    Args:
        name: Pipe name.

    Returns:
        The validated pipe name.

    Raises:
        ArgumentTypeError: If the pipe name contains invalid characters.
    """

    if not match(r"^[a-zA-Z0-9._-]+$", name):
        raise ArgumentTypeError(f"Invalid pipe name: {name}")
    return name
    
def parse_args() -> Namespace:
    r"""
    Parse and validate command-line arguments.
    
    python WinSystemShell.py --executable C:\Windows\System32\cmd.exe --schtasks "SystemRunOnce.exe" --server-path C:\temp\server.py --pipein shellpipein --pipeout shellpipeout

    Returns:
        Namespace containing parsed arguments:
            executable: Path to an existing executable file.
            schtasks: Path to SystemRunOnce.exe, if not defined the default schtasks was used.
            server_path: Windows path to the server executable.
            pipein: Name of the input named pipe.
            pipeout: Name of the output named pipe.
    """

    parser = ArgumentParser(description="Spawn an interactive shell as the Windows SYSTEM account.")

    parser.add_argument(
        "--executable",
        default="C:\\Windows\\System32\\cmd.exe",
        type=existing_file,
        help="Path to the executable file (must exist)."
    )

    parser.add_argument(
        "--schtasks",
        help=(
            "Path to SystemRunOnce.exe. If not exists this script download it."
            " If not used this script use the lolbin schtasks."
        )
    )

    parser.add_argument(
        "--server-path",
        default=SERVER_PATH,
        type=valid_windows_path,
        help="Valid Windows path where the server will be stored."
    )

    parser.add_argument(
        "--pipein",
        type=valid_pipe_name,
        help="Name of the input named pipe."
    )

    parser.add_argument(
        "--pipeout",
        type=valid_pipe_name,
        help="Name of the output named pipe."
    )

    return parser.parse_args()
    
def main() -> int:
    """
    The main function to start the script from the command line.
    """
    
    print(copyright)
    arguments = parse_args()
    
    if arguments.schtasks and not isfile(arguments.schtasks):
        with open(arguments.schtasks, "wb") as file:
            copyfileobj(urlopen("https://github.com/mauricelambert/WinSystemShell/releases/download/v0.0.1/SystemRunOnce.exe"), file)
    
    PipeClient(**vars(arguments)).run()
    return 0


if __name__ == "__main__":
    exit(main())
