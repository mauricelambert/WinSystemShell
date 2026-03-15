![WinSystemShell Logo](https://mauricelambert.github.io/info/python/security/WinSystemShell_small.png "WinSystemShell logo")

# WinSystemShell

## Description

A local privilege escalation utility that allows elevating from an
administrator context to the SYSTEM account on Windows to perform
high-privilege operations.

## Requirements

This package require:

 - python3
 - python3 Standard Library

## Installation

### Pip

```bash
python3 -m pip install WinSystemShell
```

### Git

```bash
git clone "https://github.com/mauricelambert/WinSystemShell.git"
cd "WinSystemShell"
python3 -m pip install .
```

### Wget

```bash
wget https://github.com/mauricelambert/WinSystemShell/archive/refs/heads/main.zip
unzip main.zip
cd WinSystemShell-main
python3 -m pip install .
```

### cURL

```bash
curl -O https://github.com/mauricelambert/WinSystemShell/archive/refs/heads/main.zip
unzip main.zip
cd WinSystemShell-main
python3 -m pip install .
```

## Usages

### Command line

```bash
WinSystemShell              # Using CLI package executable
python3 -m WinSystemShell   # Using python module
python3 WinSystemShell.pyz  # Using python executable
WinSystemShell.exe          # Using python Windows executable

python WinSystemShell.py --executable C:\Windows\System32\cmd.exe --schtasks "SystemRunOnce.exe" --server-path C:\temp\server.py --pipein shellpipein --pipeout shellpipeout
```

### Python script

```python
from WinSystemShell import *

PipeClient(executable=r"C:\Windows\System32\cmd.exe", schtasks="SystemRunOnce.exe", server_path=r"C:\temp\server.py", pipein="shellpipein", pipeout="shellpipeout").run()
```

## Links

 - [Pypi](https://pypi.org/project/WinSystemShell)
 - [Github](https://github.com/mauricelambert/WinSystemShell)
 - [Documentation](https://mauricelambert.github.io/info/python/security/WinSystemShell.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/WinSystemShell.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/WinSystemShell.exe)
 - [Server Documentation](https://mauricelambert.github.io/info/python/security/SystemShellServer.html)
 - [Server Python executable](https://mauricelambert.github.io/info/python/security/SystemShellServer.pyz)
 - [Server Python Windows executable](https://mauricelambert.github.io/info/python/security/SystemShellServer.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
