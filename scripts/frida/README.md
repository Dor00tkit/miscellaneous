# Frida Inject Toolkit

This project provides a Python script (`frida_inject.py`) to inject Frida JavaScript scripts into either a running or newly spawned process for dynamic analysis and instrumentation.

## Project Structure

```
.
├── frida_inject.py       # Main injection script
└── js/                   # Directory containing Frida JavaScript scripts
    ├── example1.js
    ├── example2.js
    └── ...
```

## Usage

```bash
python frida_inject.py -js "C:\path\to\ws32.js" [-pid <PID> | -program <exe>] [-argv "<args>"] [-print] [-log]
```

### Options

- `-js <path>`: Path to the Frida JS script to inject (**required**).
- `-pid <PID>`: PID of an already running target process.
- `-program <path>`: Path to a program to spawn and instrument.
- `-argv "<args>"`: Command-line arguments for the spawned program.
- `-print`: Print messages received from the script to the console.
- `-log`: Save output to a log file.

### Example

Inject into a running process:

```bash
python frida_inject.py -js "C:\path\to\ws32.js" -pid 1234 -print
```

Spawn a new process and inject:

```bash
python frida_inject.py -js "C:\path\to\ws32.js" -program "C:\Program Files (x86)\Nmap\ncat.exe" -argv "-l 8080" -print -log
```

## Requirements

- Python 3.x
- Frida Python bindings:
  ```bash
  pip install frida
  ```

## Notes

- Use `Ctrl+D` on Unix or `Ctrl+Z` on Windows to exit and detach cleanly.
- Logs will be written to `frida_logfile_<pid>.txt` or `frida_logfile_<program>.txt` depending on how the process was selected.