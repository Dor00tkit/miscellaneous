# Frida Inject Toolkit

This project provides a Python script (`frida_inject.py`) to inject a Frida JavaScript (`.js`) file into either a running process or a newly spawned one, for dynamic analysis and instrumentation.

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
python frida_inject.py -js "<path to JS>" [ -pid <PID> | -process_name <name> | -spwan_program <exe> [-argv "<args>"] ] [-print] [-log]
```

### Arguments

- `-js <path>`: **(Required)** Path to the Frida JavaScript file to inject.
- `-pid <PID>`: Inject into an existing process by PID.
- `-process_name <name>`: Inject into a running process by name (e.g., `"notepad.exe"`).
- `-spawn_program <path>`: Spawn a new process and inject into it.
- `-argv "<args>"`: Command-line arguments for the spawned program.
- `-print`: Print messages sent from the Frida script to stdout.
- `-log`: Save messages to a log file (`frida_logfile_<pid|process|program>.txt`).

### Examples

**Inject into a running process by PID**:

```bash
python frida_inject.py -js "C:\path\to\ws32.js" -pid 1234 -print
```

**Inject into a running process by name**:

```bash
python frida_inject.py -js "C:\path\to\ws32.js" -process_name "notepad.exe" -log
```

**Spawn a new process with arguments and inject**:

```bash
python frida_inject.py -js "C:\path\to\ws32.js" -spawn_program "C:\Program Files\Nmap\ncat.exe" -argv "-l 8080" -print -log
```

## Output

- If `-print` is used, messages from the Frida script will be printed to the console.
- If `-log` is used, messages will also be saved to a file:
  - Named based on the target:
    - `frida_logfile_<pid>.txt`
    - `frida_logfile_<process_name>.txt`
    - `frida_logfile_<program>.txt`

## Requirements

- Python 3.x
- [Frida](https://frida.re) Python bindings:

```bash
pip install frida
```

## Notes

- To cleanly detach from the instrumented process, use:
  - `Ctrl+D` on Unix
  - `Ctrl+Z` then `Enter` on Windows (cmd.exe)
- If a process is spawned, it will be resumed only after the script is injected.
- If logging is enabled, the log file is flushed continuously during execution.