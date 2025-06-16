from pathlib import Path
import argparse
import frida
import shlex
import sys
import os


g_bLogToFile = False
g_bPrintMsg = False
g_log_file = None


def parse_args():
    parser = argparse.ArgumentParser(description='Inject frida JS to a new\\running process')
    parser.add_argument("-js", required=True, help='The target frida JS file path')
    parser.add_argument("-pid", required=False, help='The target process pid')
    parser.add_argument("-process_name", required=False, help='The target process name')
    parser.add_argument("-spawn_program", required=False, help='The target program file path to spawn')
    parser.add_argument("-argv", required=False, default="", help='The commandline for the program to run')
    parser.add_argument("-print", default=False, action="store_true", required=False,
                        help='Print sent messages')
    parser.add_argument("-log", required=False, action="store_true",default=False,
                        help='Optional output log file.')

    return parser.parse_args()


def on_message(message, data):
    global g_bPrintMsg, g_bLogToFile, g_log_file

    if message["type"] == "send":
        text = message["payload"]
    elif message["type"] == "error":
        text = f"[!] Error: {message['stack']}\n"

    if g_bPrintMsg:
        print(text)

    if g_bLogToFile:
        g_log_file.write(text)
        g_log_file.flush()

def main():
    global g_bPrintMsg, g_bLogToFile, g_log_file
    pid = None
    options = parse_args()
    with open(options.js) as fs:
        script_content = fs.read()

    if options.print:
        g_bPrintMsg = True

    if options.log:
        if options.pid:
            log_file_name = f"frida_logfile_{options.pid}.txt"
        elif options.process_name:
            process_name = Path(options.process_name).stem
            log_file_name = f"frida_logfile_{process_name}.txt"
        else:
            program_name = Path(options.spawn_program).stem
            log_file_name = f"frida_logfile_{program_name}.txt"
        g_bLogToFile = True
        g_log_file = open(log_file_name, "wt")
        print(f"[+] Create output file @ {os.path.abspath(log_file_name)}")

    if options.pid:
        pid = int(options.pid)
        session = frida.attach(pid)
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
    
    elif options.process_name:
        session = frida.attach(options.process_name)
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()

    elif options.spawn_program:
        program_path = os.path.abspath(options.spawn_program)
        final_argv = [program_path]
        if options.argv:
            list_argv = shlex.split(options.argv)
            final_argv = [program_path] + list_argv

        pid = frida.spawn(final_argv)
        session = frida.attach(pid)
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
        frida.resume(pid)
    else:
        return

    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        if g_bLogToFile:
            g_log_file.close()
        session.detach()
        if pid:
            frida.kill(pid)
        sys.exit(0)

if __name__ == "__main__":
    main()
