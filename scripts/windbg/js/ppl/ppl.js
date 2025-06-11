// Helpers
const print = msg => host.diagnostics.debugLog(msg);
const println = msg => print(msg + "\n");
const hex = (num, padding = 0) => "0x" + num.toString(16).padStart(padding, "0");
const exec = cmd => host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd);

// Offsets
const EPROCESS_SIGNATURELEVEL_OFFSET = 0x5f8; // _EPROCESS.SignatureLevel Windows 11 24H2 x64, https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS
const LIST_PPL_PROCESSES_CMD = "dx -g -r2 @$cursession.Processes.Where(p => (p.KernelObject.Protection.Type != 0)).Select(p => new {Name = p.Name, PID = p.Id, SignatureLevel = p.KernelObject.SignatureLevel, SectionSignatureLevel = p.KernelObject.SectionSignatureLevel, ProtectionType = p.KernelObject.Protection.Type, ProtectionSigner = p.KernelObject.Protection.Signer,  ProtectionAudit = p.KernelObject.Protection.Audit})"

// Registers commands.
function initializeScript() {
    return [
        new host.apiVersionSupport(1, 9),
        new host.functionAlias(ListPPL, "list_ppl"),
        new host.functionAlias(DisablePPL, "disable_ppl"),
        new host.functionAlias(DisableAllPPL, "disable_all_ppl"),
        
    ];
}

function ListPPL() {
    let output = exec(LIST_PPL_PROCESSES_CMD);
    for (let line of output) {
        println(line);
    }
}

function GetProcessObjectByName(processName) {
    let processes = host.currentSession.Processes;

    for(let process of processes){
         if (process.Name.toLowerCase() === processName.toLowerCase()) {
            return process;
        }
    }

    return null;
}

function GetProcessObjectByPID(pid) {
    let processes = host.currentSession.Processes;

    for(let process of processes){
         if (process.Id == pid) {
            return process;
        }
    }

    return null;
}

function DisablePPL(input) {
    let process = null;

    if (typeof input === "string") {
        process = GetProcessObjectByName(input);
        if (!process) {
            println(`Cant find process name: ${input}`);
            return;
        }
    }

    else if (typeof input === "number") {
        process = GetProcessObjectByPID(input);
        if (!process) {
            println(`Cant find process id: ${hex(input)}`);
            return;
        }
    }

    else {
        println(`Error: Unexpected input type. Please provide a process name as a string (e.g "lsass.exe") or a PID (e.g 0x100)`);
        return;
    }

    let iEprocessAddr = process.KernelObject.address;
    println(`${process.Name} PID ${process.Id} EPROCESS @ ${hex(iEprocessAddr)}`);
    println(`\tOld SignatureLevel: ${process.KernelObject.SignatureLevel}`);
    println(`\tOld SectionSignatureLevel: ${process.KernelObject.SectionSignatureLevel}`);
    println(`\tOld Protection.Level: ${process.KernelObject.Protection.Level}`);
    println(`\tOld Protection.Type: ${process.KernelObject.Protection.Type}`);
    println(`\tOld Protection.Signer: ${process.KernelObject.Protection.Signer}`);
    println(`\tOld Protection.Audit: ${process.KernelObject.Protection.Audit}`);
    process.KernelObject.SignatureLevel = 0;
    process.KernelObject.SectionSignatureLevel = 0;
    process.KernelObject.Protection.Level = 0;
    process.KernelObject.Protection.Type = 0;
    process.KernelObject.Protection.Audit = 0;
    process.KernelObject.Protection.Signer = 0;
    println(`\tNew SignatureLevel: ${process.KernelObject.SignatureLevel}`);
    println(`\tNew SectionSignatureLevel: ${process.KernelObject.SectionSignatureLevel}`);
    println(`\tNew Protection.Level: ${process.KernelObject.Protection.Level}`);
    println(`\tNew Protection.Type: ${process.KernelObject.Protection.Type}`);
    println(`\tNew Protection.Signer: ${process.KernelObject.Protection.Signer}`);
    println(`\tNew Protection.Audit: ${process.KernelObject.Protection.Audit}`);
}

function DisableAllPPL() {
    let processes = host.currentSession.Processes;

    for(let process of processes){
         if (process.KernelObject.Protection.Type != 0) {
            println(`Disabling PPL: ${process.Name} PID ${process.Id}`);
            process.KernelObject.SignatureLevel = 0;
            process.KernelObject.SectionSignatureLevel = 0;
            process.KernelObject.Protection.Level = 0;
            process.KernelObject.Protection.Type = 0;
            process.KernelObject.Protection.Audit = 0;
            process.KernelObject.Protection.Signer = 0;
        }
    }

    return null;
}

function invokeScript() {
    println(`Usage: !list_ppl`);
    println(`Usage: !disable_ppl "process.exe" or !disable_ppl 0x100`);
    println(`Usage: !disable_all_ppl`);
}