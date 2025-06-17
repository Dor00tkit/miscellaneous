const bSEND = true;
const bPRINT = false;

// ntdll.dll
const sNtdll = "ntdll.dll";
LoadDLLSymbols(sNtdll);
const NtAlpcCreatePortPtr = Module.getExportByName(sNtdll, "NtAlpcCreatePort");
const NtAlpcAcceptConnectPortPtr = Module.getExportByName(sNtdll, "NtAlpcAcceptConnectPort")
const NtAlpcConnectPortPtr = Module.getExportByName(sNtdll, "NtAlpcConnectPort")
const NtAlpcConnectPortExPtr = Module.getExportByName(sNtdll, "NtAlpcConnectPortEx")
const NtAlpcSendWaitReceivePortPtr = Module.getExportByName(sNtdll, "NtAlpcSendWaitReceivePort");
const NtImpersonateClientOfPortPtr = Module.getExportByName(sNtdll, "NtImpersonateClientOfPort");
const NtAlpcCreatePortSectionPtr = Module.getExportByName(sNtdll, "NtAlpcCreatePortSection");
const NtAlpcCreateSectionViewPtr = Module.getExportByName(sNtdll, "NtAlpcCreateSectionView");

// Helpers
function LogOutput(msg, bStackTrace=false) {
    // send the output to frida-python script
	if (bSEND) {
        send(msg + '\n');
        if (bStackTrace) {
            send(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'))
        }
    }

    if (bPRINT) {
        console.log('\n' + msg);
        if (bStackTrace) {
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'))
        }
    }
}

function LoadDLLSymbols(dll_name) {
	try {
		DebugSymbol.load(dll_name);
	}
	catch (err) {
		LogOutput("[-] Error while try loading symbols for " + dll_name + " error code: " + err);
		try{
			LogOutput("[?] trying to load module:" + dll_name);
			Module.load(dll_name);
			DebugSymbol.load(dll_name);
		}
		catch (err) {
			LogOutput("[+] Failed to load " + dll_name);
			return 0;
		}
	}
	LogOutput("[+] DebugSymbol.load(" + dll_name + ")");
}

function printObjectAttributes(objectAttributes) {
    if (objectAttributes.isNull()) {
        LogOutput("    ObjectAttributes: NULL");
        return;
    }

    try {
        // OBJECT_ATTRIBUTES layout:
        // ULONG Length;
        // HANDLE RootDirectory;
        // PUNICODE_STRING ObjectName;
        // ULONG Attributes;
        // PVOID SecurityDescriptor;
        // PVOID SecurityQualityOfService;

        const length = objectAttributes.readU32();
        const rootDirectory = objectAttributes.add(8).readPointer();
        const objectNamePtr = objectAttributes.add(0x10).readPointer();
        const attributes = objectAttributes.add(0x18).readU32();
        const securityDescriptor = objectAttributes.add(0x20).readPointer();
        const securityQoS = objectAttributes.add(0x28).readPointer();

        LogOutput("    ObjectAttributes:");
        LogOutput("        Length: 0x" + length.toString(16));
        LogOutput("        RootDirectory: " + rootDirectory);
        LogOutput("        Attributes: 0x" + attributes.toString(16));
        LogOutput("        SecurityDescriptor: " + securityDescriptor);
        LogOutput("        SecurityQualityOfService: " + securityQoS);

        if (!objectNamePtr.isNull()) {
            const nameLength = objectNamePtr.readU16();
            const maxLength = objectNamePtr.add(2).readU16();
            const nameBuffer = objectNamePtr.add(8).readPointer();
            let portName = "";
            if (!nameBuffer.isNull() && nameLength > 0) {
                portName = nameBuffer.readUtf16String(nameLength / 2);
            }
            LogOutput("        ObjectName: " + portName);
        } else {
            LogOutput("        ObjectName: NULL");
        }
    } catch (e) {
        LogOutput("    Failed to parse ObjectAttributes: " + e);
    }
}

function parsePortMessage(ptr) {
    if (ptr.isNull()) {
        return "[NULL]";
    }

    try {
        const dataLength     = ptr.readU16();           // u1.s1.DataLength
        const totalLength    = ptr.add(2).readU16();    // u1.s1.TotalLength
        const type           = ptr.add(4).readU16();    // u2.s2.Type
        const dataInfoOffset = ptr.add(6).readU16();    // u2.s2.DataInfoOffset
        const clientPid      = ptr.add(8).readU32();    // ClientId.UniqueProcess
        const clientTid      = ptr.add(12).readU32();   // ClientId.UniqueThread
        const messageId      = ptr.add(16).readU32();   // MessageId
        const callbackId     = ptr.add(20).readU32();   // ClientViewSize or CallbackId

        const messageTypes = {
            0: "None", 1: "Request", 2: "Reply", 3: "Datagram", 4: "LostReply",
            5: "PortClosed", 6: "ClientDied", 7: "Exception", 8: "DebugEvent",
            9: "ErrorEvent", 10: "ConnectionRequest", 11: "ConnectionReply",
            12: "UNKNOWN12", 13: "PortDisconnected"
        };

        const typeStr = messageTypes[type & 0xFF] || `Unknown(${type})`;

        let output = [
            `    \tType: ${typeStr}`,
            `    \tDataLength: 0x${dataLength.toString(16)}`,
            `    \tTotalLength: 0x${totalLength.toString(16)}`,
            `    \tDataInfoOffset: 0x${dataInfoOffset.toString(16)}`,
            `    \tClientId: PID=${clientPid} TID=${clientTid}`,
            `    \tMessageId: 0x${messageId.toString(16)}`,
            `    \tCallbackId/ClientViewSize: 0x${callbackId.toString(16)}`
        ];

        const payloadPtr = ptr.add(0x28);

        if (dataLength > 0 && dataLength < 0x1000) {
            try {
                output.push("    Raw Data:");
                output.push(hexdump(payloadPtr, {
                    length: dataLength,
                    header: false,
                    ansi: false
                }));
            } catch (dumpErr) {
                output.push(`    (Failed to dump payload: ${dumpErr})`);
            }
        } else {
            output.push("    (Skipping payload dump due to DataLength is 0 or invalid or too large DataLength)");
        }

        return output.join('\n');

    } catch (e) {
        return `Error parsing PORT_MESSAGE at ${ptr}: ${e}`;
    }
}

function printValidMessageAttributes(ptrAttr) {
    const AlpcGetMessageAttribute = new NativeFunction(
        Module.getExportByName("ntdll.dll", "AlpcGetMessageAttribute"),
        'pointer', ['pointer', 'uint']
    );

    const ATTR = {
        TOKEN:  0x08000000,
        SECURITY: 0x80000000,
        CONTEXT: 0x20000000,
        VIEW: 0x40000000,
        HANDLE: 0x10000000,
        DIRECT: 0x04000000,
        WOBA: 0x02000000 // Work on Behalf Attribute
    };

    if (ptrAttr.isNull()) {
        LogOutput("[-] ALPC_MESSAGE_ATTRIBUTES is NULL");
        return;
    }

    const valid = ptrAttr.add(4).readU32();
    LogOutput(`[*] Valid Message Attributes: 0x${valid.toString(16)}`);

    function tryAttr(flag, name, handler) {
        if (valid & flag) {
            console.log(`\t${name}`);
            const attrPtr = AlpcGetMessageAttribute(ptrAttr, flag);
            if (!attrPtr.isNull()) {
                try {
                    handler(attrPtr);
                } catch (e) {
                    console.log(`\t  [!] Failed to parse ${name}: ${e}`);
                }
            } else {
                console.log(`\t  [!] ${name} attribute pointer is NULL`);
            }
        }
    }

    tryAttr(ATTR.TOKEN, "ALPC_MESSAGE_TOKEN_ATTRIBUTE", p => {
        const tokenId = p.readU64();
        const authId = p.add(8).readU64();
        const modifiedId = p.add(16).readU64();
        LogOutput(`\t  TokenId=0x${tokenId.toString(16)}, AuthId=0x${authId.toString(16)}, ModifiedId=0x${modifiedId.toString(16)}`);
    });

    tryAttr(ATTR.SECURITY, "ALPC_MESSAGE_SECURITY_ATTRIBUTE", p => {
        const flags = p.readU32();
        const qosPtr = p.add(8).readPointer();
        const ctxHandle = p.add(0x10).readPointer();
        LogOutput(`\t  Flags=0x${flags.toString(16)}, ContextHandle=${ctxHandle}`);
        if (!qosPtr.isNull()) {
            const impersonationLevel = qosPtr.add(4).readU32();
            console.log(`\t  QOS.ImpersonationLevel=${impersonationLevel}`);
        }
    });

    tryAttr(ATTR.CONTEXT, "ALPC_MESSAGE_CONTEXT_ATTRIBUTE", p => {
    const portContext = p.readPointer();
    const messageContext = p.add(8).readPointer();
    const sequence = p.add(0x10).readU32();
    const messageId = p.add(0x18).readU32();
    const callbackId = p.add(0x20).readU32();

    LogOutput(`\t  PortContext=${portContext} | MessageContext=${messageContext}`);
    LogOutput(`\t  Sequence=0x${sequence.toString(16)} | MessageId=0x${messageId.toString(16)} | CallbackId=0x${callbackId.toString(16)}`);
    });


    tryAttr(ATTR.VIEW, "ALPC_MESSAGE_VIEW_ATTRIBUTE", p => {
        const flags = p.readU32();
        const sectionHandle =  p.add(8).readPointer();
        const viewBase = p.add(0x10).readPointer();
        const viewSize = p.add(0x18).readU64();
        LogOutput("\t  Flags: 0x" + flags.toString(16));
        LogOutput("\t  SectionHandle: 0x" + sectionHandle.toString(16));
        LogOutput("\t  ViewBase: 0x" + viewBase.toString(16));
        LogOutput("\t  ViewSize: 0x" + viewSize.toString(16));
    });

    tryAttr(ATTR.HANDLE, "ALPC_MESSAGE_HANDLE_ATTRIBUTE", p => {
        const flags = p.readU32();
        const handle = p.add(8).readPointer();
        const objectType = p.add(0x10).readU32();
        const desiredAccess = p.add(0x18).readU32();
        LogOutput(`\t  Flags=0x${flags.toString(16)}, Handle=${handle}, ObjectType=0x${objectType.toString(16)}, Access=0x${desiredAccess.toString(16)}`);
    });

    tryAttr(ATTR.DIRECT, "ALPC_MESSAGE_DIRECT_ATTRIBUTE", p => {
        const eventHandle = p.readPointer();
        LogOutput(`\t  Event=${eventHandle}`);
    });

    tryAttr(ATTR.WOBA, "ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE", p => {
        const ticket = p.readU64();
        LogOutput(`\t  Work-On-Behalf Ticket=0x${ticket.toString(16)}`);
    });

    const knownFlags = Object.values(ATTR).reduce((a, b) => a | b, 0);
    const unknownFlags = valid & ~knownFlags;
    if (unknownFlags !== 0) {
        LogOutput(`\t  Unknown Attribute Flags: 0x${unknownFlags.toString(16)}`);
    }
}

// Hooks

// --- ntdll!NtAlpcCreatePort ---
Interceptor.attach(NtAlpcCreatePortPtr, {
    onEnter(args) {
        this.portHandlePtr = args[0];
        this.objectAttributes = args[1];

        LogOutput("[+] NtAlpcCreatePort called");

        printObjectAttributes(this.objectAttributes);

    },

    onLeave(retval) {
        if (this.portHandlePtr) {
            const handle = this.portHandlePtr.readPointer();
            LogOutput("    Returned handle: " + handle);
        }
    }
});

// --- ntdll!NtAlpcAcceptConnectPort ---
Interceptor.attach(NtAlpcAcceptConnectPortPtr, {
    onEnter(args) {
        this.portHandlePtr = args[0]; // OUT
        this.connectionPortHandle = args[1]; // IN
        this.flags = args[2].toInt32(); // IN
        this.objectAttributes = args[3]; // IN_OPT
        this.portAttributes = args[4]; // IN_OPT
        this.portContext = args[5]; // IN_OPT
        this.connectionRequest = args[6]; // IN
        this.connectionMessageAttributes = args[7]; // INOUT_OPT
        this.acceptConnection = args[8]; // IN

        LogOutput("[+] NtAlpcAcceptConnectPort called");

        LogOutput("    ConnectionPortHandle: " + this.connectionPortHandle);
        LogOutput("    Flags: 0x" + this.flags.toString(16));

        printObjectAttributes(this.objectAttributes);

        LogOutput("    PortContext: " + this.portContext);

        if (!this.portAttributes.isNull()) {
            LogOutput("    PortAttributes: " + this.portAttributes);
        } else {
            LogOutput("    PortAttributes: NULL");
        }

        if (!this.connectionRequest.isNull()) {
            try {
                LogOutput("    ConnectionRequest:");
                LogOutput(parsePortMessage(this.connectionRequest));
            } catch (e) {
                LogOutput("    Failed to parse ConnectionRequest: " + e);
            }
        } else {
            LogOutput("    ConnectionRequest: NULL");
        }

        if (!this.connectionMessageAttributes.isNull()) {
            try {
                LogOutput("    ConnectionMessageAttributes (IN):");
                printValidMessageAttributes(this.connectionMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse ConnectionMessageAttributes: " + e);
            }
        } else {
            LogOutput("    ConnectionMessageAttributes: NULL");
        }

        LogOutput("    AcceptConnection: " + this.acceptConnection);
    },

    onLeave(retval) {
        LogOutput("[-] NtAlpcAcceptConnectPort returned: 0x" + retval.toString(16));

        if (!this.portHandlePtr.isNull()) {
            try {
                const outHandle = this.portHandlePtr.readPointer();
                LogOutput("    PortHandle (OUT): " + outHandle);
            } catch (e) {
                LogOutput("    Failed to read PortHandle: " + e);
            }
        }

        if (!this.connectionMessageAttributes.isNull()) {
            try {
                LogOutput("    ConnectionMessageAttributes (OUT):");
                printValidMessageAttributes(this.connectionMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse updated ConnectionMessageAttributes: " + e);
            }
        }
    }
});

// --- ntdll!NtAlpcConnectPort ---
Interceptor.attach(NtAlpcConnectPortPtr, {
    onEnter(args) {
        this.portHandlePtr = args[0];             // OUT
        this.portName = args[1];                  // IN
        this.objectAttributes = args[2];          // IN_OPT
        this.portAttributes = args[3];            // IN_OPT
        this.flags = args[4].toInt32();           // IN
        this.requiredServerSid = args[5];         // IN_OPT
        this.connectionMessage = args[6];         // INOUT
        this.bufferLengthPtr = args[7];           // INOUT
        this.outMessageAttributes = args[8];      // INOUT_OPT
        this.inMessageAttributes = args[9];       // INOUT_OPT
        this.timeout = args[10];                  // IN_OPT

        LogOutput("[+] NtAlpcConnectPort called");

        if (!this.portName.isNull()) {
            try {
                const len = this.portName.readU16();
                const max = this.portName.add(2).readU16();
                const buf = this.portName.add(8).readPointer();
                const name = (len > 0 && !buf.isNull()) ? buf.readUtf16String(len / 2) : "<empty>";
                LogOutput("    PortName: " + name);
            } catch (e) {
                LogOutput("    PortName: <failed to parse> " + e);
                LogOutput("    PortName Address: " + this.portHandlePtr.toString(16));
            }
        } else {
            LogOutput("    PortName: NULL");
        }

        printObjectAttributes(this.objectAttributes);

        if (!this.portAttributes.isNull()) {
            LogOutput("    PortAttributes: " + this.portAttributes);
        } else {
            LogOutput("    PortAttributes: NULL");
        }

        LogOutput("    Flags: 0x" + this.flags.toString(16));

        if (!this.requiredServerSid.isNull()) {
            LogOutput("    RequiredServerSid: " + this.requiredServerSid);
        } else {
            LogOutput("    RequiredServerSid: NULL");
        }

        if (!this.connectionMessage.isNull()) {
            LogOutput("    ConnectionMessage (IN):");
            try {
                LogOutput(parsePortMessage(this.connectionMessage));
            } catch (e) {
                LogOutput("    Failed to parse ConnectionMessage: " + e);
            }
        } else {
            LogOutput("    ConnectionMessage (IN): NULL");
        }

        if (!this.bufferLengthPtr.isNull()) {
            try {
                const bufLen = this.bufferLengthPtr.readU32();
                LogOutput("    BufferLength (IN): 0x" + bufLen.toString(16));
            } catch (e) {
                LogOutput("    Failed to read BufferLength: " + e);
            }
        } else {
            LogOutput("    BufferLength (IN): NULL");
        }

        if (!this.outMessageAttributes.isNull()) {
            LogOutput("    OutMessageAttributes (IN):");
            try {
                printValidMessageAttributes(this.outMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse OutMessageAttributes: " + e);
            }
        } else {
            LogOutput("    OutMessageAttributes (IN): NULL");
        }

        if (!this.inMessageAttributes.isNull()) {
            LogOutput("    InMessageAttributes (IN):");
            try {
                printValidMessageAttributes(this.inMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse InMessageAttributes: " + e);
            }
        } else {
            LogOutput("    InMessageAttributes (IN): NULL");
        }

        if (this.timeout.isNull()) {
            LogOutput("    Timeout: NULL");
        } else {
            try {
                LogOutput("    Timeout: 0x" + this.timeout.readS64().toString(16));
            } catch (e) {
                LogOutput("    Failed to read Timeout: " + e);
            }
        }
    },

    onLeave(retval) {
        LogOutput("[-] NtAlpcConnectPort returned: 0x" + retval.toString(16));

        if (!this.portHandlePtr.isNull()) {
            try {
                const portHandle = this.portHandlePtr.readPointer();
                LogOutput("    PortHandle (OUT): " + portHandle);
            } catch (e) {
                LogOutput("    Failed to read PortHandle pointer: " + e);
            }
        } else {
            LogOutput("    PortHandle (OUT): NULL");
        }

        if (!this.connectionMessage.isNull()) {
            LogOutput("    ConnectionMessage (OUT):");
            try {
                LogOutput(parsePortMessage(this.connectionMessage));
            } catch (e) {
                LogOutput("    Failed to parse updated ConnectionMessage: " + e);
            }
        }

        if (!this.bufferLengthPtr.isNull()) {
            try {
                const bufLenAfter = this.bufferLengthPtr.readU32();
                LogOutput("    BufferLength (OUT): 0x" + bufLenAfter.toString(16));
            } catch (e) {
                LogOutput("    Failed to read updated BufferLength: " + e);
            }
        }

        if (!this.outMessageAttributes.isNull()) {
            LogOutput("    OutMessageAttributes (OUT):");
            try {
                printValidMessageAttributes(this.outMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse updated OutMessageAttributes: " + e);
            }
        }

        if (!this.inMessageAttributes.isNull()) {
            LogOutput("    InMessageAttributes (OUT):");
            try {
                printValidMessageAttributes(this.inMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse updated InMessageAttributes: " + e);
            }
        }
    }
});

// --- ntdll!NtAlpcConnectPortEx ---
Interceptor.attach(NtAlpcConnectPortExPtr, {
    onEnter(args) {
        this.portHandlePtr = args[0];                 // OUT
        this.connectionPortObjAttr = args[1];         // IN
        this.clientPortObjAttr = args[2];             // IN_OPT
        this.portAttributes = args[3];                 // IN_OPT
        this.flags = args[4].toInt32();                // IN
        this.serverSecurity = args[5];                 // IN_OPT
        this.connectionMessage = args[6];              // INOUT
        this.bufferLengthPtr = args[7];                // INOUT_OPT
        this.outMessageAttributes = args[8];           // INOUT_OPT
        this.inMessageAttributes = args[9];            // INOUT_OPT
        this.timeout = args[10];                        // IN_OPT

        LogOutput("[+] NtAlpcConnectPortEx called");


        LogOutput("    ConnectionPortObjectAttributes:");
        printObjectAttributes(this.connectionPortObjAttr);


        LogOutput("    ClientPortObjectAttributes:");
        printObjectAttributes(this.clientPortObjAttr);

        if (!this.portAttributes.isNull()) {
            LogOutput("    PortAttributes: " + this.portAttributes);
        } else {
            LogOutput("    PortAttributes: NULL");
        }

        LogOutput("    Flags: 0x" + this.flags.toString(16));

        if (!this.serverSecurity.isNull()) {
            LogOutput("    ServerSecurityRequirements: " + this.serverSecurity);
        } else {
            LogOutput("    ServerSecurityRequirements: NULL");
        }

        if (!this.connectionMessage.isNull()) {
            LogOutput("    ConnectionMessage (IN):");
            try {
                LogOutput(parsePortMessage(this.connectionMessage));
            } catch (e) {
                LogOutput("    Failed to parse ConnectionMessage: " + e);
            }
        } else {
            LogOutput("    ConnectionMessage (IN): NULL");
        }

        if (!this.bufferLengthPtr.isNull()) {
            try {
                const bufLen = this.bufferLengthPtr.readU32();
                LogOutput("    BufferLength (IN): 0x" + bufLen.toString(16));
            } catch (e) {
                LogOutput("    Failed to read BufferLength: " + e);
            }
        } else {
            LogOutput("    BufferLength (IN): NULL");
        }

        if (!this.outMessageAttributes.isNull()) {
            LogOutput("    OutMessageAttributes (IN):");
            try {
                printValidMessageAttributes(this.outMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse OutMessageAttributes: " + e);
            }
        } else {
            LogOutput("    OutMessageAttributes (IN): NULL");
        }

        if (!this.inMessageAttributes.isNull()) {
            LogOutput("    InMessageAttributes (IN):");
            try {
                printValidMessageAttributes(this.inMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse InMessageAttributes: " + e);
            }
        } else {
            LogOutput("    InMessageAttributes (IN): NULL");
        }

        if (this.timeout.isNull()) {
            LogOutput("    Timeout: NULL");
        } else {
            try {
                LogOutput("    Timeout: 0x" + this.timeout.readS64().toString(16));
            } catch (e) {
                LogOutput("    Failed to read Timeout: " + e);
            }
        }
    },

    onLeave(retval) {
        LogOutput("[-] NtAlpcConnectPortEx returned: 0x" + retval.toString(16));

        if (!this.portHandlePtr.isNull()) {
            try {
                const portHandle = this.portHandlePtr.readPointer();
                LogOutput("    PortHandle (OUT): " + portHandle);
            } catch (e) {
                LogOutput("    Failed to read PortHandle pointer: " + e);
            }
        } else {
            LogOutput("    PortHandle (OUT): NULL");
        }

        if (!this.connectionMessage.isNull()) {
            LogOutput("    ConnectionMessage (OUT):");
            try {
                LogOutput(parsePortMessage(this.connectionMessage));
            } catch (e) {
                LogOutput("    Failed to parse updated ConnectionMessage: " + e);
            }
        }

        if (!this.bufferLengthPtr.isNull()) {
            try {
                const bufLenAfter = this.bufferLengthPtr.readU32();
                LogOutput("    BufferLength (OUT): 0x" + bufLenAfter.toString(16));
            } catch (e) {
                LogOutput("    Failed to read updated BufferLength: " + e);
            }
        }

        if (!this.outMessageAttributes.isNull()) {
            LogOutput("    OutMessageAttributes (OUT):");
            try {
                printValidMessageAttributes(this.outMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse updated OutMessageAttributes: " + e);
            }
        }

        if (!this.inMessageAttributes.isNull()) {
            LogOutput("    InMessageAttributes (OUT):");
            try {
                printValidMessageAttributes(this.inMessageAttributes);
            } catch (e) {
                LogOutput("    Failed to parse updated InMessageAttributes: " + e);
            }
        }
    }
});

// --- ntdll!NtAlpcSendWaitReceivePort ---
Interceptor.attach(NtAlpcSendWaitReceivePortPtr, {
    onEnter(args) {
        this.portHandle = args[0]; // IN
        this.flags = args[1].toInt32(); // IN
        this.sendMessage = args[2]; // IN_OPT
        this.sendAttrs = args[3]; // INOUT_OPT
        this.recvMessage = args[4]; // OUT
        this.bufferLengthPtr = args[5]; // INOUT_OPT
        this.recvAttrs = args[6]; // INOUT_OPT
        this.timeoutPtr = args[7]; // IN_OPT

        LogOutput("[+] NtAlpcSendWaitReceivePort called");

        LogOutput("    PortHandle: " + this.portHandle);
        LogOutput("    Flags: 0x" + this.flags.toString(16));

        if (!this.sendMessage.isNull()) {
            try {
                LogOutput("    SendMessage:");
                LogOutput(parsePortMessage(this.sendMessage));
            } catch (e) {
                LogOutput("    SendMessage: <failed to parse> " + e);
            }
        } else {
            LogOutput("    SendMessage: NULL");
        }

        if (!this.sendAttrs.isNull()) {
            LogOutput("    SendMessageAttributes (IN):");
            printValidMessageAttributes(this.sendAttrs);
        } else {
            LogOutput("    SendMessageAttributes: NULL");
        }

        if (this.recvMessage.isNull()) {
            LogOutput("    ReceiveMessage: NULL");
        }

        if (!this.bufferLengthPtr.isNull()) {
            try {
                const bufLen = this.bufferLengthPtr.readU32();
                LogOutput("    BufferLength (IN): 0x" + bufLen.toString(16));
            } catch (e) {
                LogOutput("    BufferLength (IN): <failed to read> " + e);
            }
        } else {
            LogOutput("    BufferLength: NULL");
        }

        if (!this.recvAttrs.isNull()) {
            LogOutput("    ReceiveMessageAttributes (IN):");
            printValidMessageAttributes(this.recvAttrs);
        } else {
            LogOutput("    ReceiveMessageAttributes: NULL");
        }

        if (!this.timeoutPtr.isNull()) {
            try {
                const timeout = this.timeoutPtr.readS64();
                LogOutput("    Timeout: " + timeout);
            } catch (e) {
                LogOutput("    Timeout: <failed to read> " + e);
            }
        } else {
            LogOutput("    Timeout: NULL");
        }
    },

    onLeave(retval) {
        LogOutput("[-] NtAlpcSendWaitReceivePort returned: 0x" + retval.toString(16));

        if (!this.sendAttrs.isNull()) {
            LogOutput("    SendMessageAttributes (OUT):");
            printValidMessageAttributes(this.sendAttrs);
        }

        if (!this.recvMessage.isNull()) {
            try {
                LogOutput("    ReceiveMessage (OUT):");
                LogOutput(parsePortMessage(this.recvMessage));
            } catch (e) {
                LogOutput("    ReceiveMessage (OUT): <failed to parse> " + e);
            }
        }

        if (!this.bufferLengthPtr.isNull()) {
            try {
                const newBufLen = this.bufferLengthPtr.readU32();
                LogOutput("    BufferLength (OUT): 0x" + newBufLen.toString(16));
            } catch (e) {
                LogOutput("    BufferLength (OUT): <failed to read> " + e);
            }
        }

        if (!this.recvAttrs.isNull()) {
            try {
                LogOutput("    ReceiveMessageAttributes (OUT):");
                printValidMessageAttributes(this.recvAttrs);
            } catch (e) {
                LogOutput("    ReceiveMessageAttributes (OUT): <failed to parse> " + e);
            }
        }
    }
});

// --- ntdll!NtImpersonateClientOfPort ---
Interceptor.attach(NtImpersonateClientOfPortPtr, {
    onEnter(args) {
        this.portHandle = args[0];
        this.messagePtr = args[1];

        LogOutput("[+] NtImpersonateClientOfPort called");
        LogOutput("    PortHandle: " + this.portHandle);

        if (!this.messagePtr.isNull()) {
            LogOutput("    Message:");
            LogOutput(parsePortMessage(this.messagePtr));
        } else {
            LogOutput("    Message: NULL");
        }
    },
    onLeave(retval) {
        LogOutput("[-] NtImpersonateClientOfPort returned: 0x" + retval.toString(16));
    }
});

// --- ntdll!NtAlpcCreatePortSection ---
Interceptor.attach(NtAlpcCreatePortSectionPtr, {
    onEnter(args) {
        this.portHandle        = args[0];
        this.flags             = args[1].toInt32();
        this.sectionHandle     = args[2];
        this.sectionSize       = args[3];
        this.alpcSectionHandle = args[4];
        this.actualSectionSize = args[5];

        LogOutput("[+] NtAlpcCreatePortSection called");
        LogOutput("    PortHandle: 0x" + this.portHandle.toString(16));
        LogOutput("    Flags: 0x" + this.flags.toString(16));
        LogOutput("    SectionHandle: " + (this.sectionHandle.isNull() ? "NULL" : this.sectionHandle));
        LogOutput("    SectionSize: 0x" + this.sectionSize.toString(16));
    },

    onLeave(retval) {
        LogOutput("[-] NtAlpcCreatePortSection returned: 0x" + retval.toString(16));

        if (retval.toInt32() === 0) {  // STATUS_SUCCESS
            try {
                const outHandle = this.alpcSectionHandle.readPointer();
                const actualSize = this.actualSectionSize.readU64();

                LogOutput("    => AlpcSectionHandle: " + outHandle);
                LogOutput("    => ActualSectionSize: 0x" + actualSize.toString(16));
            } catch (e) {
                LogOutput("    [!] Failed to read output values: " + e);
            }
        }
    }
});

// --- ntdll!NtAlpcCreateSectionView ---
Interceptor.attach(NtAlpcCreateSectionViewPtr, {
    onEnter(args) {
        this.portHandle = args[0];
        this.flags = args[1].toInt32();
        this.viewAttrPtr = args[2];

        LogOutput("[+] NtAlpcCreateSectionView called");
        LogOutput("    PortHandle: " + this.portHandle);
        LogOutput("    Flags: 0x" + this.flags.toString(16));

        if (this.viewAttrPtr.isNull()) {
            LogOutput("    ViewAttributes: NULL");
        } else {
            try {
                this.initialViewAttr = {
                    flags: this.viewAttrPtr.readU32(),
                    sectionHandle: this.viewAttrPtr.add(8).readPointer(),
                    viewBase: this.viewAttrPtr.add(0x10).readPointer(),
                    viewSize: this.viewAttrPtr.add(0x18).readU64(), // offset of ViewSize
                };

                LogOutput("    ViewAttributes (before call):");
                LogOutput("        Flags: 0x" + this.initialViewAttr.flags.toString(16));
                LogOutput("        SectionHandle: 0x" + this.initialViewAttr.sectionHandle.toString(16));
                LogOutput("        ViewBase: 0x" + this.initialViewAttr.viewBase.toString(16));
                LogOutput("        ViewSize: 0x" + this.initialViewAttr.viewSize.toString(16));
            } catch (e) {
                LogOutput("    [!] Failed to read ViewAttributes: " + e);
            }
        }
    },

    onLeave(retval) {
        LogOutput("[-] NtAlpcCreateSectionView returned: 0x" + retval.toString(16));

        if (retval.toInt32() === 0 && this.viewAttrPtr && !this.viewAttrPtr.isNull()) {
            try {
                this.newViewAttr = {
                    flags: this.viewAttrPtr.readU32(),
                    sectionHandle: this.viewAttrPtr.add(8).readPointer(),
                    viewBase: this.viewAttrPtr.add(0x10).readPointer(),
                    viewSize: this.viewAttrPtr.add(0x18).readU64(), // offset of ViewSize
                };

                LogOutput("    ViewAttributes (after call):");
                LogOutput("        Flags: 0x" + this.newViewAttr.flags.toString(16));
                LogOutput("        SectionHandle: 0x" + this.newViewAttr.sectionHandle.toString(16));
                LogOutput("        ViewBase: 0x" + this.newViewAttr.viewBase.toString(16));
                LogOutput("        ViewSize: 0x" + this.newViewAttr.viewSize.toString(16));
            } catch (e) {
                LogOutput("    [!] Failed to read updatedViewAttributes: " + e);
            }
        }
    }
});