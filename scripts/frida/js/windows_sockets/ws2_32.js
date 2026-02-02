const bSEND = true;
const bPRINT = false;

const PTR_SIZE = Process.pointerSize;
const WSABUF_SIZE = PTR_SIZE === 8 ? 16 : 8;
const WSABUF_BUF_OFFSET = PTR_SIZE === 8 ? 8 : 4;

// ================= Helpers =================

function LogOutput(msg) {
    if (bSEND) {
        send(msg + "\n");
    }
    if (bPRINT) {
        console.log(msg);
    }
}

function LoadDLLSymbols(dll_name) {
	try {
		DebugSymbol.load(dll_name);
	}
	catch (err) {
		LogOutput("[-] Error while try loading symbols for " + dll_name + " error code: " + err);
        return;
	}
	LogOutput("[+] DebugSymbol.load(" + dll_name + ")");
}

function ntohs(n) {
    return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

function formatIpv4(sa) {
    return {
        ip: [
            sa.add(4).readU8(),
            sa.add(5).readU8(),
            sa.add(6).readU8(),
            sa.add(7).readU8()
        ].join('.'),
        port: ntohs(sa.add(2).readU16())
    };
}

function hexdumpJS(buf, len) {
    const u8 = new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < len; i += 16) {
        let row = i.toString(16).padStart(8, "0") + "  ";
        let asc = "";
        for (let j = 0; j < 16; j++) {
            if (i + j < len) {
                const b = u8[i + j];
                row += b.toString(16).padStart(2, "0") + " ";
                asc += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".";
            } else {
                row += "   ";
                asc += " ";
            }
        }
        out += row + " " + asc + "\n";
    }
    return out;
}

function FridaGetProcAddress(hModule, lpProcName) {
    try {
        return hModule.getExportByName(lpProcName);
    } catch (_) {
        return null;
    }
}

// ================= Hooks =================

function installHooks(mod) {
    const socketPtr = FridaGetProcAddress(mod, "socket");
    const bindPtr = FridaGetProcAddress(mod, "bind");
    const listenPtr = FridaGetProcAddress(mod, "listen");
    const acceptPtr = FridaGetProcAddress(mod, "accept");
    const connectPtr = FridaGetProcAddress(mod, "connect");
    const closesocketPtr = FridaGetProcAddress(mod, "closesocket");
    const sendPtr = FridaGetProcAddress(mod, "send");
    const recvPtr = FridaGetProcAddress(mod, "recv");
    const sendtoPtr = FridaGetProcAddress(mod, "sendto");
    const recvfromPtr = FridaGetProcAddress(mod, "recvfrom");
    const WSASendPtr = FridaGetProcAddress(mod, "WSASend");
    const WSARecvPtr = FridaGetProcAddress(mod, "WSARecv");

    // -------- socket --------
    if (socketPtr) {
        Interceptor.attach(socketPtr, {
            onEnter(args) {
                this.af = args[0].toInt32();
                this.type = args[1].toInt32();
                this.proto = args[2].toInt32();
            },
            onLeave(ret) {
                LogOutput(`socket(af=${this.af}, type=${this.type}, proto=${this.proto}) = ${ret}`);
            }
        });
    }

    // -------- bind --------
    if (bindPtr) {
        Interceptor.attach(bindPtr, {
            onEnter(args) {
                const sa = args[1];
                if (!sa.isNull() && sa.readU16() === 2) {
                    const {
                        ip,
                        port
                    } = formatIpv4(sa);
                    LogOutput(`bind(${args[0]}) ${ip}:${port}`);
                }
            }
        });
    }

    // -------- listen --------
    if (listenPtr) {
        Interceptor.attach(listenPtr, {
            onEnter(args) {
                LogOutput(`listen(${args[0]}, backlog=${args[1].toInt32()})`);
            }
        });
    }

    // -------- accept --------
    if (acceptPtr) {
        Interceptor.attach(acceptPtr, {
            onEnter(args) {
                this.sa = args[1];
            },
            onLeave(ret) {
                if (this.sa && !this.sa.isNull() && this.sa.readU16() === 2) {
                    const {
                        ip,
                        port
                    } = formatIpv4(this.sa);
                    LogOutput(`accept() = ${ret} from ${ip}:${port}`);
                }
            }
        });
    }

    // -------- connect --------
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter(args) {
                const sa = args[1];
                if (!sa.isNull() && sa.readU16() === 2) {
                    const {
                        ip,
                        port
                    } = formatIpv4(sa);
                    LogOutput(`connect(${args[0]}) -> ${ip}:${port}`);
                }
            }
        });
    }

    // -------- closesocket --------
    if (closesocketPtr) {
        Interceptor.attach(closesocketPtr, {
            onEnter(args) {
                LogOutput(`closesocket(${args[0]})`);
            }
        });
    }

    // -------- send --------
    if (sendPtr) {
        Interceptor.attach(sendPtr, {
            onEnter(args) {
                this.s = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32() >>> 0;
            },
            onLeave(ret) {
                const n = ret.toInt32();
                if (n <= 0 || this.buf.isNull()) return;
                const data = this.buf.readByteArray(Math.min(n, this.len));
                if (data)
                    LogOutput(`send(${this.s}) ${n} bytes\n${hexdumpJS(data, n)}`);
            }
        });
    }

    // -------- recv --------
    if (recvPtr) {
        Interceptor.attach(recvPtr, {
            onEnter(args) {
                this.s = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32() >>> 0;
            },
            onLeave(ret) {
                const n = ret.toInt32();
                if (n <= 0 || this.buf.isNull()) return;
                const data = this.buf.readByteArray(Math.min(n, this.len));
                if (data)
                    LogOutput(`recv(${this.s}) ${n} bytes\n${hexdumpJS(data, n)}`);
            }
        });
    }

    // -------- sendto --------
    if (sendtoPtr) {
        Interceptor.attach(sendtoPtr, {
            onEnter(args) {
                this.buf = args[1];
                this.len = args[2].toInt32() >>> 0;
            },
            onLeave(ret) {
                const n = ret.toInt32();
                if (n <= 0 || this.buf.isNull()) return;
                const data = this.buf.readByteArray(Math.min(n, this.len));
                if (data)
                    LogOutput(`sendto ${n} bytes\n${hexdumpJS(data, n)}`);
            }
        });
    }

    // -------- recvfrom --------
    if (recvfromPtr) {
        Interceptor.attach(recvfromPtr, {
            onEnter(args) {
                this.buf = args[1];
                this.len = args[2].toInt32() >>> 0;
            },
            onLeave(ret) {
                const n = ret.toInt32();
                if (n <= 0 || this.buf.isNull()) return;
                const data = this.buf.readByteArray(Math.min(n, this.len));
                if (data)
                    LogOutput(`recvfrom ${n} bytes\n${hexdumpJS(data, n)}`);
            }
        });
    }

    // -------- WSASend --------
    if (WSASendPtr) {
        Interceptor.attach(WSASendPtr, {
            onEnter(args) {
                this.s = args[0];
                this.bufs = args[1];
                this.count = args[2].toInt32() >>> 0;
                this.sent = args[3];
            },
            onLeave() {
                if (this.sent.isNull() || this.bufs.isNull()) return;
                const total = this.sent.readU32();
                if (!total) return;

                let out = Memory.alloc(total);
                let off = 0;

                for (let i = 0; i < this.count && off < total; i++) {
                    const b = this.bufs.add(i * WSABUF_SIZE);
                    const len = b.readU32();
                    const ptr = b.add(WSABUF_BUF_OFFSET).readPointer();
                    if (ptr.isNull() || !len) continue;

                    const n = Math.min(len, total - off);
                    Memory.writeByteArray(out.add(off), ptr.readByteArray(n));
                    off += n;
                }

                if (off)
                    LogOutput(`WSASend(${this.s}) ${off} bytes\n${hexdumpJS(out.readByteArray(off), off)}`);
            }
        });
    }

    // -------- WSARecv --------
    if (WSARecvPtr) {
        Interceptor.attach(WSARecvPtr, {
            onEnter(args) {
                this.s = args[0];
                this.bufs = args[1];
                this.count = args[2].toInt32() >>> 0;
                this.recvd = args[3];
            },
            onLeave(ret) {
                if (ret.toInt32() !== 0 || this.recvd.isNull()) return;
                const total = this.recvd.readU32();
                if (!total || this.bufs.isNull()) return;

                let out = Memory.alloc(total);
                let off = 0;

                for (let i = 0; i < this.count && off < total; i++) {
                    const b = this.bufs.add(i * WSABUF_SIZE);
                    const len = b.readU32();
                    const ptr = b.add(WSABUF_BUF_OFFSET).readPointer();
                    if (ptr.isNull() || !len) continue;

                    const n = Math.min(len, total - off);
                    Memory.writeByteArray(out.add(off), ptr.readByteArray(n));
                    off += n;
                }

                if (off)
                    LogOutput(`WSARecv(${this.s}) ${off} bytes\n${hexdumpJS(out.readByteArray(off), off)}`);
            }
        });
    }
}

// ================= Loader =================

function waitForWs2() {
    const sWs2_32_dll = "ws2_32.dll"; 
    const t = setInterval(() => {
        try {
            const m = Process.getModuleByName(sWs2_32_dll);
            LoadDLLSymbols(sWs2_32_dll);
            clearInterval(t);
            installHooks(m);
        } catch (_) {}
    }, 100);
}

// ================= Start =================

waitForWs2();