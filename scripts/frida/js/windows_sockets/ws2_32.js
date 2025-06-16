const bSEND = true;
const bPRINT = false;

// ws2_32.dll
const sWs2_32_dll = "ws2_32.dll";
LoadDLLSymbols(sWs2_32_dll);
const socketPtr = Module.getExportByName(sWs2_32_dll, "socket");
const bindPtr = Module.getExportByName(sWs2_32_dll, "bind");
const listenPtr = Module.getExportByName(sWs2_32_dll, "listen");
const acceptPtr = Module.getExportByName(sWs2_32_dll, "accept");
const connectPtr = Module.getExportByName(sWs2_32_dll, "connect");
const recvPtr = Module.getExportByName(sWs2_32_dll, "recv");
const recvfromPtr = Module.getExportByName(sWs2_32_dll, "recvfrom");
const sendPtr = Module.getExportByName(sWs2_32_dll, "send");
const sendtoPtr = Module.getExportByName(sWs2_32_dll, "sendto");
const closeSocketPtr = Module.getExportByName(sWs2_32_dll, "closesocket");
//const WSASocketWPtr = Module.getExportByName("ws2_32.dll", "WSASocketW");
//const WSAAcceptPtr = Module.getExportByName(sWs2_32_dll, "WSAAccept");
const WSAConnectPtr = Module.getExportByName(sWs2_32_dll, "WSAConnect");
const WSAConnectByListPtr = Module.getExportByName(sWs2_32_dll, "WSAConnectByList");
const WSAConnectByNameWPtr = Module.getExportByName(sWs2_32_dll, "WSAConnectByNameW");
const WSARecvPtr = Module.getExportByName(sWs2_32_dll, "WSARecv");
const WSASendPtr = Module.getExportByName(sWs2_32_dll, "WSASend");
const SOCKET_ERROR = 0xffffffff;
const SOMAXCONN = 0x7fffffff;

// Helpers
function LogOutput(msg, bStackTrace=false) {
    // send the output to frida-python script "frida_inject.py"
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

function ntohs(n) {
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF);
}

function formatIpv4(sockaddr) {
    let port = ntohs(sockaddr.add(2).readU16());
    let ip = [
        sockaddr.add(4).readU8(),
        sockaddr.add(5).readU8(),
        sockaddr.add(6).readU8(),
        sockaddr.add(7).readU8()
    ].join('.');
    return { sin_addr: ip, sin_port: port };
}

function formatIpv6(sockaddr) {
    let sin6_port = ntohs(sockaddr.add(2).readU16());

    let segments = [];
    for (let i = 0; i < 16; i += 2) {
        let raw_segment = sockaddr.add(8 + i).readU16();
        let segment = ntohs(raw_segment); // Convert network byte order to host
        segments.push(segment.toString(16));
    }

    // Remove leading zeros and lowercase
    segments = segments.map(s => s.replace(/^0+/, '') || '0');

    // Compress longest sequence of zeros (basic version)
    let zeroRuns = [];
    let runStart = -1;
    for (let i = 0; i <= segments.length; i++) {
        if (segments[i] === '0') {
            if (runStart === -1) runStart = i;
        } else {
            if (runStart !== -1) {
                zeroRuns.push([runStart, i - 1]);
                runStart = -1;
            }
        }
    }

    let longestRun = zeroRuns.sort((a, b) => (b[1] - b[0]) - (a[1] - a[0]))[0];
    if (longestRun && (longestRun[1] - longestRun[0]) >= 1) {
        let [start, end] = longestRun;
        segments.splice(start, end - start + 1, '');
        if (start === 0) segments.unshift('');
        if (end === 7) segments.push('');
    }

    let ipv6_addr = segments.join(':');
    let scope_id = sockaddr.add(24).readU32();
    let scope_str = scope_id !== 0 ? `%${scope_id}` : "";

    return {
        ip: `[${ipv6_addr}${scope_str}]`,
        port: sin6_port
    };
}

function GetPeername(sock) {
    const getpeernamePtr = Module.getExportByName("ws2_32.dll", "getpeername");
    const getpeername = new NativeFunction(getpeernamePtr, 'int', ['int', 'pointer', 'pointer']);

    const sockaddrSize = 28; // 28 bytes cover both sockaddr_in and sockaddr_in6
    const addr = Memory.alloc(sockaddrSize);
    const addrlen = Memory.alloc(8);
    addrlen.writeU32(sockaddrSize);

    const result = getpeername(sock.toInt32(), addr, addrlen);
    if (result !== 0) {
        LogOutput(`[-] getpeername(sock=${sock}) failed.`);
        return null;
    }

    const family = addr.readU16();
    if (family === 2) { // AF_INET
        let { sin_addr, sin_port } = formatIpv4(addr);
        return {
            ipv: "IPv4",
            ip: sin_addr,
            port: sin_port
        };
    } else if (family === 23) { // AF_INET6
        let { ip, port } = formatIpv6(addr);
        return {
            ipv: "IPv6",
            ip: ip,
            port: port
        };
    } else {
        LogOutput(`[-] getpeername(sock=${sock}) returned unknown family: ${family}`);
        return null;
    }
}

function _fillUp (value, count, fillWith) {
    var l = count - value.length;
    var ret = "";

    while (--l > -1)
        ret += fillWith;

    return ret + value;
}

function hexdumpJS (arrayBuffer, offset, length) {
    var view = new DataView(arrayBuffer);
    offset = offset || 0;
    length = length || arrayBuffer.byteLength;

    var out = _fillUp("Offset", 8, " ") + "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n";
    var row = "";

    for (var i = 0; i < length; i += 16) 
    {
        row += _fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
        var n = Math.min(16, length - offset);
        var string = "";

        for (var j = 0; j < 16; ++j) 
        {
            if (j < n) 
            {
                var value = view.getUint8(offset);
                string += (value >= 32 && value < 128) ? String.fromCharCode(value) : ".";
                row += _fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
                offset++;
            }
            else 
            {
                row += "   ";
                string += " "; 
            }
        }
        row += " " + string + "\n";
    }
    out += row;
    return out;
};

// Hooks

// --- ws2_32!socket ---
Interceptor.attach(socketPtr, {
    onEnter: function(args) {
        this.af = args[0].toInt32();
        this.type = args[1].toInt32();
        this.protocol = args[2].toInt32();
    },
    onLeave: function(retval) {
        let sock = retval;

        let afStr = {
            2: "AF_INET",
            23: "AF_INET6"
        }[this.af] || `Unknown (${this.af})`;

        let typeStr = {
            1: "SOCK_STREAM",
            2: "SOCK_DGRAM",
            3: "SOCK_RAW"
        }[this.type] || `Unknown (${this.type})`;

        let protoStr = {
            6: "IPPROTO_TCP",
            17: "IPPROTO_UDP",
            1: "IPPROTO_ICMP"
        }[this.protocol] || `Unknown (${this.protocol})`;

        LogOutput(`socket(af = ${this.af} (${afStr}), type = ${this.type} (${typeStr}), protocol = ${this.protocol} (${protoStr})) => SOCKET=${sock}`);
    }
});

// --- ws2_32!bind ---
Interceptor.attach(bindPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        let sockaddr = args[1];
        if (!sockaddr.isNull()) {
            let family = sockaddr.readU16();
            if (family === 2) { // AF_INET
                let { sin_addr, sin_port } = formatIpv4(sockaddr);
                LogOutput(`bind(sock=${this.sock}, family=AF_INET(IPv4), IP=${sin_addr}, PORT=${sin_port})`);
            } else if (family === 23) { // AF_INET6
                let { ip, port } = formatIpv6(sockaddr);
                LogOutput(`bind(sock=${this.sock}, family=AF_INET6(IPv6), IP=${ip}, PORT=${port})`);
            } else {
                LogOutput(`bind(sock=${this.sock}) => Unknown family ${family}`);
            }
        }
    }
});

// --- ws2_32!listen ---
Interceptor.attach(listenPtr, {
    onEnter: function(args) {
        let sock = args[0];
        let backlog = args[1].toInt32();
        if (backlog === SOMAXCONN) {
            LogOutput(`listen(${sock}, SOMAXCONN)`);
        }
        else {
            LogOutput(`listen(${sock}, backlog=${backlog})`);
        }
        
    }
});

// --- ws2_32!accept ---
Interceptor.attach(acceptPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        this.sockaddr_in = args[1];
        this.addrlen = args[2];
    },
    onLeave: function(retval) {
        let clientSock = retval;

        let sockaddr = this.sockaddr_in;
        if (!sockaddr.isNull()) {
            let family = sockaddr.readU16();
            if (family === 2) { // AF_INET
                let { sin_addr, sin_port } = formatIpv4(sockaddr);
                LogOutput(`accept(${this.sock}) => SOCKET=${clientSock}, Client info(IPv4): IP=${sin_addr}, PORT=${sin_port}`);
            } else if (family === 23) { // AF_INET6
                let { ip, port } = formatIpv6(sockaddr);
                LogOutput(`accept(${this.sock}) => SOCKET=${clientSock}, Client info(IPv6): IP=${ip}, PORT=${port}`);
            } else {
                LogOutput(`accept(${this.sock}) => SOCKET=${clientSock}, Unknown family ${family}`);
            }
        }
        else {
            //LogOutput(`accept(${this.sock}, addr=NULL) => ${clientSock} `);
            const peer = GetPeername(clientSock);
            if (peer) {
                LogOutput(`accept(sock=${this.sock}) => SOCKET=${clientSock}, getpeername() => Client info(${peer.ipv}): IP=${peer.ip}, PORT=${peer.port}`);
            } else {
                LogOutput(`accept(sock=${this.sock}) => SOCKET=${clientSock}, but could not retrieve client info.`);
            }

        }
    }
});

// --- ws2_32!connect ---
Interceptor.attach(connectPtr, {
    onEnter: function (args) {
        this.sock = args[0];
        this.sockaddr_in = args[1];

        let sockaddr = this.sockaddr_in;
        if (!sockaddr.isNull()) {
            let family = sockaddr.readU16();

            if (family === 2) { // AF_INET
                let { sin_addr, sin_port } = formatIpv4(sockaddr);
                LogOutput(`connect(sock=${this.sock}, family=AF_INET(IPv4), IP=${sin_addr}, PORT=${sin_port})`);
            } else if (family === 23) { // AF_INET6
                let { ip, port } = formatIpv6(sockaddr);
                LogOutput(`connect(sock=${this.sock}, family=AF_INET6(IPv6), IP=${ip}, PORT=${port})`);
            } else {
                LogOutput(`connect(sock=${this.sock}, family=${family})`);
            }
        }
    }
});

// --- ws2_32!recv ---
Interceptor.attach(recvPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32() >>> 0;
        this.flags = args[3].toInt32();
    },
    onLeave: function(retval) {
        let ret = retval.toInt32() >>> 0;
        if (ret !== SOCKET_ERROR) {
            let len = retval.toInt32() >>> 0;
            if (!this.buf.isNull()) {
                let data = this.buf.readByteArray(len);
                if (data && len) {
                    LogOutput(`recv(s=${this.sock},\nbuf=\n${hexdumpJS(data, 0, len)}len=${len})`);
                }
            }
        }
        else {
            LogOutput(`recv(s=${this.sock},buf=${this.buf}, len=${this.len}) => ret=${retval}`);
        }
    }
});

// --- ws2_32!recvfrom ---
Interceptor.attach(recvfromPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32() >>> 0;
        this.flags = args[3].toInt32();
        this.from = args[4];
    },
    onLeave: function(retval) {
        let ret = retval.toInt32() >>> 0;
        if (ret !== SOCKET_ERROR) {
            if (!this.buf.isNull()) {
                let data = this.buf.readByteArray(ret);
                if (data && ret) {
                    let addrInfo = '';
                    if (!this.from.isNull()) {
                        let family = this.from.readU16();
                        if (family === 2) {
                            let { ip, port } = formatIpv4(this.from);
                            addrInfo = `sockaddr(IPv4) IP=${ip}, PORT=${port}`;
                        } else if (family === 23) {
                            let { ip, port } = formatIpv6(this.from);
                            addrInfo = `sockaddr(IPv6) IP=${ip}, PORT=${port}`;
                        } else {
                            addrInfo = `sockaddr(Unknown family) = ${family}`;
                        }
                    }
                    LogOutput(`recvfrom(s=${this.sock},\nbuf=\n${hexdumpJS(data, 0, ret)},len=${ret}, from=${addrInfo})`);
                }
            }
        } else {
            LogOutput(`recvfrom(s=${this.sock},buf=${this.buf}, len=${this.len}) => ret=${retval}`);
        }
    }
});

// --- ws2_32!send ---
Interceptor.attach(sendPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32() >>> 0;
        this.flags = args[3].toInt32();

        if (!this.buf.isNull() && this.len !== 0) {
            let data = this.buf.readByteArray(this.len);
            LogOutput(`send(s=${this.sock},\nbuf=\n${hexdumpJS(data, 0, this.len)},len=${this.len})`);
        }
    }
});

// --- ws2_32!sendto ---
Interceptor.attach(sendtoPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32() >>> 0;
        this.flags = args[3].toInt32();
        let to = args[4];

        if (!this.buf.isNull() && this.len !== 0) {
            let data = this.buf.readByteArray(this.len);
            let addr = '';

            if (!to.isNull()) {
                let family = to.readU16();
                if (family === 2) {
                    let { ip, port } = formatIpv4(to);
                    addr = `sockaddr(IPv4) IP=${ip}, PORT=${port}`;
                } else if (family === 23) {
                    let { ip, port } = formatIpv6(to);
                    addr = `sockaddr(IPv6) IP=${ip}, PORT=${port}`;
                } else {
                    addr = `sockaddr(Unknown family) = ${family}`;
                }
            }

            LogOutput(`sendto(s=${this.sock},\nbuf=\n${hexdumpJS(data, 0, this.len)},len=${this.len},to=${addr})`);
        }
    }
});

// --- ws2_32!closesocket ---
Interceptor.attach(closeSocketPtr, {
    onEnter: function(args) {
        this.sock = args[0];
        LogOutput(`closesocket(${this.sock})`);
    }
});

// --- ws2_32!WSASocketW ---
/*
Interceptor.attach(WSASocketWPtr, {
    onEnter: function(args) {
        this.af = args[0].toInt32();
        this.type = args[1].toInt32();
        this.protocol = args[2].toInt32();
        this.lpProtocolInfo = args[3];
        this.group = args[4].toInt32();
        this.dwFlags = args[5].toInt32();
    },
    onLeave: function(retval) {
        let sock = retval;

        let afStr = {
            2: "AF_INET",
            23: "AF_INET6"
        }[this.af] || `Unknown (${this.af})`;

        let typeStr = {
            1: "SOCK_STREAM",
            2: "SOCK_DGRAM",
            3: "SOCK_RAW"
        }[this.type] || `Unknown (${this.type})`;

        let protoStr = {
            6: "IPPROTO_TCP",
            17: "IPPROTO_UDP",
            1: "IPPROTO_ICMP"
        }[this.protocol] || `Unknown (${this.protocol})`;

        LogOutput(`WSASocketW() = ${sock}`);
        LogOutput(`\taf = ${this.af} (${afStr})`);
        LogOutput(`\ttype = ${this.type} (${typeStr})`);
        LogOutput(`\tprotocol = ${this.protocol} (${protoStr})`);
        LogOutput(`\tlpProtocolInfo = ${this.lpProtocolInfo}`);
        LogOutput(`\tgroup = ${this.group}`);
        LogOutput(`\tdwFlags = 0x${this.dwFlags.toString(16)}`);
    }
});
*/

// --- ws2_32!WSAAccept ---
/*
Interceptor.attach(WSAAcceptPtr, {
    onEnter: function (args) {
        this.s = args[0];
        this.sockaddr_in = args[1];
    },
    onLeave: function (retval) {
        let clientSock = retval;
        //LogOutput(`WSAAccept(${this.s}) => ${clientSock}`);

        let sockaddr = this.sockaddr_in;
        if (!sockaddr.isNull()) {
            let family = sockaddr.readU16();
            if (family === 2) { // AF_INET
                let { sin_addr, sin_port } = formatIpv4(sockaddr);
                LogOutput(`WSAAccept(${this.s}) => SOCKET=${clientSock}, Client info(IPv4): ${sin_addr}:${sin_port}`);
            } else if (family === 23) { // AF_INET6
                let { ip, port } = formatIpv6(sockaddr);
                LogOutput(`WSAAccept(${this.s}) => SOCKET=${clientSock}, Client info(IPv6): ${ip}:${port}`);
            } else {
                LogOutput(`WSAAccept(${this.s}) => SOCKET=${clientSock}, Unknown address family ${family}`);
            }
        }
    }
});
*/

// --- ws2_32!WSAConnect ---
Interceptor.attach(WSAConnectPtr, {
    onEnter: function (args) {
        this.s = args[0];
        this.name = args[1];

        let sockaddr_in = this.name;
        if (!sockaddr_in.isNull()) {
            let sin_family = sockaddr_in.readU16();
            if (sin_family === 2) { // AF_INET
                let { sin_addr, sin_port } = formatIpv4(sockaddr_in);
                LogOutput(`WSAConnect(s=${this.s}, family=AF_INET(IPv4), IP=${sin_addr}, PORT=${sin_port})`);
            }
            else if (sin_family === 23) { // AF_INET6
                let { ip, port } = formatIpv6(sockaddr_in);
                LogOutput(`WSAConnect(s=${this.s}, family=AF_INET6(IPv6), IP=${ip}, PORT=${port})`);
            }
            else {
                LogOutput(`WSAConnect(s=${this.s}, family=${sin_family})`);
            }
        }
    }
});

// --- ws2_32!WSAConnectByList ---
Interceptor.attach(WSAConnectByListPtr, {
    onEnter: function (args) {
        LogOutput(`WSAConnectByList()`);
    }
});

// --- ws2_32!WSAConnectByNameW ---
Interceptor.attach(WSAConnectByNameWPtr, {
    onEnter: function (args) {
        this.sock = args[0];
        this.nodenamePtr = args[1];
        this.servicenamePtr = args[2];
        // this.localAddressLengthPtr = args[3];
        // this.localAddress = args[4];
        // this.remoteAddressLengthPtr = args[5];
        this.remoteAddress = args[6];

        this.nodename = (!this.nodenamePtr.isNull()) ? this.nodenamePtr.readUtf16String() : "<NULL>";
        this.servicename = (!this.servicenamePtr.isNull()) ? this.servicenamePtr.readUtf16String() : "<NULL>";

        if (!this.remoteAddress.isNull()) {
            try {
                let sockaddr = this.remoteAddress;
                let sin_family = sockaddr.readU16();

                if (sin_family === 2) { // AF_INET
                    let { sin_addr, sin_port } = formatIpv4(sockaddr);
                    LogOutput(`WSAConnectByNameW(sock=${this.sock}, nodename="${this.nodename}", servicename="${this.servicename}", IP=${sin_addr}, PORT=${sin_port})`);
                } else if (sin_family === 23) { // AF_INET6
                    let { ip, port } = formatIpv6(sockaddr);
                    LogOutput(`WSAConnectByNameW(sock=${this.sock}, nodename="${this.nodename}", servicename="${this.servicename}", IP=[${ip}], PORT=${port})`);
                } else {
                    LogOutput(`\tUnknown address family: ${sin_family}`);
                }
            } catch (e) {
                LogOutput(`\tFailed to parse remote address: ${e}`);
            }
        } else {
            LogOutput(`\tNo remote address provided.`);
        }
    }
});

// --- ws2_32!WSARecv ---
Interceptor.attach(WSARecvPtr, {
    onEnter: function (args) {
        this.s = args[0];
        this.lpBuffers = args[1];
        this.dwBufferCount = args[2].toInt32() >>> 0;
        this.lpNumberOfBytesRecvd = args[3];
        this.dwFlags = args[4].toInt32() >>> 0;
        this.lpOverlapped = args[5];
        this.lpCompletionRoutine = args[6];

    },
    onLeave: function (retval) {
        if (retval.toInt32() >>> 0 === SOCKET_ERROR) return;

        if (this.lpNumberOfBytesRecvd.isNull()){
            LogOutput(
                `WSARecv(s=${this.s},\n` +
                `lpBuffers=${lpBuffers},\n` +
                `dwBufferCount=${dwBufferCount},\n` +
                `lpNumberOfBytesRecvdPtr=${this.lpNumberOfBytesRecvd},\n` +
                `lpNumberOfBytesRecvdVal=${totalReceived},\n` +
                `dwFlags=${this.dwFlags},\n` +
                `lpOverlapped=${this.lpOverlapped},\n` +
                `lpCompletionRoutine=${this.lpCompletionRoutine},\n` +
                `retval=${retval},)\n`
            );
            return;
        }
        const totalReceived = this.lpNumberOfBytesRecvd.readU32();
        if (totalReceived === 0) {
            LogOutput(
                `WSARecv(s=${this.s},\n` +
                `lpBuffers=${lpBuffers},\n` +
                `dwBufferCount=${dwBufferCount},\n` +
                `lpNumberOfBytesRecvdPtr=${this.lpNumberOfBytesRecvd},\n` +
                `lpNumberOfBytesRecvdVal=${totalReceived},\n` +
                `dwFlags=${this.dwFlags},\n` +
                `lpOverlapped=${this.lpOverlapped},\n` +
                `lpCompletionRoutine=${this.lpCompletionRoutine},\n` +
                `retval=${retval},)\n`
            );
            return;
        }

        const dwBufferCount = this.dwBufferCount;
        const lpBuffers = this.lpBuffers;
        let buffers = [];
        let collected = 0;

        for (let i = 0; i < dwBufferCount && collected < totalReceived; i++) {
            const WSABUF = lpBuffers.add(i * 0x10);  // WSABUF size is 16 bytes on 64-bit
            const len = WSABUF.readU32();
            const bufPtr = WSABUF.add(8).readPointer(); // pointer is at offset 8

            const toRead = Math.min(len, totalReceived - collected);
            const chunk = bufPtr.readByteArray(toRead);
            buffers.push({ len: toRead, data: chunk });
            collected += toRead;
        }

        const fullData = Memory.alloc(totalReceived);
        let offset = 0;
        for (const b of buffers) {
            Memory.writeByteArray(fullData.add(offset), b.data);
            offset += b.len;
        }

        LogOutput(
            `WSARecv(s=${this.s}, lpBuffers=${lpBuffers}, dwBufferCount=${dwBufferCount}, ` +
            `dwFlags=0x${this.dwFlags.toString(16)}, retval=${retval},\n` +
            `lpNumberOfBytesRecvd=${totalReceived},\n` +
            `buf=\n${hexdumpJS(fullData, 0, totalReceived)})\n`
        );
    }
});

// --- ws2_32!WSASendPtr ---
Interceptor.attach(WSASendPtr, {
    onEnter: function (args) {
        this.s = args[0];
        this.lpBuffers = args[1];
        this.dwBufferCount = args[2].toInt32() >>> 0;
        this.lpNumberOfBytesSent = args[3];
        this.dwFlags = args[4].toInt32() >>> 0;
        this.lpOverlapped = args[5];
        this.lpCompletionRoutine = args[6];
    },
    onLeave: function (retval) {
        if (!this.lpNumberOfBytesSent.isNull()) {
            const bytesSent = this.lpNumberOfBytesSent.readU32();
            let collected = 0;
            let fullData = Memory.alloc(bytesSent);
            let offset = 0;

            for (let i = 0; i < this.dwBufferCount && collected < bytesSent; i++) {
                const WSABUF = this.lpBuffers.add(i * 0x10);
                const len = WSABUF.readU32();
                const bufPtr = WSABUF.add(8).readPointer();

                const toCopy = Math.min(len, bytesSent - collected);
                const chunk = bufPtr.readByteArray(toCopy);
                Memory.writeByteArray(fullData.add(offset), chunk);

                collected += toCopy;
                offset += toCopy;
            }
            const arrayBuf = fullData.readByteArray(bytesSent);
            LogOutput(`WSASend(s=${this.s},\n` +
                      `lpNumberOfBytesSentVal=${bytesSent},\n` +
                      `buf=\n${hexdumpJS(arrayBuf, 0, bytesSent)})\n`
            );
        }

        else{
            LogOutput(`WSASend(s=${this.s},\n` +
                      `dwBufferCount=${this.dwBufferCount},\n` +
                      `lpNumberOfBytesSentPtr=${this.lpNumberOfBytesSent},\n` +
                      `lpNumberOfBytesSentVal=${bytesSent},\n` +
                      `dwFlags=0x${this.dwFlags},\n` +
                      `lpOverlapped=${this.lpOverlapped},\n` +
                      `lpCompletionRoutine=${this.lpCompletionRoutine})\n` +
                      `=> retval=${retval}\n`
            );
        }
    }    
});