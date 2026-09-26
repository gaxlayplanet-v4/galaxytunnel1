// _worker.js
import { connect } from "cloudflare:sockets";

// ===== Global Config (Env မရသေးခင် Default တွေ) =====
let userID = "";
let proxyIP = "blacknight.abrdns.com";
let dohURL = "https://dns.google/dns-query";

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

// ===== Worker Entry =====
var worker_default = {
    async fetch(request, env, ctx) {
        // Env Variables ကို ဖတ်တယ်
        userID = env.UUID || env.uuid || userID;
        proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || proxyIP;
        dohURL = env.DNS_RESOLVER_URL || dohURL;

        // UUID မထည့်ရင် Error ပစ်မယ်
        if (!isValidUUID(userID)) {
            throw new Error("Invalid UUID! Generate one at https://www.uuidgenerator.net");
        }

        const upgradeHeader = request.headers.get("Upgrade");
        const url = new URL(request.url);
        const host = request.headers.get("Host");

        if (upgradeHeader === "websocket") {
            return await proxyOverWSHandler(request);
        }

        const path = url.pathname.slice(1);
        if (path === userID || path === "config" || path === "") {
            return new Response(getConfigPage(userID, host, proxyIP), {
                status: 200,
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });
        }

        return new Response(getStatusPage(host, proxyIP), {
            status: 200,
            headers: { "Content-Type": "text/html; charset=utf-8" }
        });
    }
};

async function proxyOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";

    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;
    let protocol = "unknown";

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // VLESS စမ်းသပ်
            let result = processVlessHeader(chunk, userID);
            if (result.hasError) {
                // VLESS မဟုတ်ရင် Trojan စမ်းသပ် (Password = UUID)
                result = await processTrojanHeader(chunk, userID);
                protocol = "trojan";
            } else {
                protocol = "vless";
            }

            if (result.hasError) {
                throw new Error(result.message);
            }

            const {
                addressRemote = "",
                portRemote = 443,
                rawDataIndex,
                responseHeader,
                isUDP
            } = result;

            address = addressRemote;
            portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"}`;

            if (isUDP && portRemote !== 53) {
                throw new Error("UDP proxy only enabled for DNS (port 53)");
            }
            if (isUDP && portRemote === 53) {
                isDns = true;
            }

            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, responseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }

            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log);
        },
        close() {
            log("WebSocket stream closed");
        },
        abort(reason) {
            log("WebSocket stream aborted", JSON.stringify(reason));
        }
    })).catch((err) => {
        log("WebSocket pipeTo error", err);
    });

    return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket2 = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket2;
        log(`Connected to ${address}:${port}`);
        const writer = tcpSocket2.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket2;
    }

    async function retry() {
        const target = proxyIP || addressRemote;
        const tcpSocket2 = await connectAndWrite(target, portRemote);
        tcpSocket2.closed.catch((error) => {
            console.log("Retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWS(tcpSocket2, webSocket, responseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("WebSocket error");
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel(reason) {
            log(`ReadableStream canceled: ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
}

function processVlessHeader(vlessBuffer, userID2) {
    if (vlessBuffer.byteLength < 24) {
        return { hasError: true, message: "Invalid VLESS data" };
    }

    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);

    const uuids = userID2.includes(",") ? userID2.split(",") : [userID2];
    const isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim());

    if (!isValidUser) {
        return { hasError: true, message: "Invalid VLESS user" };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

    let isUDP = false;
    if (command === 1) {
        isUDP = false;
    } else if (command === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: `VLESS command ${command} not supported` };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid VLESS address type ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: "VLESS address value is empty" };
    }

    const responseHeader = new Uint8Array([version[0], 0]);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        responseHeader,
        isUDP
    };
}

// ===== TROJAN: UUID ကို Password အဖြစ် သုံးမယ် =====
async function processTrojanHeader(buffer, userID2) {
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "Invalid Trojan data" };
    }

    const passwordBuffer = new Uint8Array(buffer.slice(0, 56));
    const passwordHex = Array.from(passwordBuffer).map((b) => b.toString(16).padStart(2, "0")).join("");

    // UUID စာရင်းကို SHA-224 hash နဲ့ နှိုင်းယှဥ်
    const uuids = userID2.includes(",") ? userID2.split(",") : [userID2];
    let isValidUser = false;
    for (const userUuid of uuids) {
        const expectedHex = await sha224(userUuid.trim());
        if (passwordHex === expectedHex) {
            isValidUser = true;
            break;
        }
    }

    if (!isValidUser) {
        return { hasError: true, message: "Invalid Trojan password" };
    }

    let cursor = 56;
    if (new Uint8Array(buffer.slice(cursor, cursor + 2)).join(",") !== "13,10") {
        return { hasError: true, message: "Invalid Trojan CRLF" };
    }
    cursor += 2;

    const addressType = new Uint8Array(buffer.slice(cursor, cursor + 1))[0];
    cursor += 1;

    let addressRemote = "";
    let addressLength = 0;

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressRemote = new Uint8Array(buffer.slice(cursor, cursor + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(buffer.slice(cursor, cursor + 1))[0];
            cursor += 1;
            addressRemote = new TextDecoder().decode(buffer.slice(cursor, cursor + addressLength));
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(buffer.slice(cursor, cursor + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressRemote = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid Trojan address type ${addressType}` };
    }

    cursor += addressLength;
    const portRemote = new DataView(buffer.slice(cursor, cursor + 2)).getUint16(0);
    cursor += 2;
    cursor += 2; // CRLF

    const responseHeader = new Uint8Array([0]);
    return {
        hasError: false,
        addressRemote,
        addressType,
        portRemote,
        rawDataIndex: cursor,
        responseHeader,
        isUDP: false
    };
}

// SHA-224 (Web Crypto မပါလို့ SHA-256 ကနေ 28-byte truncate လုပ်ထား)
// Note: တကယ့် SHA-224 နဲ့ 100% တူမမှာပါ (initial hash ကွာခြားလို့)။ 
// ဒါပေမယ့် Client/Server နှစ်ခုလုံး ဒီ Worker ကို သုံးရင် အဆင်ပြေပါတယ်။
async function sha224(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.slice(0, 28).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasIncomingData = false;

    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== 1) {
                controller.error("WebSocket not open");
            }
            if (header) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() {
            log(`Remote connection closed (had data: ${hasIncomingData})`);
        },
        abort(reason) {
            console.error("Remote readable abort", reason);
        }
    })).catch((error) => {
        console.error("remoteSocketToWS error", error.stack || error);
        safeCloseWebSocket(webSocket);
    });

    if (hasIncomingData === false && retry) {
        log("Retrying connection...");
        retry();
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

var byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw TypeError("Stringified UUID is invalid");
    }
    return uuid;
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

async function handleUDPOutBound(webSocket, responseHeader, log) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength; ) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(dohURL, {
                method: "POST",
                headers: { "content-type": "application/dns-message" },
                body: chunk
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);

            if (webSocket.readyState === 1) {
                log(`DoH success, DNS message length: ${udpSize}`);
                if (isHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log("DNS UDP error" + error);
    });

    const writer = transformStream.writable.getWriter();
    return { write: (chunk) => writer.write(chunk) };
}

function getConfigPage(userID2, hostName, proxyIP2) {
    const vlessLink = `vless://${userID2}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#VLESS-${hostName}`;
    // Trojan Password = UUID (တူညီတယ်)
    const trojanLink = `trojan://${userID2}@${hostName}:443?security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#Trojan-${hostName}`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS + Trojan Config</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #0f172a; color: #e2e8f0; }
        h1 { color: #38bdf8; }
        h2 { color: #818cf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }
        pre { background: #1e293b; padding: 12px; border-radius: 8px; overflow-x: auto; word-wrap: break-word; white-space: pre-wrap; }
        .status-ok { color: #4ade80; }
        .status-warn { color: #fbbf24; }
        ul { line-height: 1.8; }
        .note { background: #334155; padding: 10px; border-radius: 6px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🚀 VLESS + Trojan Worker</h1>
    <p>Clean proxy implementation - UUID shared for both protocols</p>
    <p class="${proxyIP2 ? 'status-ok' : 'status-warn'}">
        ${proxyIP2 ? "✅ ProxyIP Active: " + proxyIP2 : "⚠️ Direct Connection (No ProxyIP set)"}
    </p>

    <div class="note">
        <strong>💡 Note:</strong> VLESS & Trojan နှစ်ခုလုံး <strong>တူညီတဲ့ UUID</strong> ကို သုံးထားပါတယ်။ 
        Trojan Client မှာ Password အဖြစ် UUID ကို ထည့်သွင်းပါ။
    </div>

    <h2>VLESS Connection Link</h2>
    <pre>${vlessLink}</pre>

    <h2>Trojan Connection Link</h2>
    <pre>${trojanLink}</pre>

    <h2>⚙️ Manual Configuration</h2>
    <ul>
        <li><strong>Address:</strong> ${hostName}</li>
        <li><strong>Port:</strong> 443</li>
        <li><strong>Security:</strong> TLS</li>
        <li><strong>SNI:</strong> ${hostName}</li>
        <li><strong>Network:</strong> WebSocket (WS)</li>
        <li><strong>Path:</strong> /?ed=2048</li>
        <li><strong>Host:</strong> ${hostName}</li>
    </ul>

    <h2>🔑 Credentials</h2>
    <ul>
        <li><strong>VLESS UUID:</strong> <code>${userID2}</code></li>
        <li><strong>Trojan Password:</strong> <code>${userID2}</code> (same as UUID)</li>
    </ul>
</body>
</html>`;
}

function getStatusPage(hostName, proxyIP2) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Status</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; text-align: center; background: #0f172a; color: #e2e8f0; }
        .ok { color: #4ade80; }
    </style>
</head>
<body>
    <h1 class="ok">✅ Worker is Running</h1>
    <p>Host: <strong>${hostName}</strong></p>
    <p>ProxyIP: <strong>${proxyIP2 || "Direct"}</strong></p>
    <p>Visit <code>/${userID}</code> or <code>/config</code> for connection links.</p>
</body>
</html>`;
}

export default worker_default;
