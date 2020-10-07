const fs = require('fs');
const path = require('path');
const tls = require('tls');
const net = require('net');
const dgram = require('dgram');

/**
 * Used DOCS:
 * https://tools.ietf.org/html/rfc5424   // The Syslog Protocol
 * https://tools.ietf.org/html/rfc6587   // Transmission of Syslog Messages over TCP
 * https://tools.ietf.org/html/rfc5425   // Transport Layer Security (TLS) Transport Mapping for Syslog
 */

const SYSLOG_PRI = (1) * 8 + (5)  // Facility: user-level messages (1); Severity: Notice (5)
const SYSLOG_VERSION = 1
const SYSLOG_APP_NAME = "TANlockManager"
const SYSLOG_PROCID = `PID${process.pid}`
const SYSLOG_PRIVATE_ENTERPRISE_NUMBER = "61208" //"Fath" Alphabet Position
const SYSLOG_NILVALUE = "-"
const SYSLOG_BOM = "\ufeff"

let _config = {};
let inited = false;
let udpSocket;
let tcpSocket;
let tlsSocket;

const _baseConfig = {
    useTCP: false,
    tcpTLS: false,
    tcpOC: true,
    tcpNonTransparentFramingChar: "\n",
    port: 514,
    host: "255.255.255.255",
    syslogHostname: SYSLOG_NILVALUE
};

function _getConfig() {
    return new Promise((resolve, reject) => {
        resolve(_getConfigSync());
    });
}

function _getConfigSync() {
    try {
        let data = fs.readFileSync(path.join(__dirname, "syslogConfig.json"), { encoding: "utf-8" });
        return JSON.parse(data.toString('utf8'));
    } catch{
        return _baseConfig;
    }
}

function _onEvent(type, body) {
    let syslogMsg = _createSysLogMsg(type, body);
    // console.log(syslogMsg);
    if (!inited) {
        return
    }
    if (_config.useTCP || _config.useTLS) {
        if (_config.tcpOC || _config.tcpTLS) {
            syslogMsg = _addOctettCount(syslogMsg);
        } else {
            syslogMsg = _addNonTransparentFraming(syslogMsg);
        }
        if (_config.tcpTLS) {
            _sendTls(syslogMsg);
        } else {
            _sendTcp(syslogMsg);
        }
    } else {
        _sendUdp(syslogMsg);
    }
}

function _createSysLogMsg(type, body) {
    let timestamp = new Date(body.timestamp).toISOString();
    let msg_id = type.toUpperCase();
    // msg_id = SYSLOG_NILVALUE;
    let syslogMsg = `<${SYSLOG_PRI}>${SYSLOG_VERSION} ${timestamp} ${_config.syslogHostname} ${SYSLOG_APP_NAME} ${SYSLOG_PROCID} ${msg_id}`

    let structuredData = _createStructuredData(type, body);
    if (structuredData.length > 0) {
        syslogMsg += ` ${structuredData}`
    } else {
        syslogMsg += ` ${SYSLOG_NILVALUE}`
    }

    let msg = _createMsg(type, body);
    if (msg.length > 0) {
        syslogMsg += ` ${SYSLOG_BOM}${msg}`
    }

    return syslogMsg;
}

function _createStructuredData(type, body) {
    let structEvent = _createEventStructured(body);
    let structLock = _createObjStructured("tanlock", _slimLock(body.tanlock));
    let structCabinet = _createObjStructured("cabinet", _slimCabinet(body.cabinet));
    let structRow = _createObjStructured("row", _slimRow(body.row));
    let structCage = _createObjStructured("cage", _slimCage(body.cage));

    let structuredData = "";
    structuredData = _splittAppend(structuredData, structEvent);
    structuredData = _splittAppend(structuredData, structLock);
    structuredData = _splittAppend(structuredData, structCabinet);
    structuredData = _splittAppend(structuredData, structRow);
    structuredData = _splittAppend(structuredData, structCage);

    return structuredData;
}

function _splittAppend(base, app, delim = " ") {
    if (base.length > 0) {
        return `${base}${delim}${app}`;
    } else {
        return `${app}`;
    }
}

function _createEventStructured(body) {
    return `[event@${SYSLOG_PRIVATE_ENTERPRISE_NUMBER} event="${body.event}" eventId="${body.eventId}"]`;
}

function _createObjStructured(name, obj) {
    if (obj == null) {
        return "";
    } else {
        let data = "";
        for (let [key, value] of Object.entries(obj)) {
            data = _splittAppend(data, `${key}="${value}"`);
        }
        return `[${name}@${SYSLOG_PRIVATE_ENTERPRISE_NUMBER} ${data}]`;
    }
}

//Slim methods to Leak no Irrelevant Data
function _slimLock(lock) {
    if (lock == null)
        return null;
    return {
        id: lock.id,
        ip: lock.ip,
        name: lock.name,
        state: lock.state,
        door_1: lock.door_1,
        door_2: lock.door_2
    };
}

function _slimCabinet(cab) {
    if (cab == null)
        return null;
    return {
        id: cab.id,
        name: cab.name,
        frontLock: cab.frontLock,
        backLock: cab.backLock
    };
}

function _slimRow(row) {
    if (row == null)
        return null;
    return {
        id: row.id,
        name: row.name,
    };
}

function _slimCage(cage) {
    if (cage == null)
        return null;
    return {
        id: cage.id,
        name: cage.name,
        color: cage.color
    };
}

function _createMsg(type, body) {
    if (body.eventMessage != null) {
        return body.eventMessage;
    }
    return "";
}

//TCP Framing Methods
function _addOctettCount(msg) {
    let count = Buffer.from(msg).byteLength;
    return `${count} ${msg}`
}

function _addNonTransparentFraming(msg) {
    return `${msg}${_config.tcpNonTransparentFramingChar}`
}

//Send MSG Methods
function _sendUdp(msg) {
    let buffer = Buffer.from(msg);
    udpSocket.send(buffer, _config.port, _config.host);
}

function _sendTcp(msg) {
    let buffer = Buffer.from(msg);
    tcpSocket.write(buffer);
}

function _sendTls(msg) {
    let buffer = Buffer.from(msg);
    tlsSocket.write(buffer);
}

module.exports = {
    init: (config) => {
        _config = _getConfigSync() //Load Init Conf
        try {
            if (_config.useTCP || _config.tcpTLS) { //Open Syslog Socket
                if (_config.tcpTLS) {
                    tlsSocket = tls.connect(_config.port, _config.host);
                } else {
                    tcpSocket = net.createConnection(_config.port, _config.host);
                }
            } else {
                udpSocket = dgram.createSocket('udp4', () => {
                    udpSocket.setBroadcast(true); // Allow Broadcast
                });
            }
            inited = true
        } catch (error) {
            console.error(error)
        }
    },

    name: () => "SysLog",

    onEvent: (type, body) => _onEvent(type, body),

    getConfig: () => {
        return new Promise(resolve => {
            _getConfig().then(conf => {
                resolve(conf);
            }).catch(e => {
                resolve(_baseConfig);
            });
        });
    },

    writeConfig: (config) => {
        _config = config // Place Conf Locally
        fs.writeFile(path.join(__dirname, "syslogConfig.json"), JSON.stringify(config), (err) => {
            if (err) {
                console.error("Store Config", err);
            }
        });
    },

    getHelp: () => {
        return '{\n' +
            '    "useTCP": false,\n' +
            '    "tcpTLS": false,\n' +
            '    "tcpOC": true,\n' +
            '    "tcpNonTransparentFramingChar": "\\n",\n' +
            '    "port": 514,\n' +
            '    "host": "255.255.255.255",\n' +
            '    "syslogHostname": "-"\n' +
            '}'
    }
};
