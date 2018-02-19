"use strict";
import fs from 'fs'
import serialport from 'serialport'
import Commands from './commands'
import forge from 'node-forge'
import convertHex from "convert-hex"
import bigInt from "big-integer"
import EventEmitter from "event-emitter-es6"
import chalk from 'chalk'

export default class eSSP extends EventEmitter {
    constructor() {
        super()
        this.options = {};
        this.port = null;
        this.commands = null
        this.count = 0
        this.sequence = 0x80;
        this.keys = {
            generatorKey: null,
            modulusKey: null,
            hostRandom: null,
            hostIntKey: null,
            slaveIntKey: null,
            fixedKey: Buffer.from("0123456701234567", "hex"),
            variableKey: null,
            key: null,
            negotiateKeys: false,
            set_generator: false,
            set_modulus: false,
            request_key_exchange: false,
            finishEncryption: false
        }
    }

    initialize(opts) {
        let options = this.options = {
            device: opts.device || null,
            baudrate: opts.baudrate || 9600,
            databits: opts.databits || 8,
            stopbits: opts.stopbits || 2,
            parity: opts.parity && ['even', 'mark', 'odd', 'space'].indexOf(opts.parity.toString().toLowerCase()) > -1 ? opts.parity : 'none',
            currencies: opts.currencies || [1, 0, 1],
            type: opts.type || "nv10usb",
            sspID: opts.sspID || 0,
            seqence: opts.sequence || 0x80
        };
        if (fs.readdirSync(__dirname + '/commands').map(function (item) {
                return item.replace(/\..+$/, '');
            }).indexOf(options.type) === -1) {
            throw new Error("Unknown device type '" + options.type + "'");
        }

        var port = new serialport.SerialPort(options.device, {
            baudrate: options.baudrate,
            databits: options.databits,
            stopbits: options.stopbits,
            parity: options.parity,
            parser: serialport.parsers.raw
        }, false);


        port.open(() => {
            let parseBuffer = async(buffer) => {
                var data, buf, error, crc;
                if (buffer[0] === 0x7F) {
                    buf = buffer.toJSON();
                    if (buf.data) {
                        buf = buf.data;
                    }
                    data = buf.slice(3, 3 + buffer[2]);
                    crc = this.CRC16(buf.slice(1, buf[2] + 3));
                    if (buf[buf.length - 2] !== crc[0] && buf[buf.length - 1] !== crc[1]) {
                        console.log(chalk.red('Wrong CRC from validator'))
                        return;
                    }
                    console.log(chalk.magenta(data))

                    if (!this.keys.finishEncryption && data.length ==9) {
                        this.createHostEncryptionKeys(data)
                    }
                } else {
                    self.emit('unregistered_data', buffer);
                }
            }

            port.on('data', function (buffer) {
                console.log("COM1 <= ", chalk.green(Array.prototype.slice.call(buffer, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                var ix = 0;
                do {
                    var len = buffer[2] + 5;
                    var buf = new Buffer(len);
                    buffer.copy(buf, 0, ix, ix + len);
                    parseBuffer(buf);
                    ix += len;
                } while (ix < buffer.length);
            });

        })
        port.on('error', (err) => {
            console.log(chalk.red(err));
        });

        this.port = port;
    }

    async initiateKeys() {
        var getRandomInt = function (min, max) {
            return Math.floor(Math.random() * (max - min)) + min;
        }

        var keyPair = forge.pki.rsa.generateKeyPair(64);
        this.keys.generatorKey = keyPair.privateKey.p;
        this.keys.modulusKey = keyPair.privateKey.q;
        this.keys.hostRandom = getRandomInt(1, 5);
        this.keys.hostIntKey = this.keys.generatorKey ^ this.keys.hostRandom % this.keys.modulusKey
        this.keys.negotiateKeys = true;

        console.log(this.keys)
        let data = await this.sync()
        data = await this.sync()
        data = await this.sendGenerator()
        data = await this.sendGenerator()
        data = await this.sendModulus()
        data = await this.sendModulus()
        data = await this.sendRequestKeyExchange()
        data = await this.sendRequestKeyExchange()
    }

    parseHexString(str, count) {
        var a = [];
        for (var i = str.length; i > 0; i -= 2) {
            a.push(parseInt(str.substr(i - 2, 2), 16));
        }
        for (var i = a.length; i < count; i++) {
            a.push(0)
        }
        return a;
    }

    disable() {
        var packet = this.toPackets(0x09)
        var buff = new Buffer(packet)
        return new Promise((resolve, reject) => {
            setTimeout(()=> {
                console.log("COM1 => ", chalk.blue(Array.prototype.slice.call(buff, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                this.port.write(buff, ()=> {
                    this.port.drain()
                })
            }, 2000)
        });
    }

    sync() {
        var packet = this.toPackets(0x11)
        var buff = new Buffer(packet)
        return new Promise((resolve, reject) => {
            setTimeout(()=> {
                console.log("COM1 => ", chalk.yellow(Array.prototype.slice.call(buff, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                this.port.write(buff, ()=> {
                    this.port.drain()
                    resolve(true)
                })
            }, 1000)


        });
    }

    sendGenerator() {
        var generatorArray = this.parseHexString(this.keys.generatorKey.toString(16), 8)
        var packet = this.toPackets(0x4A, generatorArray)
        var buff = new Buffer(packet)
        return new Promise((resolve, reject) => {
            setTimeout(()=> {
                console.log("COM1 => ", chalk.yellow(Array.prototype.slice.call(buff, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                this.port.write(buff, ()=> {
                    this.keys.set_generator = true
                    this.port.drain()
                    resolve(true)
                })
            }, 1000)
        });
    }

    sendModulus() {
        var modulusArray = this.parseHexString(this.keys.modulusKey.toString(16), 8)
        var packet = this.toPackets(0x4B, modulusArray)
        var buff = new Buffer(packet)
        return new Promise((resolve, reject) => {
            setTimeout(()=> {
                console.log("COM1 => ", chalk.yellow(Array.prototype.slice.call(buff, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                this.port.write(buff, ()=> {
                    this.keys.set_modulus = true
                    this.port.drain()
                    resolve(true)
                })
            }, 1000)
        });
    }

    sendRequestKeyExchange() {
        var hostIntArray = this.parseHexString(this.keys.hostIntKey.toString(16), 8)
        var packet = this.toPackets(0x4C, hostIntArray)
        var buff = new Buffer(packet)
        return new Promise((resolve, reject) => {
            setTimeout(()=> {
                console.log("COM1 => ", chalk.yellow(Array.prototype.slice.call(buff, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                this.port.write(buff, ()=> {
                    this.keys.request_key_exchange = true
                    this.port.drain()
                    resolve(true)
                })
            }, 1000)
        });
    }

    createHostEncryptionKeys(data) {
        if (this.keys.key == null) {
            data.shift()
            var hexString = convertHex.bytesToHex(data.reverse());

            var slaveIntKey = bigInt(hexString, 16);
            var slaveIntKeyString = ""
            if (!slaveIntKey.isSmall) {
                var values = slaveIntKey.value.reverse();
                for (var i = 0; i < values.length; i++) {
                    slaveIntKeyString += "" + values[i]
                }
            } else {
                slaveIntKeyString = slaveIntKey.value
            }
            this.keys.slaveIntKey = slaveIntKeyString
            this.keys.key = this.keys.slaveIntKey ^ this.keys.hostRandom % this.keys.modulusKey
            this.keys.variableKey = this.keys.key
            this.keys.finishEncryption = true
            this.emit("ready");
        }
    }

    setDenominationRoute() {
        var packet = this.toPackets(0x3B, [0x00, 0x64, 0x00, 0x00, 0x00, 0x55, 0x53, 0x44])
        var buff = new Buffer(packet)
        return new Promise((resolve, reject) => {
            setTimeout(()=> {
                console.log("COM1 => ", chalk.yellow(Array.prototype.slice.call(buff, 0).map(function (item) {
                    return item.toString(16).toUpperCase()
                })))
                this.port.write(buff, ()=> {
                    this.port.drain()
                    resolve(true)
                })
            }, 1000)
        });
    }

    CRC16(command) {
        var length = command.length,
            seed = 0xFFFF,
            poly = 0x8005,
            crc = seed;

        for (var i = 0; i < length; i++) {
            crc ^= (command[i] << 8);
            for (var j = 0; j < 8; j++) {
                if (crc & 0x8000) {
                    crc = ((crc << 1) & 0xffff) ^ poly;
                } else {
                    crc <<= 1;
                }
            }
        }
        return [(crc & 0xFF), ((crc >> 8) & 0xFF)];
    }

    getSequence() {
        if (this.sequence == 0x80) {
            this.sequence = 0x00
        } else {
            this.sequence = 0x80
        }
        return this.sequence
    }

    toPackets(command, args = []) {
        var commandLine
        var STX = 0x7F
        var LENGTH = args.length + 1
        var SEQ_SLAVE_ID = this.getSequence()
        var DATA = [command].concat(args)

        commandLine = [SEQ_SLAVE_ID, LENGTH].concat(DATA);
        var crc = this.CRC16(commandLine);
        commandLine = [STX].concat(commandLine, crc);

        return commandLine
    }

}

