"use strict";
var serialport = require('serialport'),
    fs = require('fs'),
    EventEmitter = require('events').EventEmitter,
    Commands = require('./commands'),
    Class = require('./class'),
    forge = require('node-forge'),
    convertHex = require("convert-hex"),
    bigInt = require("big-integer"),
    crypto = require("crypto")

var SSPInstance = Class.extend({
    options: {},
    port: null,
    commands: null,
    keys: {
        generatorKey: null,
        modulusKey: null,
        hostRandom: null,
        hostIntKey: null,
        slaveIntKey: null,
        fixedKey: Buffer.from('0123456701234567', "hex"),
        variableKey: null,
        key: null,
        negotiateKeys: false,
        set_generator: false,
        set_modulus: false,
        request_key_exchange: false,
        finishEncryption: false
    },
    initialize: function (opts) {
        var self = this;
        var options = this.options = {
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
    },
    initiateKeys: function () {
        var commands = this.commands, self = this;
        var getRandomInt = function (min, max) {
            return Math.floor(Math.random() * (max - min)) + min;
        }

        var keyPair = forge.pki.rsa.generateKeyPair(64);
        self.keys.generatorKey = keyPair.privateKey.p;
        self.keys.modulusKey = keyPair.privateKey.q;
        self.keys.hostRandom = getRandomInt(1, 5);
        self.keys.hostIntKey = self.keys.generatorKey ^ self.keys.hostRandom % self.keys.modulusKey
        self.keys.negotiateKeys = true

    },
    parse: function (a, count) {
        for (var i = a.length; i < count; i++) {
            a.push(0)
        }
        return a;
    },
    sendGenerator: function () {
        var commands = this.commands, self = this;
        setTimeout(function () {
            var generatorArray = commands.parseHexString(self.keys.generatorKey.toString(16), 8)
            self.keys.set_generator = true;
            commands.set_generator.apply(this, generatorArray)
        }, 200)

    },
    sendModulus: function () {
        var commands = this.commands, self = this;
        setTimeout(function () {
            var modulusArray = commands.parseHexString(self.keys.modulusKey.toString(16), 8)
            self.keys.set_modulus = true;
            commands.set_modulus.apply(this, modulusArray)
        }, 200)
    },
    sendRequestKeyExchange: function () {
        var commands = this.commands, self = this;
        setTimeout(function () {
            var hostIntArray = commands.parseHexString(self.keys.hostIntKey.toString(16), 8)
            self.keys.request_key_exchange = true;
            commands.request_key_exchange.apply(this, hostIntArray)
        }, 200)

    },
    createHostEncryptionKeys: function (data) {
        var commands = this.commands, self = this;
        if (self.keys.key == null) {
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
            self.keys.slaveIntKey = slaveIntKeyString
            self.keys.key = self.keys.slaveIntKey ^ self.keys.hostRandom % self.keys.modulusKey
            self.keys.variableKey = self.keys.key
            self.keys.finishEncryption = true
            commands.setKeys(self.keys)
            self.emit("ready");

        }
    },
    enable: function (cb) {
        var commands = this.commands, self = this;
        var wait = function () {
            self.pollID = setTimeout(function () {
                commands.exec("poll", wait);
            }, 4000);
        }
        commands.exec("enable", function () {
            cb && cb();
            wait();
        });
    },
    disable: function (cb) {
        var self = this;
        self.pollID && clearTimeout(self.pollID);
        this.commands.exec("disable", function () {
            cb && cb();
        });
    },
    reset: function (cb) {
        var self = this;
        self.pollID && clearTimeout(self.pollID);
        this.commands.exec("reset", function () {
            self.port.close();
            cb && cb();
        });
    },
    init: function (enableOnInit, cb) {
        var port;
        var commands;
        var options = this.options;
        var self = this;
        if ("function" === typeof enableOnInit) {
            cb = enableOnInit;
            enableOnInit = false;
        }
        cb = cb || function () {
            };

        if (this.port && this.port.isOpen()) {
            this.port.close(function () {
                initializeDevice();
            });
        } else if (!options.device) {
            serialport.list(function (err, ports) {
                if (err || ports.length === 0) {
                    cb(err || new Error("No devices found"));
                } else {
                    for (var i in ports) {
                        if (ports[i].vendorId === '0x191c' || (ports[i].pnpId && ports[i].pnpId.indexOf('Innovative_Technology') > -1)) {
                            options.device = ports[i].comName;
                            //TODO: device autodetection
                        }
                    }
                    if (!options.device) {
                        cb(new Error("Device not found, try define manually"));
                    } else {
                        initializeDevice();
                    }
                }
            });
        } else {
            initializeDevice();
        }
        function initializeDevice() {
            port = new serialport.SerialPort(options.device, {
                baudrate: options.baudrate,
                databits: options.databits,
                stopbits: options.stopbits,
                parity: options.parity,
                parser: serialport.parsers.raw
            }, false);

            self.port = port;
            commands = self.commands = new Commands(port, options.type, options.sspID, options.sequence);
            port.on('close', function () {
                self.emit('close');
                console.log('close:');
            });
            port.on('error', function (err) {
                self.emit('error', err);
                console.log('error:', err);
            });
            port.on('readable', function () {
                console.log('Data:', port.read());
            });
            port.open(function (err) {
                function parseBuffer(buffer) {
                    var data, buf, error, crc;
                    if (buffer[0] === 0x7F) {
                        buf = buffer.toJSON();
                        if (buf.data) {
                            buf = buf.data;
                        }
                        data = buf.slice(3, 3 + buffer[2]);

                        crc = self.commands.CRC16(buf.slice(1, buf[2] + 3));

                        if (buf[buf.length - 2] !== crc[0] && buf[buf.length - 1] !== crc[1]) {
                            console.log('Wrong CRC from validator')
                            self.emit('error', new Error('Wrong CRC from validator'), buffer, crc);
                            return;
                        }
                        error = new Error("New error");
                        error.code = data[0];
                        switch (data[0]) {
                            case 0xF2:
                                error.message = "Command not known";
                                break;
                            case 0xF3:
                                error.message = "Wrong no parameters";
                                break;
                            case 0xF4:
                                error.message = "Parameter out of range";
                                break;
                            case 0xF5:
                                error.message = "Command cannot be processed";
                                break;
                            case 0xF6:
                                error.message = "Software error";
                                break;
                            case 0xF8:
                                error.message = "Fail";
                                break;
                            case 0xFA:
                                error.message = "Key not set";
                                break;
                            case 0xF0:
                                break;
                            default:
                                error.message = "Unknown error";
                        }
                        if (error.code == 0xFA) {
                            // self.keys.finishEncryption = false
                            // self.sendRequestKeyExchange()
                        }
                        if (error.code !== 0xF0) {
                            self.emit("error", error, buffer);
                        } else if (self.keys.negotiateKeys) {
                            if (!self.keys.set_generator) {
                                // console.log("data ", data)
                                self.sendGenerator()
                            } else if (!self.keys.set_modulus) {
                                // console.log("data ", data)
                                self.sendModulus()
                            } else if (!self.keys.request_key_exchange) {
                                // console.log("data ", data)
                                self.sendRequestKeyExchange()
                            } else if (!self.keys.finishEncryption && data.length == 9) {
                                // console.log("data ", data)
                                self.createHostEncryptionKeys(data)
                            }
                        } else if (data.length > 1) {
                            var event;
                            switch (data[1]) {
                                case 0xF1: //all
                                    event = ["slave_reset"];
                                    break;
                                case 0xEF: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["read_note", data[2]];
                                    break;
                                case 0xEE: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["credit_note", data[2]];
                                    break;
                                case 0xED: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["note_rejecting"];
                                    break;
                                case 0xEC: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    //recieve reject code
                                    self.commands.exec("last_reject_code");
                                    break;
                                case 0xCC: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["note_stacking"];
                                    break;
                                case 0xEB: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["note_stacked"];
                                    break;
                                case 0xEA: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["safe_note_jam"];
                                    break;
                                case 0xE9: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["unsafe_note_jam"];
                                    break;
                                case 0xE8: //all
                                    event = ["disabled"];
                                    break;
                                case 0xE6: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|nv201|SMART Payout|nv11|SMART Hopper
                                    event = ["fraud_attempt", data[2]];
                                    break;
                                case 0xE7: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["stacker_full"];
                                    break;
                                case 0xE1: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|nv201|SMART Payout|nv11
                                    event = ["note_cleared_from_front", data[2]];
                                    break;
                                case 0xE2: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|nv201|SMART Payout|nv11
                                    event = ["note_cleared_to_cashbox", data[2]];
                                    break;
                                case 0xE3: //bv50|bv100|nv200|SMART Payout|nv11
                                    event = ["cashbox_removed"];
                                    break;
                                case 0xE4: //bv50|bv100|nv200|SMART Payout|nv11
                                    event = ["cashbox_replaced"];
                                    break;
                                case 0xE5: //nv200|nv201
                                    event = ["barcode_ticket_validated"];
                                    break;
                                case 0xD1: //nv200|nv201
                                    event = ["barcode_ticket_acknowledge"];
                                    break;
                                case 0xE0: //nv200
                                    event = ["note_path_open"];
                                    break;
                                case 0xB5: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|SMART Payout|nv11
                                    event = ["channel_disable"];
                                    break;
                                case 0xB6: //bv20|bv50|bv100|nv9usb|nv10usb|nv200|nv201|SMART Payout|nv11|SMART Hopper
                                    event = ["initialing"];
                                    break;
                                case 0xDA: //SMART payout|SMART Hopper|nv11
                                    event = ["dispensing", data[2]];
                                    break;
                                case 0xD2: //SMART payout|SMART Hopper|nv11
                                    event = ["dispensed", data[2]];
                                    break;
                                case 0xD2: //SMART payout|SMART Hopper|nv11
                                    event = ["jammed", data[2]];
                                    break;
                                case 0xD6: //SMART payout|SMART Hopper|nv11
                                    event = ["halted", data[2]];
                                    break;
                                case 0xD7: //SMART payout|SMART Hopper
                                    event = ["floating", data[2]];
                                    break;
                                case 0xD8: //SMART payout|SMART Hopper
                                    event = ["floated", data[2]];
                                    break;
                                case 0xD9: //SMART payout|SMART Hopper|nv11
                                    event = ["timeout", data[2]];
                                    break;
                                case 0xDC: //SMART payout|SMART Hopper|nv11
                                    event = ["incomplete_payout", data[2]];
                                    break;
                                case 0xDD: //SMART payout|SMART Hopper|nv11
                                    event = ["incomplete_payout", data[2]];
                                    break;
                                case 0xDE: //SMART Hopper
                                    event = ["cashbox_paid", data[2]];
                                    break;
                                case 0xDF: //SMART Hopper
                                    event = ["coin_credit", data[2]];
                                    break;
                                case 0xC4: //SMART Hopper
                                    event = ["coin_mech_jammed"];
                                    break;
                                case 0xC5: //SMART Hopper
                                    event = ["coin_mech_return_pressed"];
                                    break;
                                case 0xB7: //SMART Hopper
                                    event = ["coin_mech_error"];
                                    break;
                                case 0xC2: //SMART payout|SMART Hopper|nv11
                                    event = ["emptying"];
                                    break;
                                case 0xC3: //SMART payout|SMART Hopper|nv11
                                    event = ["emptied"];
                                    break;
                                case 0xB3: //SMART payout|SMART Hopper|nv11
                                    event = ["smart_emptying", data[2]];
                                    break;
                                case 0xB4: //SMART payout|SMART Hopper|nv11
                                    event = ["smart_emptied", data[2]];
                                    break;
                                case 0xDB: //SMART payout|nv11
                                    event = ["note_stored_in_payout", data[2]];
                                    break;
                                case 0xC6: //SMART payout|nv11
                                    event = ["payout_out_of_service"];
                                    break;
                                case 0xB0: //SMART payout
                                    event = ["jam_recovery"];
                                    break;
                                case 0xB1: //SMART payout
                                    event = ["error_during_payout"];
                                    break;
                                case 0xC9: //SMART payout|nv11
                                    event = ["note_transfered to stacker", data[2]];
                                    break;
                                case 0xCE: //SMART payout|nv11
                                    event = ["note_held_in_bezel", data[2]];
                                    break;
                                case 0xCB: //SMART payout|nv11
                                    event = ["note_paid_into_store_at_powerup", data[2]];
                                    break;
                                case 0xCB: //SMART payout|nv11
                                    event = ["note_paid_into_stacker_at_powerup", data[2]];
                                    break;
                                case 0xCD: //nv11
                                    event = ["note_dispensed_at_powerup", data[2]];
                                    break;
                                case 0xC7: //nv11
                                    event = ["note_float_removed"];
                                    break;
                                case 0xC8: //nv11
                                    event = ["note_float_attached"];
                                    break;
                                case 0xC9: //nv11
                                    event = ["device_full"];
                                    break;
                                //Reject reasons
                                case 0x0:
                                case 0x1:
                                case 0x2:
                                case 0x3:
                                case 0x4:
                                case 0x5:
                                case 0x6:
                                case 0x7:
                                case 0x8:
                                case 0x9:
                                case 0xa:
                                case 0xb:
                                case 0xc:
                                case 0xd:
                                case 0xe:
                                case 0xf:
                                case 0x10:
                                case 0x11:
                                case 0x12:
                                case 0x13:
                                case 0x14:
                                case 0x15:
                                case 0x16:
                                case 0x17:
                                case 0x18:
                                case 0x19:
                                case 0x1a:
                                case 0x1b:
                                case 0x1c:
                                    event = ["note_rejected", data[1]];
                                    break;
                            }
                            event && self.emit.apply(self, event);
                        }
                    } else {
                        self.emit('unregistered_data', buffer);
                    }
                }

                if (err) {
                    cb(err);
                } else {
                    port.on('data', function (buffer) {
                        console.log("COM1 <= ", Array.prototype.slice.call(buffer, 0).map(function (item) {
                            return item.toString(16).toUpperCase()
                        }))
                        var ix = 0;
                        do {
                            var len = buffer[2] + 5;
                            var buf = new Buffer(len);
                            buffer.copy(buf, 0, ix, ix + len);
                            parseBuffer(buf);
                            ix += len;
                        } while (ix < buffer.length);
                    });

                    //wait a bit for port buffer to empty

                    setTimeout(function () {
                        commands.sync().enable_higher_protocol()
                        // self.initiateKeys();
                        if (enableOnInit) {
                            cb && cb();
                            self.enable(function () {
                                self.emit("ready");
                            });
                        } else {
                            commands.exec(function () {
                                cb && cb();
                                self.emit("ready");
                            });
                        }
                    }, 2000);
                }
            });
        }
    }
});

SSPInstance.prototype.__proto__ = EventEmitter.prototype;

module.exports = SSPInstance;
