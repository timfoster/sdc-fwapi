/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.
 */

/*
 * Validation functions
 */

var assert = require('assert-plus');
var constants = require('./constants');
var mod_arr = require('./array');
var mod_err = require('../errors');
var util = require('util');
var net = require('net');



// --- Exports

function validUUID(uuid) {
    return constants.UUID_REGEX.test(uuid);
}

function validateFields(name, val) {
    var fields;
    var unknown = [];

    if (typeof (val) !== 'string' && !util.isArray(val)) {
        throw mod_err.invalidParamSubErr(name, 'must be an array or string');
    }

    fields = mod_arr.splitToArray(val);
    fields.forEach(function (field) {
        if (typeof (field) !== 'string') {
            throw mod_err.invalidParamSubErr(name,
                'must be an array of strings');
        }

        if (constants.PARSED_FIELDS.indexOf(field) === -1) {
            unknown.push(field);
        }
    });

    if (unknown.length !== 0) {
        throw mod_err.invalidParamSubErr(name,
            util.format('unknown field%s: %s',
                unknown.length === 1 ? '' : 's',
                unknown.join(', ')));
    }

    return fields;
}

function validateOwnerUUID(uuid)
{
    if (!validUUID(uuid)) {
        throw mod_err.invalidParamErr('Owner UUID', 'owner_uuid');
    }
}

function validateVm(name, uuid)
{
    if (typeof (uuid) == 'string') {
        if (!validUUID(uuid)) {
            throw mod_err.invalidParamErr('VM', 'vm');
        }
    } else {
        uuid.forEach(function (_uuid) {
            if (!validUUID(_uuid)) {
                throw mod_err.invalidParamErr('VM', 'vm');
            }
        });
    }
}

function validateIp(name, ip)
{
    if (typeof (ip) == 'string') {
        if (net.isIP(ip) === 0) {
            throw mod_err.invalidParamErr('IP Addr', 'ip');
        }
    } else {
        ip.forEach(function (_ip) {
            if (net.isIP(_ip) === 0) {
                throw mod_err.invalidParamErr('IP Addr', 'ip');
            }
        });
    }
}

function _validateSubnet(name, subnet)
{
    var subnetArr = subnet.split('/');
    if (subnetArr.length != 2) {
        throw mod_err.invalidParamErr('Subnet', 'subnet');
    }
    var ip = subnetArr[0];
    var is_ip = net.isIP(ip);
    if (is_ip === 0) {
        throw mod_err.invalidParamErr('Subnet', 'subnet');
    }
    var mask = subnetArr[1];
    var nmask = Number(mask);
    if (nmask === NaN) {
        throw mod_err.invalidParamErr('Subnet', 'subnet');
    } else if (is_ip == 4 && nmask > 31) {
        throw mod_err.invalidParamErr('Subnet', 'subnet');
    } else if (is_ip == 6 && nmask > 127) {
        throw mod_err.invalidParamErr('Subnet', 'subnet');
    }
}

function validateSubnet(name, subnet)
{
    if (typeof (subnet) == 'string') {
        _validateSubnet(name, subnet);
    } else {
        subnet.forEach(_validateSubnet.bind(null, name));
    }
}

function validateParams(validators, params) {
    assert.object(validators, 'validators');
    assert.object(params, 'params');

    var errs = [];
    var results = {};

    // XXX: add required

    for (var v in validators.optional) {
        if (!params.hasOwnProperty(v)) {
            continue;
        }

        try {
            results[v] = validators.optional[v](v, params[v]);
        } catch (valErr) {
            errs.push(valErr);
        }
    }

    if (errs.length !== 0) {
        throw new mod_err.InvalidParamsError(
            mod_err.INVALID_MSG, errs.map(function (e) {
                return {
                    code: e.body.errors[0].code,
                    field: e.body.errors[0].field,
                    message: e.body.errors[0].message
                };
            }));
    }

    return results;
}


module.exports = {
    uuid: validUUID,
    fields: validateFields,
    ip: validateIp,
    owner_uuid: validateOwnerUUID,
    subnet: validateSubnet,
    vm: validateVm,
    params: validateParams
};
