/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * Integration tests for getting rules
 */

var test = require('tape');
var mod_rule = require('../lib/rule');
var mod_vm = require('../lib/vm');
var mod_uuid = require('node-uuid');
var mod_vasync = require('vasync');



// --- Globals



var OWNERS = [
    mod_uuid.v4(),
    mod_uuid.v4()
];

var VM_ALIASES = [
    'vmapi0',
    'fwapi0',
    'cnapi0',
    'napi0'
];

var VM_UUIDS = [];
var RULES = [];

function
alias2uuid(vm_alias, cb)
{
    console.log('alias2uuid entry');
    mod_vm.list({ alias: vm_alias }, function (err, res) {
        if (err) {
            console.log('alias2uuid ERROR');
            /* XXX handle this */
            return;
        }
        console.log('alias2uuid FOREACH');
        res.forEach(function (vm) {
            console.log('alias2uuid PUSH');
            console.log(vm);
            VM_UUIDS.push(vm.uuid);
            console.log(VM_UUIDS);
        });
        cb(err, res);
        console.log('alias2uuid EXIT');
    });
}

test('get service zone uuids', function (t) {
    console.log('BEGIN VM PIPELINE');
    mod_vasync.forEachPipeline({
        'func': alias2uuid,
        'inputs': VM_ALIASES
    }, function (err, res) {
        console.log('END VM PIPELINE');
        console.log(res);
        t.end();
    });
});

test('Create Rules', function (t) {
    RULES = [
        {
            enabled: true,
            owner_uuid: OWNERS[0],
            rule: 'FROM any TO all vms ALLOW tcp PORT 5000'
        },
        {
            enabled: true,
            owner_uuid: OWNERS[1],
            rule: 'FROM (tag foo = bar OR tag foo = baz) '
                + 'TO tag side = two ALLOW tcp (PORT 5003 AND PORT 5004)'
        },
        {
            enabled: true,
            global: true,
            rule: 'FROM any TO tag foo = baz ALLOW tcp PORT 5010'
        },
        /* IP rule, VM rule, subnet rule */
        {
            enabled: true,
            global: true,
            rule: 'FROM ip 8.8.8.8 TO tag foo = baz ALLOW tcp PORT 5010'
        },
        {
            enabled: true,
            global: true,
            rule: 'FROM ip 4.4.4.4 TO tag foo = baz ALLOW tcp PORT 5010'
        },
        {
            enabled: true,
            global: true,
            rule: 'FROM subnet 10.8.0.0/16 TO tag foo = baz ALLOW tcp PORT 5010'
        },
        {
            enabled: true,
            global: true,
            rule: 'FROM subnet 10.7.0.0/16 TO tag foo = baz ALLOW tcp PORT 5010'
        },
        {
            enabled: true,
            global: true,
            rule: 'FROM vm ' + VM_UUIDS[0] +
                ' TO tag foo = baz ALLOW tcp PORT 5010'
        },
        {
            enabled: true,
            global: true,
            rule: 'FROM vm ' + VM_UUIDS[1] +
                ' TO tag foo = baz ALLOW tcp PORT 5010'
        }
    ];
    t.end();
});


// --- Tests



test('add all rules', function (t) {
    mod_rule.createAndGetN(t, {
        rules: RULES
    });
});


test('get: owner rule with owner_uuid', function (t) {
    mod_rule.get(t, {
        uuid: RULES[0].uuid,
        params: {
            owner_uuid: OWNERS[0]
        },
        exp: RULES[0]
    });
});


test('get: owner rule with wrong owner_uuid', function (t) {
    mod_rule.get(t, {
        uuid: RULES[0].uuid,
        params: {
            owner_uuid: OWNERS[1]
        },
        expCode: 403,
        expErr: {
            code: 'Forbidden',
            message: 'owner does not match',
            errors: [ {
                field: 'owner_uuid',
                code: 'InvalidParameter',
                message: 'owner_uuid does not match'
            } ]
        }
    });
});

test('get: owner rule with misformatted uuid', function (t) {
    mod_rule.list(t, {
        params: {
            owner_uuid: 'not-a-uuid'
        },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'owner_uuid',
                code: 'InvalidParameter',
                message: 'Invalid Owner UUID'
            } ]
        }
    });
});

test('get: ip rule with misformatted ip', function (t) {
    mod_rule.list(t, {
        params: {
            ip: 'not-an-ip'
        },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'ip',
                code: 'InvalidParameter',
                message: 'Invalid IP Addr'
            } ]
        }
    });
});

function
test_done(t, err, res)
{
    t.end();
}

test('get: ip rule with non-string value', function (t) {
    mod_rule.list(t, {
        params: { ip: 42 },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'ip',
                code: 'InvalidParameter',
                message: 'Invalid IP Addr'
            } ]
        }
    });
});

test('get: ip rule with non-string values', function (t) {
    mod_rule.list(t, {
        params: { ip: [42, {}] },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'ip',
                code: 'InvalidParameter',
                message: 'Invalid IP Addr'
            } ]
        }
    });
});

test('get: ip rule with valid ip', function (t) {
    mod_rule.list(t, {
        params: { ip: '8.8.8.8' },
        expCode: 200
    }, test_done.bind(null, t));
});

test('get: ip rule with valid ips', function (t) {
    mod_rule.list(t, {
        params: { ip: ['8.8.8.8', '4.4.4.4'] },
        expCode: 200
    }, test_done.bind(null, t));
});

test('get: vm rule with misformatted vm', function (t) {
    mod_rule.list(t, {
        params: {
            vm: 'not-a-vm'
        },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'vm',
                code: 'InvalidParameter',
                message: 'Invalid VM'
            } ]
        }
    });
});

test('get: vm rule with non-string value', function (t) {
    mod_rule.list(t, {
        params: { vm: 42 },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'vm',
                code: 'InvalidParameter',
                message: 'Invalid VM'
            } ]
        }
    });
});

test('get: vm rule with non-string values', function (t) {
    mod_rule.list(t, {
        params: { vm: [42, {}] },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'vm',
                code: 'InvalidParameter',
                message: 'Invalid VM'
            } ]
        }
    });
});

test('get: vm rule with valid vm', function (t) {
    mod_rule.list(t, {
        params: { vm: VM_UUIDS[0] },
        expCode: 200
    }, test_done.bind(null, t));
});

test('get: vm rule with valid vms', function (t) {
    mod_rule.list(t, {
        params: { vm: [VM_UUIDS[0], VM_UUIDS[1]] },
        expCode: 200
    }, test_done.bind(null, t));
});

test('get: subnet rule with misformatted subnet', function (t) {
    mod_rule.list(t, {
        params: {
            subnet: 'not-a-subnet'
        },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'subnet',
                code: 'InvalidParameter',
                message: 'Invalid Subnet'
            } ]
        }
    });
});

test('get: subnet rule with non-string value', function (t) {
    mod_rule.list(t, {
        params: { subnet: 42 },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'subnet',
                code: 'InvalidParameter',
                message: 'Invalid Subnet'
            } ]
        }
    });
});

test('get: subnet rule with non-string values', function (t) {
    mod_rule.list(t, {
        params: { subnet: [42, {}] },
        expCode: 422,
        expErr: {
            code: 'InvalidParameters',
            message: 'Invalid parameters',
            errors: [ {
                field: 'subnet',
                code: 'InvalidParameter',
                message: 'Invalid Subnet'
            } ]
        }
    });
});

test('get: subnet rule with valid subnet', function (t) {
    mod_rule.list(t, {
        params: { subnet: '10.8.0.0/16' },
        expCode: 200
    }, test_done.bind(null, t));
});

test('get: subnet rule with valid subnets', function (t) {
    mod_rule.list(t, {
        params: { subnet: [ '10.8.0.0/16', '10.7.0.0/16'] },
        expCode: 200
    }, test_done.bind(null, t));
});

test('get: global rule with no params', function (t) {
    mod_rule.get(t, {
        uuid: RULES[2].uuid,
        exp: RULES[2]
    });
});



// --- Teardown



test('teardown', mod_rule.delAllCreated);
