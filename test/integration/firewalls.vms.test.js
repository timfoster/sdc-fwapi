/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Unit tests for /firewalls/vms/:uuid endpoint.
 */

var assert = require('assert-plus');
var fmt = require('util').format;
var helpers = require('./helpers');
var mod_rule = require('../lib/rule');
var mod_vm = require('../lib/vm');
var mod_uuid = require('node-uuid');
var util = require('util');
var config = require('../lib/config');
var async = require('async');
var mod_vasync = require('vasync');
var mod_client = require('../lib/client');

var OWNERS = [ config.test.owner_uuid ];

var VMS = [];
var delVMS = [];
var NVM = 9;

/*
 * Create NVM number of VMs. Use them for our evil experiments. We use mod_vm's
 * provision() function which takes an array of VM configs as an option, and
 * uses those to create the VMs just how we like them.
 */
exports.setup = function (t)
{
    var vms = [];
    for (var vi = 0; vi < NVM; vi++) {
        vms[vi] =
            {
                alias: mod_vm.alias(),
                firewall_enabled: true,
                owner_uuid: OWNERS[0],
                server_uuid: config.test.server1_uuid,
                tags: { }
            };
    }

    mod_vm.provision(t, {
        vms: vms
    }, function (err, res) {
        t.ok(err === null, 'Should have no provisioning errors');
        if (res) {
            VMS = res;
        }

        /* now we delete the last 2 vms. */
        var di = 0;
        for (vi = 8; vi < NVM; vi++) {
            delVMS[di] = VMS[vi];
            di++;
        }

        var doDelete = function (t2, vm, cb) {
            mod_vm.delOneNoPoll(t2, { uuid: vm.uuid }, cb);
        };

        var count = 0;

        mod_vasync.forEachParallel({
            'func': doDelete.bind(null, t),
            'inputs': delVMS
        }, function delCb(err2, res2) {
            count++;
            if (err2) {
                return;
            }
            if (count == delVMS.length) {
                t.done();
                return (t);
            } else {
                return;
            }
        });
    });
};


/*
 * After we've created the VMs and initialized the delete of the last VM, we
 * want to sleep for 5 minutes, to give the system time to propagate the new VM
 * state. This may seem like a hack, and like polling is a better solution. But
 * it's not -- as that makes the tests unbearable slow.
 */
exports.sleep = function (t)
{
    setTimeout(t.done, 5*60*1000);
};



/*
 * So we have $NVM VMs. For the singular rule case, we want to take the first
 * VM and create 2 rules for it:
 *      -In the first rule it is the only VM in the FROM clause.
 *          -All other VMs are in TO clause.
 *      -In the second rule it is the only VM in the TO clause.
 *          -All other VMs are in FROM clause.
 *
 * The expectation is that if we call DELETE /firewalls/vms/:uuid on the first
 * machine, the rules above will be deleted. We try this for both the case
 * where the VM exists and where the VM is deleted. It should work for both,
 * regardless.
 *
 * For the multi machine case, we place half the VMs in one of the clauses, and
 * all of the VMs in the other clause. We delete each of the machine in the
 * half-sized group and call the endpoint on it.
 *
 * The expectation is that the rule-deletion should fail until we get to the
 * last call of the endpoint.
 */

/*
 * Returns either all vms in the VMS array, or a limited number.
 */
function all_vm_list(limit)
{
    var N = NVM;
    if (limit) {
        N = limit;
    }

    assert.arrayOfObject(VMS, 'VMS');

    var vm_map_cb = function (vm) {
        assert.uuid(vm.uuid);
        return 'VM ' + vm.uuid;
    };

    return '(' + VMS.slice(0, N).map(vm_map_cb).join(' OR ') + ')';
}

/*
 * Prints two VMs from the VMS array, user's choice (by index).
 */
function two_vm_list(a, b)
{
    var ret = '';
    assert.arrayOfObject(VMS, 'VMS');
    assert.number(a, 'a');
    assert.number(b, 'b');
    ret = '( VM ' + VMS[a].uuid + ' OR VM ' + VMS[b].uuid + ')';
    return (ret);
}

var singularRules = function (t)
{
    /* create 2 rules (we arbitrarily use port 22) */
    var rule1raw = {
        description: 'Singular FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM VM %s TO %s ALLOW tcp PORT 22',
                 VMS[0].uuid, all_vm_list(4))
    };
    var rule2raw = {
        description: 'Singular TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO VM %s ALLOW tcp PORT 22',
                all_vm_list(4), VMS[0].uuid)
    };

    var expErr = {
        code: 'ResourceNotFound',
        message: 'Rule not found'
    };

    /*
     * This callback is meant to be run by the create-rule function. It does
     * some basic checking, and then calls the FWAPI endpoint for deleting
     * rules that affect a VM (VMS[0].uuid). The function that calls this
     * endpoint (deleteVMrules), also take a callback which checks to see if
     * these rules still exist.
     */
    var rule_create_cb = function (invocation, err, rule) {
        t.ok(err === null, 'Should not err when creating rule.');
        if (err) {
            t.done();
            return;
        }

        mod_rule.deleteVMrules(t, {
            uuid: VMS[0].uuid,
            params: { owner_uuid: OWNERS[0] }
            }, function (err2, res2) {
                mod_rule.get(t, {uuid: rule.uuid, expErr: expErr, expCode: 404},
                    function (err3, res3) {

                    t.ok(err3 !== null, 'err3 !== null');
                    /* This rule should be deleted by now. */
                    if (err3) {
                        /*
                         * rule_create_cb() gets called in two contexts. It
                         * gets called as a consequence of our first call to
                         * `mod_rule.create()` at the bottom of the
                         * `singularRules()` function. It also gets called
                         * on itself as a consequence of calling
                         * `mod_rule.create()` in the if-block below. Both of
                         * these invocations do esseintally the same thing.
                         * Except that invocation 1 results in a single
                         * iteration of a recursive-loop -- it calls
                         * `mod_rule.create()`, on rule 2, passing itself as a
                         * callback. We only have 2 rules, so on the second
                         * invocation, we terminate this loop/recursion by
                         * verifying that the rule has been deleted, and ending
                         * the test via `t.done()`.
                         *
                         * In other words, `invocation` is akin to a loop
                         * counter, and the counter can never exceed 2.
                         *
                         * There is probably a better way to do this.
                         */
                        if (invocation == 1) {
                            mod_rule.create(t, {rule: rule2raw},
                                rule_create_cb.bind(null, 2));
                        } else {
                            mod_rule.get(t, {uuid: rule.uuid, expErr: expErr,
                                expCode: 404}, function (err4, res4) {
                                /*
                                 * This get-request should also return an
                                 * error.
                                 */
                                t.ok(err4 !== null, 'err4 !== null');
                                t.done();
                            });
                        }
                    } else {
                        t.done();
                    }
                });
             });
    };

    mod_rule.create(t, {rule: rule1raw}, rule_create_cb.bind(null, 1));

    return (t);
};

var singularCommon = function (t, rule_raw, deletable) {
    var expErr = {
        code: 'ResourceNotFound',
        message: 'Rule not found'
    };

    /*
     * This callback is meant to be run by the create-rule function. It does
     * some basic checking, and then calls the FWAPI endpoint for deleting
     * rules that affect a VM (VMS[0].uuid). The function that calls this
     * endpoint (deleteVMrules), also take a callback which checks to see if
     * these rules still exist.
     */
    var rule_create_cb = function (err, rule) {
        t.ok(err === null, 'Should not err when creating rule.');
        if (err) {
            t.done();
            return;
        }

        mod_rule.deleteVMrules(t, {
            uuid: VMS[0].uuid,
            params: { owner_uuid: OWNERS[0] }
            }, function (err2, res2) {
                var del_vm_args;
                if (deletable) {
                    del_vm_args = {uuid: rule.uuid, expErr: expErr, expCode: 404};
                } else {
                    del_vm_args = {uuid: rule.uuid};
                }
                mod_rule.get(t, del_vm_args, function (err3, res3) {

                    if (deletable) {
                        t.ok(err3 !== null, 'err3 !== null');
                    } else {
                        t.ok(err3 === null, 'err3 === null');
                    }
                    if (err3) {
                        mod_rule.get(t, {uuid: rule.uuid, expErr: expErr,
                            expCode: 404}, function (err4, res4) {
                            /*
                             * This get-request should also return an error.
                             */
                            t.ok(err4 !== null, 'err4 !== null');
                            t.done();
                        });
                    } else {
                        mod_rule.get(t, {uuid: rule.uuid},
                            function (err4, res4) {
                            /*
                             * This get-request should not return an error.
                             */
                            t.ok(err4 === null, 'err4 === null');
                            t.done();
                        });
                    }
                });
             });
    };

    mod_rule.create(t, {rule: rule_raw}, rule_create_cb);

    return (t);
};

exports.singularFrom = function (t)
{
    var rule_raw = {
        description: 'Singular FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM VM %s TO %s ALLOW tcp PORT 22',
                 VMS[0].uuid, all_vm_list(4))
    };
    t = singularCommon(t, rule_raw, 1);
    return (t);
};

exports.singularTo = function (t)
{
    var rule_raw = {
        description: 'Singular TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO VM %s ALLOW tcp PORT 22',
                all_vm_list(4), VMS[0].uuid)
    };
    t = singularCommon(t, rule_raw, 1);
    return (t);
};

exports.singularFromAny = function (t) {
    var rule_raw = {
        description: 'Singular FROM Any',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO VM %s ALLOW tcp PORT 22',
                'any', VMS[0].uuid)
    };
    t = singularCommon(t, rule_raw, 1);
    return (t);
};

exports.singularToAny = function (t) {
    var rule_raw = {
        description: 'Singular TO Any',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM VM %s TO %s ALLOW tcp PORT 22',
                VMS[0].uuid, 'any')
    };
    t = singularCommon(t, rule_raw, 1);
    return (t);
};

exports.singularFromAnyToAll = function (t) {
    var rule_raw = {
        description: 'Singular FROM Any TO All',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                'any', 'all vms')
    };
    t = singularCommon(t, rule_raw, 0);
    return (t);
};

exports.singularFromAll = function (t) {
    var rule_raw = {
        description: 'Singular FROM All',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO VM %s ALLOW tcp PORT 22',
                'all vms', VMS[0].uuid)
    };
    t = singularCommon(t, rule_raw, 1);
    return (t);
};

exports.singularToAll = function (t) {
    var rule_raw = {
        description: 'Singular To All',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM VM %s TO %s ALLOW tcp PORT 22',
                VMS[0].uuid, 'all vms')
    };
    t = singularCommon(t, rule_raw, 1);
    return (t);
};

exports.singularFromAllToAny = function (t) {
    var rule_raw = {
        description: 'Singular FROM All TO Any',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                'all vms', 'any')
    };
    t = singularCommon(t, rule_raw, 0);
    return (t);
};

exports.singularFromTag = function (t) {
    var rule_raw = {
        description: 'Singular FROM Tag',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO VM %s ALLOW tcp PORT 22',
                'tag mytag', VMS[0].uuid)
    };
    t = singularCommon(t, rule_raw, 0);
    return (t);
};

exports.singularToTag = function (t) {
    var rule_raw = {
        description: 'Singular TO Tag',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM VM %s TO %s ALLOW tcp PORT 22',
                VMS[0].uuid, 'tag mytag')
    };
    t = singularCommon(t, rule_raw, 0);
    return (t);
};

var pluralCaseCommon = function (t, rule1raw, targ_uuid, deletable)
{
    var expErr = {
        code: 'ResourceNotFound',
        message: 'Rule not found'
    };

    var created_rule;

    var rule_get_cb = function (err, res) {
        t.done();
    };


    var rule_create_cb = function (err, res) {
        t.ok(err === null, 'Should not err when creating rule.');
        if (err) {
            t.done();
            return;
        }

        created_rule = res;

        var delete_vm_rules_opts;
        if (deletable) {
            delete_vm_rules_opts = {uuid: created_rule.uuid, expErr: expErr,
                expCode: 404};
        } else {
            delete_vm_rules_opts = {uuid: created_rule.uuid};
        }
        var delete_vm_rules_cb = function (err2, res2) {
            mod_rule.get(t, delete_vm_rules_opts, rule_get_cb);
        };

        /*
         * Delete VM rules, and check if the rule is gone or not.
         */
        mod_rule.deleteVMrules(t, {
            uuid: targ_uuid,
            params: {
                owner_uuid: OWNERS[0]
            },
            expCode: 204}, delete_vm_rules_cb);
    };

    var client = mod_client.get('vmapi');
    client.getVm({ uuid: VMS[8].uuid }, function (err2, vm) {
        if (err2) {
            return;
        }
        if (vm.state != 'destroyed') {
            return;
        }
        mod_rule.create(t, {rule: rule1raw}, rule_create_cb);
    });
};

exports.pluralToNotDeletable = function (t)
{

    var rule1raw = {
        description: 'Plural TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                all_vm_list(4), two_vm_list(0, 1))
    };
    pluralCaseCommon(t, rule1raw, VMS[0].uuid, 0);
};

exports.pluralToDeletable = function (t)
{

    var rule1raw = {
        description: 'Plural TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                all_vm_list(4), two_vm_list(0, 8))
    };
    pluralCaseCommon(t, rule1raw, VMS[0].uuid, 1);
};

exports.pluralFromNotDeletable = function (t)
{

    var rule1raw = {
        description: 'Plural FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(2, 3), all_vm_list(4))
    };
    pluralCaseCommon(t, rule1raw, VMS[2].uuid, 0);
};

exports.pluralFromDeletable = function (t)
{

    var rule1raw = {
        description: 'Plural FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(2, 8), all_vm_list(4))
    };
    pluralCaseCommon(t, rule1raw, VMS[2].uuid, 1);
};

/*
 * We try this on a rule where the VM-lists are the same length (2). Target is
 * in FROM.
 */
exports.smallPluralFromNotDeletable = function (t)
{
    var rule1raw = {
        description: 'Small Plural FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(4, 5), two_vm_list(6, 7))
    };

    pluralCaseCommon(t, rule1raw, VMS[4].uuid, 0);
};

exports.smallPluralFromDeletable = function (t)
{
    var rule1raw = {
        description: 'Small Plural FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(4, 8), two_vm_list(6, 7))
    };

    pluralCaseCommon(t, rule1raw, VMS[4].uuid, 1);
};

/*
 * We try this on a rule where the VM-lists are the same length (2). Target is
 * in TO.
 */
exports.smallPluralToNotDeletable = function (t)
{
    var rule1raw = {
        description: 'Small Plural TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(4, 5), two_vm_list(6, 7))
    };

    pluralCaseCommon(t, rule1raw, VMS[6].uuid, 0);
};

exports.smallPluralToDeletable = function (t)
{
    var rule1raw = {
        description: 'Small Plural TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(4, 5), two_vm_list(6, 8))
    };

    pluralCaseCommon(t, rule1raw, VMS[6].uuid, 1);
};

/*
 * We want to destroy any remaining VMs.
 */
exports.teardown = function (t)
{
    mod_vm.delAllCreated(t, function (err, res) {
        if (err) {
            t.ok(err === null, 'Should not have errors when destroying VMs.');
            t.done();
            return;
        }
        t.done();
    });
};

module.exports = {
    setup: exports.setup,

    sleep: exports.sleep,

    singularFrom: exports.singularFrom,
    singularTo: exports.singularTo,
    singularFromAny: exports.singularFromAny,
    singularToAny: exports.singularToAny,
    singularFromAnyToAll: exports.singularFromAnyToAll,
    singularFromAll: exports.singularFromAll,
    singularToAll: exports.singularToAll,
    singularFromAllToAny: exports.singularFromAllToAny,
    singularFromTag: exports.singularFromTag,
    singularToTag: exports.singularToTag,

    pluralToNotDeletable: exports.pluralToNotDeletable,
    pluralFromNotDeletable: exports.pluralFromNotDeletable,
    smallPluralToNotDeletable: exports.smallPluralToNotDeletable,
    smallPluralFromNotDeletable: exports.smallPluralFromNotDeletable,

    pluralToDeletable: exports.pluralToDeletable,
    pluralFromDeletable: exports.pluralFromDeletable,
    smallPluralToDeletable: exports.smallPluralToDeletable,
    smallPluralFromDeletable: exports.smallPluralFromDeletable,

    teardown: exports.teardown
};
