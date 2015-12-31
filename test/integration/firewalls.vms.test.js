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

var OWNERS = [ config.test.owner_uuid ];

var VMS = [];
var NVM = 8;

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

        t.done();
        return (t);
    });
};



/*
 * So we have $NVM VMs. For the single machine case, we want to take the first
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

exports.singleMachineCase = function (t)
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
                         * `singleMachineCase()` function. It also gets called
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

var multiMachineCaseCommon = function (t, rule1raw, targ_uuid, delVMuuid)
{

    var expErr = {
        code: 'ResourceNotFound',
        message: 'Rule not found'
    };


    var destroy_vm_cb = function (err, res) {
        t.ok(err === null, 'err === null in destroy_vm_cb');
        if (err) {
            t.done();
            return;
        }

        mod_rule.deleteVMrules(t, {
            uuid: targ_uuid,
            params: {
                owner_uuid: OWNERS[0]
            },
            expCode: 204
        }, delete_vm_rules_err_cb);
    };

    var rule_get_cb = function (err, res) {
        /*
         * If the rule still exists, we need to delete a VM. Otherwise we are
         * done.
         */
        if (!err) {
            mod_vm.delOne(t, {uuid: delVMuuid}, destroy_vm_cb);
        } else {
            t.done();
        }
    };

    var created_rule;

    /* This function expects to receive an error when getting rules. */
    var delete_vm_rules_err_cb = function (err, res) {
        mod_rule.get(t, {uuid: created_rule.uuid, expErr: expErr,
            expCode: 404}, rule_get_cb);
    };

    /* This function expects to succeed when getting rules. */
    var delete_vm_rules_cb = function (err, res) {
        mod_rule.get(t, {uuid: created_rule.uuid},
            rule_get_cb);
    };


    var rule_create_cb = function (err, res) {
        t.ok(err === null, 'Should not err when creating rule.');
        if (err) {
            t.done();
            return;
        }

        created_rule = res;

        mod_rule.deleteVMrules(t, {
            uuid: targ_uuid,
            params: {
                owner_uuid: OWNERS[0]
            },
            expCode: 204}, delete_vm_rules_cb);
    };

    mod_rule.create(t, {rule: rule1raw}, rule_create_cb);
};

exports.multiMachineCaseOne = function (t)
{

    var rule1raw = {
        description: 'Plural TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                all_vm_list(4), two_vm_list(0, 1))
    };
    multiMachineCaseCommon(t, rule1raw, VMS[0].uuid, VMS[1].uuid);
};

exports.multiMachineCaseTwo = function (t)
{

    var rule1raw = {
        description: 'Plural FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(2, 3), all_vm_list(4))
    };
    multiMachineCaseCommon(t, rule1raw, VMS[2].uuid, VMS[3].uuid);
};

/*
 * We try this on a rule where the VM-lists are the same length (2). Target is
 * in FROM.
 */
exports.multiMachineCaseThree = function (t)
{
    var rule1raw = {
        description: 'Small Plural FROM',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(4, 5), two_vm_list(6, 7))
    };

    multiMachineCaseCommon(t, rule1raw, VMS[4].uuid, VMS[5].uuid);
};

/*
 * We try this on a rule where the VM-lists are the same length (2). Target is
 * in TO.
 */
exports.multiMachineCaseFour = function (t)
{
    var rule1raw = {
        description: 'Small Plural TO',
        enabled: true,
        owner_uuid: OWNERS[0],
        rule: util.format(
                'FROM %s TO %s ALLOW tcp PORT 22',
                two_vm_list(4, 5), two_vm_list(6, 7))
    };

    multiMachineCaseCommon(t, rule1raw, VMS[6].uuid, VMS[7].uuid);
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
    singleMachineCase: exports.singleMachineCase,
    multiMachineCaseTwo: exports.multiMachineCaseTwo,
    multiMachineCaseOne: exports.multiMachineCaseOne,
    multiMachineCaseThree: exports.multiMachineCaseThree,
    multiMachineCaseFour: exports.multiMachineCaseFour,
    teardown: exports.teardown
};