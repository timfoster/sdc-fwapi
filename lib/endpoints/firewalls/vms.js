/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.
 */

/*
 * Restify handlers for listing and deleting rules applied to vms
 */

var mod_err = require('../../errors');
var mod_persist = require('../../persist');
var restify = require('restify');
var util = require('util');
var validators = require('fwrule/lib/validators');

var Rule = require('../../rule.js').Rule;
var mod_vasync = require('vasync');

var VError = require('verror').VError;



// --- Internal helpers



/**
 * restify 'before' handler for validating request parameters
 * for getVMrules below
 */
function validateParams(req, res, next) {
    if (!validators.validateUUID(req.params.uuid)) {
        return next(new mod_err.InvalidParamsError(mod_err.INVALID_MSG,
            [ mod_err.invalidParam('uuid', 'Invalid UUID') ]));
    }

    if (req.params.hasOwnProperty('owner_uuid') &&
            !validators.validateUUID(req.params.owner_uuid)) {
        return next(new mod_err.InvalidParamsError(mod_err.INVALID_MSG,
            [ mod_err.invalidParam('owner_uuid', 'Invalid UUID') ]));
    }

    return next();
}



// --- Restify handlers



/**
 * GET /firewalls/vms/:uuid
 */
function getVMrules(req, res, next) {
    req._vmapi.getVm(req.params, function (err, vm) {
        if (err) {
            return next(err);
        }
        var filter = {
            owner_uuid: vm.owner_uuid,
            tags: vm.tags,
            vms: [ vm.uuid ]
        };

        req.log.debug(filter, 'filtering UFDS rules');
        mod_persist.vmRules(req._app, req.log, filter,
            function (err2, rules) {
            if (err2) {
                return next(err2);
            }

            res.send(200, rules.map(function (r) {
                return r.serialize();
            }));

            return next();
        });
    });
}

function VMExistsError(vm) {
    VError.apply(this, Array.prototype.slice.call(arguments, 1));
    this.vm = vm;
}

/*
 * This merely checks that `vm` does not exist. See `nextVmWrap()` for
 * details on why we pass that instead of `nextVmCb` to `getVm`.
 */
function checkVMExists(targ, req, vm_uuid, nextVmCb)
{
    req._vmapi.getVm({uuid: vm_uuid}, function nextVmWrap(err, vm) {
        if (err) {
            if (err.statusCode == 404) {
                nextVmCb(null);
                return;
            } else {
                nextVmCb(err);
                return;
            }
        }

        if (vm.uuid == targ || vm.state == 'destroyed') {
            nextVmCb(null);
            return;
        } else {
            nextVmCb(new VMExistsError(vm));
            return;
        }
    });
}

/*
 * This function is called as part of the pipeline that processes the tuple of
 * VM-arrays. It merely initiates a sub-pipeline that processes an array of
 * VMs. We don't call `nextVmArr` from this function. We would not have all
 * the information we need to advance the vm_tuple pipeline. So we call it from
 * within the nextVm callback.
 */
function verifyVmsNonExistent(targ, req, rule, vm_list, nextVmArrCb)
{
    mod_vasync.forEachPipeline({
        'func': checkVMExists.bind(null, targ, req),
        'inputs': vm_list
    }, function nextVm(err, res) {
        if (err) {
            if (err instanceof VMExistsError) {
                if (rule.activeness == 'none_active') {
                    rule.activeness = 'one_active';
                } else if (rule.activeness == 'one_active') {
                    rule.activeness = 'both_active';
                }
                return nextVmArrCb();
            } else {
                return nextVmArrCb(err);
            }
        } else {
            return nextVmArrCb();
        }
    });
}

function isSideActive(side)
{
    if (side.wildcards.length > 0 || side.ips.length > 0 ||
        side.subnets.length > 0) {

        return (true);
    }
    return (false);
}

/*
 * Check if rule is fully or partially active as a result of referring to
 * non-VM entities.
 */
function ruleActiveness(rule, nextRuleCb)
{
    if (rule.tags.length > 0) {
        return nextRuleCb();
    }
    if (isSideActive(rule.from) && isSideActive(rule.to)) {
        return nextRuleCb();
    } else if (isSideActive(rule.from) || isSideActive(rule.to)) {
        rule.activeness = 'one_active';
    } else {
        rule.activeness = 'none_active';
    }
}

/*
 * If vm.uuid is singular source/destination in this rule,
 * delete the rule. Otherwise, if either of the
 * source/destination lists contain ONLY VMs that have been
 * deleted, we delete the rule. For all other scenarios we do
 * nothing.
 */
function maybeDeleteRule(targ, req, rule, nextRuleCb)
{

    var bail = false;
    ruleActiveness(rule, function () {
        bail = true;
        return nextRuleCb();
    });

    if (bail) {
        return;
    }

    /*
     * Vasync interprets `rules.*.vms` as an object instead of an array,
     * causing problems. Using slice() to alias `rule.*.vms` to `*_vms`
     * unconfuses vasync.
     */
    var vms_tuple = [];
    var to_vms = rule.to.vms.slice(0);
    var from_vms = rule.from.vms.slice(0);


    /*
     * We store the vm lists in a list of their own, so that we can use vasync
     * to walk them one at a time. If a list is empty, it implies that we have
     * a wildcard on that side (wildcards and vms cannot be mixed). We don't
     * push empty lists to the tuple. This implicitly handles the presence of
     * wildcards.
     */
    if (to_vms.length > 0) {
        vms_tuple.push(to_vms);
    }

    if (from_vms.length > 0) {
        vms_tuple.push(from_vms);
    }

    if (vms_tuple.length < 1) {
        return nextRuleCb();
    }

    mod_vasync.forEachPipeline({
        'func': verifyVmsNonExistent.bind(null, targ, req, rule),
        'inputs': vms_tuple
    }, function nextVmArr(err, res) {

        if (err) {
            return nextRuleCb(err);
        }

        if (rule.activeness == 'both_active') {
            return nextRuleCb();
        }

        var deleteCb = function (err2, res2) {
            if (err2 && err2.statusCode != 404) {
                return nextRuleCb(err2);
            }

            return nextRuleCb();
        };

        /*
         * We've looked up all of the VMs, so we can go ahead and delete the
         * rule.
         */
        mod_persist.deleteRule(req._app, req.log, rule.uuid, deleteCb);
    });
}

/*
 * DELETE /firewalls/vms/:uuid
 *
 * Overview
 * --------
 *
 * This endpoint is similar to the above except that it a) deletes rules
 * instead of retrieving them, and b) deletes rules that affect no other VM
 * than the one referenced by :uuid.
 *
 * If :uuid is the singular source or singular destination, we simply delete
 * the rule. If :uuid is a member of a list, we check whether any of the VMs in
 * that list still exist. If so, we do nothing. If they have all been
 * destroyed, we delete the rule.
 *
 * There is another way to implement this. If :uuid is not the singular
 * source/destination, one can simply update the rule to no longer include
 * :uuid in it. If the VMs in that rule keep getting destroyed, then over time
 * the rule will contain a VM that is a singular source/destination and it will
 * be destroyed when that last VM is destroyed. This method generates fewer
 * remote API calls than the former (we have to ask VMAPI about every single
 * VM), but the former method appears to be less error prone. At some point, it
 * may be desirable to switch to the latter method.
 */
function deleteVMrules(req, res, next)
{
    req._vmapi.getVm(req.params, function (err, vm) {
        if (err) {
            res.send(503);
            return next();
        }

        var filter = {
            owner_uuid: vm.owner_uuid,
            tags: vm.tags,
            vms: [ vm.uuid ]
        };

        var filterCb = function (err2, rules) {
            if (err2) {
                res.send(503);
                return next();
            }

            /*
             * We want to map over the rules and delete them. We could do this
             * in parallel, however that would make the test suite useless
             * (which assumes we are deleting in sequence).
             */
            mod_vasync.forEachPipeline({
                'func': maybeDeleteRule.bind(null, vm.uuid, req),
                'inputs': rules
            }, function nextRule(err3, obj) {
                if (err3) {
                    res.send(503);
                    next();
                    return;
                }
                res.send(200);
                next();
            });
        };

        mod_persist.vmRules(req._app, req.log, filter, filterCb);
    });
}

// --- Exports



/**
 * Registers endpoints with a restify server
 */
function register(server, before) {
    server.get({ path: '/firewalls/vms/:uuid', name: 'getVMrules' },
        before.concat(validateParams), getVMrules);
    server.del({ path: '/firewalls/vms/:uuid', name: 'deleteVMrules' },
        before.concat(validateParams), deleteVMrules);
}



module.exports = {
    register: register
};
