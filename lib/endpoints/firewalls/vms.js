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
function verifyVmsNonExistent(targ, req, vm_list, cb)
{
    mod_vasync.forEachPipeline({
        'func': checkVMExists.bind(null, targ, req),
        'inputs': vm_list
    }, function nextVmCb(err, res) {
        if (err) {
            if (err instanceof VMExistsError) {
                return cb(null, true);
            } else {
                return cb(err);
            }
        } else {
            /* We only call the `cb` if we've finished all elements */
            if (res.ndone == vm_list.length) {
                return cb(null, false);
            }
        }
    });
}

function sideActive(side, cb)
{
    if (side.wildcards.length > 0 || side.ips.length > 0 ||
        side.subnets.length > 0) {

        return cb(true);
    }
    return cb(false);
}

function vmSideActive(targ, req, side, cb)
{
    if (side.vms.length === 0) {
        return cb(null, false);
    }
    verifyVmsNonExistent(targ, req, side.vms, cb);
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
    if (rule.tags.length > 0) {
        return nextRuleCb();
    }
    function ruleTryDelete(err2, active2) {
        if (active2) {
            return nextRuleCb();
        }
        if (err2) {
            return nextRuleCb(err2);
        }
        var deleteCb = function (err3, res3) {
            if (err3 && err3.statusCode != 404) {
                return nextRuleCb(err3);
            }

            return nextRuleCb();
        };

        mod_persist.deleteRule(req._app, req.log, rule.uuid, deleteCb);
    }

    sideActive(rule.from, function isFromActive(active) {
        if (active) {
            sideActive(rule.to, function isToActiveToo(active2) {
                /* both sides are active */
                if (active2) {
                    return nextRuleCb();
                }
                /*
                 * Only the `from` side is active, so we go ahead check the
                 * existence of the VMs in `to`.
                 */
                vmSideActive(targ, req, rule.to, ruleTryDelete);
            });
        } else {
            sideActive(rule.to, function isToActive(active2) {

                /*
                 * Only the `to` side is active, so we go ahead check the
                 * existence of the VMs in `from`.
                 */
                if (active2) {
                    vmSideActive(targ, req, rule.from, ruleTryDelete);
                    return;
                }
                /*
                 * No sides are active so we check the VMs on both sides.
                 */
                vmSideActive(targ, req, rule.to,

                    function isToVmActive(err, active3) {

                    if (err) {
                        return nextRuleCb(err);
                    }
                    if (active3) {
                        vmSideActive(targ, req, rule.from, ruleTryDelete);
                        return;
                    }
                    ruleTryDelete(null, false);
                });
            });
        }
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
