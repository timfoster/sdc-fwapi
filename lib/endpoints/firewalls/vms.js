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
 * This merely checks that `vm` does not exist. See `next_vm_wrap()` for
 * details on why we pass that instead of `next_vm_cb` to `getVm`.
 */
function checkVMExists(targ, req, vm_uuid, next_vm_cb)
{
    /*
     * The closure we pass here wraps around vasync's own modified copy of
     * next_vm (which is passed via the `next_vm_cb` arg) and swaps the err and
     * vm args' position in the arglist before passing them to next_vm.  It
     * does not pass a VM if it is the target VM (as that would result in an
     * error, which we do not want in that case). The reason we swap the args,
     * is that we don't want vasync to stop processing the list on the first
     * error object it intercepts, but rather on the first VM object it
     * intercepts.
     */
    req._vmapi.getVm({uuid: vm_uuid}, function next_vm_wrap(err, vm) {
        if (err) {
            if (err.statusCode == 404) {
                next_vm_cb(null);
                return;
            } else {
                next_vm_cb(err);
                return;
            }
        }

        if (vm.uuid == targ || vm.state == 'destroyed') {
            next_vm_cb(null);
            return;
        } else {
            next_vm_cb(new VMExistsError(vm));
            return;
        }
    });
}

/*
 * This function is called as part of the pipeline that processes the tuple of
 * VM-arrays. It merely initiates a sub-pipeline that processes an array of
 * VMs. We don't call `next_vm_arr` from this function. We would not have all
 * the information we need to advance the vm_tuple pipeline. So we call it from
 * within the next_vm callback.
 */
function verify_vms_non_existent(targ, req, rule, vm_list, next_vm_arr_cb)
{
    mod_vasync.forEachPipeline({
        'func': checkVMExists.bind(null, targ, req),
        'inputs': vm_list
    }, function next_vm(err, res) {
        if (err) {
            if (err instanceof VMExistsError) {
                if (rule.activeness == 'none_active') {
                    rule.activeness = 'one_active';
                } else if (rule.activeness == 'one_active') {
                    rule.activeness = 'both_active';
                }
                return next_vm_arr_cb();
            } else {
                return next_vm_arr_cb(err);
            }
        } else {
            return next_vm_arr_cb();
        }
    });
}

/*
 * If vm.uuid is singular source/destination in this rule,
 * delete the rule. Otherwise, if either of the
 * source/destination lists contain ONLY VMs that have been
 * deleted, we delete the rule. For all other scenarios we do
 * nothing.
 */
function maybe_delete_rule(targ, req, rule, next_rule_cb)
{
    if (rule.from.wildcards.length > 0 && rule.to.wildcards.length > 0) {
        rule.activeness = 'both_active';
        return next_rule_cb();
    } else if (rule.from.wildcards.length > 0 || rule.to.wildcards.length > 0) {
        rule.activeness = 'one_active';
    } else {
        rule.activeness = 'none_active';
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
     * If the rule contains tags, we ignore it.
     */
    if (rule.tags.length > 0) {
        return next_rule_cb();
    }

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
        return next_rule_cb();
    }

    mod_vasync.forEachPipeline({
        'func': verify_vms_non_existent.bind(null, targ, req, rule),
        'inputs': vms_tuple
    }, function next_vm_arr(err, res) {

        if (err) {
            return next_rule_cb(err);
        }

        if (rule.activeness == 'both_active') {
            return next_rule_cb();
        }

        var ufds_delete_cb = function (err2, res2) {
            if (err2 && err2.statusCode != 404) {
                return next_rule_cb(err2);
            }

            return next_rule_cb();
        };

        /*
         * If we've looked up all of the VMs and have gotten this far, it
         * means we can go ahead and delete the rule. If any VMs existed we
         * would have broken out of the pipeline at the first conditional
         * of this function.
         */
        mod_persist.deleteRule(req._app, req.log, rule.uuid, ufds_delete_cb);
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

        var ufds_filter_cb = function (err2, rules) {
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
                'func': maybe_delete_rule.bind(null, vm.uuid, req),
                'inputs': rules
            }, function next_rule(err3, obj) {
                if (err3) {
                    res.send(503);
                    next();
                    return;
                }
                res.send(200);
                next();
            });
        };

        mod_persist.vmRules(req._app, req.log, filter, ufds_filter_cb);
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
