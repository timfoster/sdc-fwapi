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

var ufdsmodel = require('../../ufds/model');
var Rule = require('../../rule.js').Rule;
var mod_vasync = require('vasync');



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


/**
 * DELETE /firewalls/vms/:uuid
 *
 * Overview
 * --------
 *
 * This endpoint is similar to the above except that it a) deletes rules
 * instead of retrieving the, and b) deletes rules that affect no other VM than
 * the one referenced by :uuid.
 *
 * If :uuid is the singular source or singular destination, we simply delete
 * the rule. If :uuid is a member of a list, we check whether any of the VMs in
 * that list still exist. If so, we do nothing. If they have all been
 * destroyed, we delete the rule.
 *
 * There is another way to implement this. If :uuid is not the singular
 * source/destination, one can simply update the rule to no longer inlcude
 * :uuid in it. If the VMs in that rule keep getting destroyed, then over time
 * the rule will contain a VM that is a singular source/desitnation and it will
 * be destroyed when that last VM is destroyed. This method generates less IO
 * than the former (we have to ask VMAPI about every single VM), but the former
 * method appears to be less error prone.
 *
 * Implementation Details
 * ----------------------
 *
 * The code below may be difficult to follow, but the flow is as follows:
 *
 * We check the that the VM exists using `req._vmapi.getVm()`, which takes a
 * callback. This callback is the workhorse that takes care of rule deletion in
 * the event that the VM actually exists.
 *
 * If the VM exists, we call `common.filterUFDSrules()`, which takes
 * `ufds_filter_cb` as a callback. That function acts on the array of rules
 * that might be returned by `filterUFDSrules()`. If no rules are returned, it
 * bails. If there are rules, it maps over them and does the machine checks for
 * plural rules. To this end it uses `walk_vms()` which sequentially checks for
 * the existence of the VMs. If `walk_vms()` indicates that no existing
 * machines would be effected, `ufds_filter_cb` invokes `ufds.modelDelete()`
 * and passes `ufds_delete_cb()` to it, which merely does some error handling.
 *
 * There is one case in which `walk_vms()` gets more complicated. If we have a
 * plural source _and_ destination that _both_ contain the target VM (:uuid),
 * we have to check _both_ of those lists for any existing VMs. As long as 1 of
 * the lists contains no existing VMs, we can safely delete the rule.
 *
 * An alternative implementation using VASYNC may be more desirable than what's
 * here. Suggestions welcome.
 */
function deleteVMrules(req, res, next) {

    req._vmapi.getVm(req.params, function (err, vm) {
        if (err) {
            return next(err);
        }
        var filter = {
            owner_uuid: vm.owner_uuid,
            tags: vm.tags,
            vms: [ vm.uuid ]
        };

        /* This is the callback we pass to ufdsmodel.modelDelete below. */
        var ufds_delete_cb = function (is_last_rule, err3, res2) {
            if (err3) {
                return next(err3);
            }
            if (is_last_rule) {
                res.send(204);
                return next();
            }
        };

        /*
         * This variable should be false before we begin walking any lists.
         * Only if the machine in the list exists, will it be set to true by
         * walk_vms(). Unless the machine that exists is the target (we don't
         * care if it exists or not).
         */
        var any_vm_exists = false;

        /*
         * This function is recursive. It uses `vmapi.getVm()` to determine if
         * the machine exists. It passes a version of itself as a callback to
         * `vmapi.getVm()` -- with some extra arguments prepended using
         * `bind()`. This way, we gaurantee that the queries happen in
         * sequence, one after another. Once we pass the last element in the
         * list of VMs (vmls), we check the `any_vm_exists` var above and
         * either delete the rule or do nothing.
         *
         * The first call to this function is always outside of `getVm()`. When
         * called this way, it accepts an index of -1. This is done to
         * kick-start the recursion.
         */
        var walk_vms = function (vm_uuid, rules, r, vmls, vmls2, index, err2,
            response) {

            /*
             * We've passed the end of a VM list. Now that we've walked the
             * entire list we can decide which action to take.  If
             * any_vm_exists is true, we're done and we bail. If, on the other
             * hand, it's false, we delete the rule and bail.
             */
            if (index == vmls.length) {
                if (any_vm_exists) {
                    return next();
                }
                var is_last_rule = (rules[(rules.length - 1)] == r);
                ufdsmodel.modelDelete(req._app, Rule,
                    Rule.dn(r.uuid), req.log,
                        ufds_delete_cb.bind(null, is_last_rule));
                return next();
            }
            /*
             * If the index is less than zero, this is the first invocation of
             * walk_vms on this list.
             */
            var uuid_arg;
            if (index < 0) {
                index++;
                uuid_arg = vmls[index];
                req._vmapi.getVm({uuid: uuid_arg},
                        walk_vms.bind(null, vm_uuid, rules, r, vmls, vmls2,
                            index));
                return;
            }
            /*
             * If we have an error, we know that the VM does not exist. So we
             * call this function on the next VM in the list. If we have no
             * error we know that the VM exists. If the VM in question is the
             * target itself, we ignore it and treat it as if we have the
             * error. If it's not the target we have to make other
             * considerations. If we are only walking over a single list, we
             * set any_vm_exists to true and are done. If we have a secondary
             * list, we leave it false and call ourselves on _that_ list
             * instead.
             */
            if (err2 || vmls[index] == vm_uuid ||
                response.state == 'destroyed') {

                index++;
                /* can't pass undefined uuid arg */
                if (index == vmls.length) {
                    uuid_arg = vmls[(index - 1)];
                } else {
                    uuid_arg = vmls[index];
                }
                req._vmapi.getVm({uuid: uuid_arg},
                        walk_vms.bind(null, vm_uuid, rules, r, vmls, vmls2,
                            index));
            } else {
                if (vmls2 === null) {
                    /* we can ignore our target VM's existence */
                    any_vm_exists = true;
                    res.send(204);
                } else {
                    req._vmapi.getVm({uuid: vmls2[0]},
                       walk_vms.bind(null, vm_uuid, rules, r, vmls2, null, 0));
                }
            }
        };

        var ufds_filter_cb = function (err2, rules) {
            if (err2) {
                return next(err2);
            }

            /*
             * We want to map over the rules and delete them.
             */
            rules.map(function (r) {
                /*
                 * If vm.uuid is singular source/destination in this rule,
                 * delete the rule. Otherwise, if either of the
                 * source/destination lists contain ONLY VMs that have been
                 * deleted, we delete the rule. For all other scenarios we do
                 * nothing.
                 */
                var rule = r;
                var to_vms = rule.to.vms;
                var from_vms = rule.from.vms;
                /* Initialize an err object, to get walk_vms started */
                var init_err = {message: 'This is an error stub'};
                if (from_vms.indexOf(vm.uuid) > -1) {
                    if (to_vms.indexOf(vm.uuid) > -1) {
                        walk_vms(vm.uuid, rules, r, from_vms, to_vms, -1,
                            init_err, null);
                    } else {
                        walk_vms(vm.uuid, rules, r, from_vms, null, -1,
                                init_err, null);
                    }
                } else if (to_vms.indexOf(vm.uuid) > -1) {
                    walk_vms(vm.uuid, rules, r, to_vms, null, -1, init_err,
                            null);
                }
            });
        };

        common.filterUFDSrules(filter, req._app, req.log,
            ufds_filter_cb);
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
