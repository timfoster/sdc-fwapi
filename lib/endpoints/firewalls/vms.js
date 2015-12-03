/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Restify handlers for listing and deleting rules applied to vms
 */

var common = require('../common');
var mod_err = require('../../errors');
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

        common.filterUFDSrules(filter, req._app, req.log,
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


/*
 * The function checks if we recieved a VM (which indicates that a VM exists,
 * and we interpret that as an error). We never recieve a VM that has that same
 * UUID as the target VM (:uuid arg to this endpoint), or that is in the
 * destroyed state.
 */
function check_cb(metadata, vm)
{
    var err = metadata.check_err;
    if (vm) {
        metadata.next_vm_arr(false, false);
        return;
    }


    if (err) {
        if (err.statusCode != 404) {
            metadata.next_vm_arr(false, false);
            return;
        } else {
            var ufds_delete_cb = function (err2, res) {
                metadata.rule_deleted = true;
                if (err2) {
                    metadata.res.send(204);
                    return metadata.next(err2);
                }
                metadata.next_vm_arr(false, false);
                return;
            };

            /*
             * If we've looked up all of the VMs and have gotten this far, it
             * means we can go ahead and delete the rule. If any VMs existed we
             * would have broken out of the pipeline at the first conditional
             * of this function.
             */
            if (metadata.vms.length == metadata.vm_lookups &&
                metadata.vms.length) {

                ufdsmodel.modelDelete(metadata.req._app, Rule,
                    Rule.dn(metadata.rule.uuid), metadata.req.log,
                        ufds_delete_cb);
            }
        }
    }
}

/*
 * This function wraps around vasync's own modified copy of check_cb (which is
 * passed via the `cb` arg) and swaps the err and vm args' position in the
 * arglist before passing them to check_cb. It does not pass a VM if it is the
 * target VM (as that would result in an error, which we do not want in that
 * case). The reason we swap the args, is that we don't want vasync to stop
 * processing the list on the first error object it intercepts, but rather on
 * the first VM object it intercepts.
 */
function check_cb_wrap(metadata, err, vm)
{
    metadata.vm_lookups++;
    metadata.check_err = err;
    if (vm) {
        if (vm.uuid == metadata.targ || vm.state == 'destroyed') {
            metadata.check_err = {};
            metadata.check_err.statusCode = 404;
            metadata.next_vm(null);
        } else {
            metadata.next_vm(vm);
        }
    } else {
            metadata.next_vm(vm);
    }
}

function checkVMExists(metadata, vm, cb)
{
    metadata.next_vm = cb;
    metadata.req._vmapi.getVm({uuid: vm}, check_cb_wrap.bind(null, metadata));

}

function verify_vms_non_existent(metadata, vms, next_vm_arr)
{
    /*
     * We've either walked both tuples or have deleted the rule. So we advance
     * the rules-callback at the top-level pipeline.
     */
    if (vms.length === 0 || metadata.rule_deleted) {
        next_vm_arr(false, false);
        return;
    }
    metadata.vms = vms;
    metadata.vm_lookups = 0;
    metadata.next_vm_arr = next_vm_arr;
    mod_vasync.forEachPipeline({
        'func': checkVMExists.bind(null, metadata),
        'inputs': vms
    }, check_cb.bind(null, metadata));
}

/*
 * If vm.uuid is singular source/destination in this rule,
 * delete the rule. Otherwise, if either of the
 * source/destination lists contain ONLY VMs that have been
 * deleted, we delete the rule. For all other scenarios we do
 * nothing.
 */
function maybe_delete_rule(metadata, rule, next_rule)
{
    /*
     * We've reached the end of the rules list and we respond to the client.
     */
    if (rule === null) {
        metadata.res.send(204);
        return (metadata.next());
    }
    metadata.rule = rule;

    var to_vms = [];
    var from_vms = [];
    var vms_tuple = [];
    to_vms = to_vms.concat(rule.to.vms);
    from_vms = from_vms.concat(rule.from.vms);
    /*
     * We store the vm lists in list of their own, so that we can use vasync to
     * walk them one at a time.
     */
    if (to_vms.length > 0) {
        vms_tuple.push(to_vms);
    }
    if (from_vms.length > 0) {
        vms_tuple.push(from_vms);
    }
    /*
     * We don't operate on rules that consist entirely of wildcards.
     */
    if (vms_tuple.length > 0) {
        /* termination so that we know when we've walked all vms */
        vms_tuple.push([]);
        mod_vasync.forEachPipeline({
            'func': verify_vms_non_existent.bind(null, metadata),
            'inputs': vms_tuple
        }, function (err, res) {
            /*
             * We call this function when we want to advance the pipeline. We
             * should _never_ pass an error to this function. This function
             * calls `cb`, to advance the pipline at the level above.
             */
            next_rule(false, true);
            return;
        });
    } else {
        next_rule(null, null);
        return;
    }
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
 * be destroyed when that last VM is destroyed. This method generates fewer
 * remote API calls than the former (we have to ask VMAPI about every single
 * VM), but the former method appears to be less error prone. At some point, it
 * may be desirable to switch to the latter method.
 */
function deleteVMrules(req, res, next)
{

    req._vmapi.getVm(req.params, function (err, vm) {
        if (err) {
            return next(err);
        }
        var filter = {
            owner_uuid: vm.owner_uuid,
            tags: vm.tags,
            vms: [ vm.uuid ]
        };


        var ufds_filter_cb = function (err2, rules) {
            if (err2) {
                return next(err2);
            }

            /*
             * We make the rules array null-terminated, so that
             * maybe_delete_rule()'s callback know when the last rule has been
             * acted upon.
             */
            rules.push(null);
            /*
             * We store a bunch of metadata about this request in this object.
             * We pass this between our functions, so that they have more
             * context.
             */
            var metadata = {};
            metadata.req = req;
            metadata.res = res;
            metadata.next = next;
            metadata.targ = vm.uuid;
            metadata.rule_deleted = false;

            /*
             * We want to map over the rules and delete them. We could do this
             * in parallel, however that would make the test suite useless
             * (which assumes we are deleting in sequence).
             */
            mod_vasync.forEachPipeline({
                'func': maybe_delete_rule.bind(null, metadata),
                'inputs': rules
            }, function (err3, results) {
                return;
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
