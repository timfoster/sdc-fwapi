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

/*
 * These are utility functions that halt the vm, vm-tuple, and rule pipelines,
 * respectively. They all call the pipelines' callbacks with a truth error
 * value to induce a halt. However, they check to make sure that the pipeline
 * has not already completed, as a callback on a completed pipeline would cause
 * vasync to error out and the process would abort entirely.
 */
function halt_vm_pipeline(metadata)
{
    if (metadata.vm_list.length > metadata.vm_lookups) {
        metadata.next_vm(true);
    }

}

function halt_vm_tuple_pipeline(metadata)
{
    /*
     * If we can't call next_vm_arr (which would then call next_rule()), we
     * have to call next_rule directly.
     */
    if (metadata.ncalls < 2) {
        metadata.next_vm_arr(true);
    } else {
        metadata.next_rule();
    }
}

function halt_rule_pipeline(metadata)
{
    if (metadata.rules_walked < metadata.nrules) {
        metadata.next_rule(true);
    }
}

/*
 * The function checks if we received a VM (which indicates that a VM exists,
 * and we interpret that as an error). We never receive a VM that has that same
 * UUID as the target VM (:uuid arg to this endpoint), or that is in the
 * destroyed state. This function serves to do one of these things:
 *
 *     - advance the vm-pipeline
 *     - advance the vm-tuple pipeline
 *     - delete the rule and advance the rule pipeline
 *
 * We do the first when we verify that the VM does not exist (i.e. we recv a
 * 404). We do the second when the VM _does_ exist or when we get a non-404
 * error from VMAPI. We do the third when we recv a 404 and we know that we've
 * walked over evey elem in the current vm-arr.
 */
function next_vm(metadata, vm)
{
    var err = metadata.next_vm_wrap_err;
    /*
     * If we receive both a vm and an err, that just means that the execution
     * of the pipeline is being halted. If, we are receiving just a vm, that's
     * an error that results in an advancement of the parent pipeline.
     */
    if (vm && err) {
        return;
    } else if (vm) {
        metadata.next_vm_arr();
        return;
    }


    if (err) {
        /*
         * If VMAPI gives us a non-404 status code, we bail out of the endpoint
         * by inducing a halt to all of our pipelines and returning a 503 at a
         * higher layer.
         */
        if (err.statusCode != 404) {
            metadata.bail = true;
            halt_vm_pipeline(metadata);
            halt_vm_tuple_pipeline(metadata);
            return;
        } else {
            /*
             * When we delete a rule, we want to cause the vm-tuple pipeline to
             * terminate and the rules pipeline to advance. This is done by
             * passing a truthy error value to `next_vm_arr`
             *
             * However, it is also possible that the deletion fails. If the
             * error code we receive is a 404, then it's already been deleted
             * and we advance the the rules pipeline in the aforementioned way.
             * However if the error code is not a 404, we halt the execution
             * of the vm-pipeline and the vm-arr pipeline. By halting the
             * vm-arr pipeline and setting the `bail` boolean to true, we are
             * percolating the error condition to the upper layers and causing
             * the endpoint to return a 503 to the client. The client can then
             * attempt a retry if it so desires.
             *
             * We don't try to induce a halt if the pipeline is already
             * completed, as that would upset vasync.
             */
            var ufds_delete_cb = function (err2, res) {
                if (err2) {
                    if (err2.statusCode != 404) {
                        metadata.bail = true;
                    }
                }
                halt_vm_pipeline(metadata);
                halt_vm_tuple_pipeline(metadata);
                return;
            };

            /*
             * If we've looked up all of the VMs and have gotten this far, it
             * means we can go ahead and delete the rule. If any VMs existed we
             * would have broken out of the pipeline at the first conditional
             * of this function.
             */
            if (metadata.vm_list.length == metadata.vm_lookups &&
                metadata.vm_list.length) {

                ufdsmodel.modelDelete(metadata.req._app, Rule,
                    Rule.dn(metadata.rule.uuid), metadata.req.log,
                        ufds_delete_cb);
            }
        }
    }
}

/*
 * This function wraps around vasync's own modified copy of next_vm (which is
 * passed via the `next_vm_cb` arg) and swaps the err and vm args' position in
 * the arglist before passing them to next_vm. It does not pass a VM if it is
 * the target VM (as that would result in an error, which we do not want in
 * that case). The reason we swap the args, is that we don't want vasync to
 * stop processing the list on the first error object it intercepts, but rather
 * on the first VM object it intercepts.
 */
function next_vm_wrap(metadata, err, vm)
{
    metadata.vm_lookups++;
    metadata.next_vm_wrap_err = err;
    if (vm) {
        if (vm.uuid == metadata.targ || vm.state == 'destroyed') {
            metadata.next_vm_wrap_err = {};
            metadata.next_vm_wrap_err.statusCode = 404;
            metadata.next_vm(null);
        } else {
            metadata.next_vm(vm);
        }
    } else {
        metadata.next_vm(vm);
    }
}

/*
 * This merely checks that `vm` does not exist. See `next_vm_wrap()` for
 * details on why we pass that instead of `next_vm_cb` to `getVm`.
 */
function checkVMExists(metadata, vm, next_vm_cb)
{
    metadata.next_vm = next_vm_cb;
    metadata.req._vmapi.getVm({uuid: vm}, next_vm_wrap.bind(null, metadata));

}

/*
 * This function is called as part of the pipeline that processes the tuple of
 * VM-arrays. It merely initiates a sub-pipeline that processes an array of
 * VMs. We don't call `next_vm_arr` from this function. We would not have all
 * the information we need to advance the vm_tuple pipeline. So we call it from
 * within the next_vm callback.
 */
function verify_vms_non_existent(metadata, vm_list, next_vm_arr_cb)
{
    metadata.ncalls++;
    metadata.vm_list = vm_list;
    metadata.vm_lookups = 0;
    metadata.next_vm_arr = next_vm_arr_cb;
    mod_vasync.forEachPipeline({
        'func': checkVMExists.bind(null, metadata),
        'inputs': vm_list
    }, next_vm.bind(null, metadata));
}

/*
 * The callback we pass to verify_vms_nonexistent. We call it to either advance
 * the vm-arrays pipeline, or to advance the rules pipeline at the layer above.
 * We do the latter only if we get an error, or if we've finished with the
 * tuple (which we know by how many calls we've made to the
 * verify_vms_nonexistent function.
 */
function next_vm_arr(metadata, err, res) {
    /*
     * We need to bail out of this endpoint request, so we halt the rules
     * pipeline.
     */
    if (metadata.bail) {
        halt_rule_pipeline(metadata);
    }
    if (err || metadata.ncalls == 2) {
        metadata.next_rule();
    }
}

/*
 * This function is taken as a callback by maybe_delete_rule. It is usually
 * used to advance the rules-pipeline. However, it is also used to call the
 * endpoint's next() callback when we have walked over all of the rules.
 */
function next_rule(metadata, err, res) {
    /*
     * We only receive this error when we are supposed to bail out of this
     * endpoint (usually due to an error when trying to make a request to UFDS
     * or VMAPI). At this point the rules-pipeline will stop advancing, and we
     * will send a 503 to the client.
     */
    if (err) {
        metadata.res.send(503);
        metadata.endpoint_next();
        return;
    }
    if (metadata.rules_walked == metadata.nrules) {
        metadata.res.send(200);
        metadata.endpoint_next();
    }
}

/*
 * If vm.uuid is singular source/destination in this rule,
 * delete the rule. Otherwise, if either of the
 * source/destination lists contain ONLY VMs that have been
 * deleted, we delete the rule. For all other scenarios we do
 * nothing.
 */
function maybe_delete_rule(metadata, rule, next_rule_cb)
{
    metadata.rule = rule;
    metadata.ncalls = 0;
    metadata.next_rule = next_rule_cb;
    metadata.rules_walked++;

    /*
     * We do this to keep vasync's type checking code happy. Vasync interprets
     * `rules.*.vms` as an object instead of an array. This causes the process
     * to bail out. Using slice() to alias `rule.*.vms` to `*_vms` allows us to
     * pass `*_vms` to the vasync code which it recognizes as an array.
     */
    var to_vms = [];
    var from_vms = [];
    var vms_tuple = [];
    to_vms = rule.to.vms.slice(0);
    from_vms = rule.from.vms.slice(0);
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
        mod_vasync.forEachPipeline({
            'func': verify_vms_non_existent.bind(null, metadata),
            'inputs': vms_tuple
        }, next_vm_arr.bind(null, metadata));
    } else {
        next_rule_cb();
        return;
    }
}

/*
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
 *
 * Vasync Control Flow
 * -------------------
 *
 * We get a list of rules. Each rule has two lists of VMs. We essentially call
 * 3 nested vasync pipelines:
 *
 *      -A rules pipeline
 *      -A vm-array pipieline (remember we have 2 arrays of vms)
 *      -A vm pipeline
 *
 * Each pipeline takes a callback, which either advances the pipeline to the
 * next element in the array it is processing or forces it to stop on error.
 * Both of these things are percolated from the lowest layer to the highest. It
 * is only at the lower layer that we know what to do at the layer immediately
 * above.
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
                return;
            }

            /*
             * We store a bunch of metadata about this request in this object.
             * We pass this between our functions, so that they have more
             * context.
             */
            var metadata = {
                req: req,
                res: res,
                targ: vm.uuid,
                rules_walked: 0,
                nrules: rules.length,
                bail: false,
                endpoint_next: next
            };

            /*
             * We want to map over the rules and delete them. We could do this
             * in parallel, however that would make the test suite useless
             * (which assumes we are deleting in sequence).
             */
            mod_vasync.forEachPipeline({
                'func': maybe_delete_rule.bind(null, metadata),
                'inputs': rules
            }, next_rule.bind(null, metadata));
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
