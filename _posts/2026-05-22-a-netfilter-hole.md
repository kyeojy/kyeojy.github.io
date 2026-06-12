---
layout: post
title: "A Netfilter hole"
date: 2026-05-22 17:27:00 +0800
categories: vulnerability exploitation
tags: linux kernel uaf
---

This post explores the root cause and exploitation of CVE-2022-32250, a vulnerability I used for a successful demonstration at Pwn2Own Vancouver 2022, and also the first vulnerability I discovered. The issue was used to achieve local privilege escalation on `Ubuntu 22.04 kernel 5.15.0-30-release`. 

It turns out that around the time of the competition, there was a separate disclosure from NCC Group to the kernel maintainer for the same issue, and ultimately they were given credit for CVE-2022-32250 as they were considered the first ones to report it. Some time after, there were multiple write-ups published on exploitation of the vulnerability (e.g. [here](https://www.nccgroup.com/research/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/) and [here](https://theori.io/blog/linux-kernel-exploit-cve-2022-32250-with-mqueue)), and this post will offer a different method of exploitation, using only objects from netfilter modules. 

# Netlink batch processing
The vulnerability is a use-after-free (UAF) and to better understand the conditions that lead to this UAF, it is helpful to understand how netlink processes batches of messages, as well as how the creation and deletion of objects are handled. When interacting with the `nf_tables` API, we can send multiple batches of netlink messages, where each batch consists of a number of netlink messages. When netlink
messages are processed by the kernel, they eventually reach the function `nfnetlink_rcv_batch`. The batch of netlink messages is then processed one at a time by this function.
The function first retrieves the `nfnetlink_subsystem` responsible for processing the batch and then gets the relevant callback handler to handle each message in the batch. If an entire batch is processed successfully, `ss->commit(...) [1]` is called, which is a function pointer to `nf_tables_commit`. If an error is encountered while processing the batch, it adds the `NFNL_BATCH_FAILURE` flag to the status and instead of calling `ss->commit(...)`, it calls `ss->abort(...) [2]`, which is a function pointer to `nf_tables_abort`.

```c
static void nfnetlink_rcv_batch(struct sk_buff *skb, struct nlmsghdr *nlh,
                                u16 subsys_id, u32 genid)
{
    ...
    ss = nfnl_dereference_protected(subsys_id);
    ...
    while (skb->len >= nlmsg_total_size(0)) {
            int msglen, type;
        ...
        nc = nfnetlink_find_client(type, ss);
                if (!nc) {
                        err = -EINVAL;
                        goto ack;
                }
        ...
        err = nc->call(skb, &info, (const struct nlattr **)cda);
        ...
        if (nlh->nlmsg_flags & NLM_F_ACK || err) {
                /* Errors are delivered once the full batch has been
                    * processed, this avoids that the same error is
                    * reported several times when replaying the batch.
                    */
                if (nfnl_err_add(&err_list, nlh, err, &extack) < 0) {
                        /* We failed to enqueue an error, reset the
                            * list of errors and send OOM to userspace
                            * pointing to the batch header.
                            */
                        nfnl_err_reset(&err_list);
                        netlink_ack(oskb, nlmsg_hdr(oskb), -ENOMEM,
                                    NULL);
                        status |= NFNL_BATCH_FAILURE;
                        goto done;
                }
                /* We don't stop processing the batch on errors, thus,
                    * userspace gets all the errors that the batch
                    * triggers.
                    */
                if (err)
                        status |= NFNL_BATCH_FAILURE;
        }
        ...
    }
done:
    if (status & NFNL_BATCH_REPLAY) {
            ...
    } else if (status == NFNL_BATCH_DONE) {
            err = ss->commit(net, oskb);    <--- [1]
            if (err == -EAGAIN) {
                    status |= NFNL_BATCH_REPLAY;
                    goto done;
            } else if (err) {
                    ss->abort(net, oskb, NFNL_ABORT_NONE);
                    netlink_ack(oskb, nlmsg_hdr(oskb), err, NULL);
            }
    } else {
            enum nfnl_abort_action abort_action;

            if (status & NFNL_BATCH_FAILURE)
                    abort_action = NFNL_ABORT_NONE;
            else
                    abort_action = NFNL_ABORT_VALIDATE;

            err = ss->abort(net, oskb, abort_action);    <--- [2]
            ...
    }
    ...
}
```

The callback handlers that actually process each message of the batch are different `nf_tables` functions and some examples of them are the following.

```c
static const struct nfnl_callback nf_tables_cb[NFT_MSG_MAX] = {
        ...
        [NFT_MSG_NEWSETELEM] = {
                .call           = nf_tables_newsetelem,
                .type           = NFNL_CB_BATCH,
                .attr_count     = NFTA_SET_ELEM_LIST_MAX,
                .policy                 = nft_set_elem_list_policy,
        },
        [NFT_MSG_GETSETELEM] = {
                .call           = nf_tables_getsetelem,
                .type           = NFNL_CB_RCU,
                .attr_count     = NFTA_SET_ELEM_LIST_MAX,
                .policy                 = nft_set_elem_list_policy,
        },
        [NFT_MSG_DELSETELEM] = {
                .call           = nf_tables_delsetelem,
                .type           = NFNL_CB_BATCH,
                .attr_count     = NFTA_SET_ELEM_LIST_MAX,
                .policy                 = nft_set_elem_list_policy,
        },
        [NFT_MSG_NEWOBJ] = {
                .call           = nf_tables_newobj,
                .type           = NFNL_CB_BATCH,
                .attr_count     = NFTA_OBJ_MAX,
                .policy                 = nft_obj_policy,
        },
        [NFT_MSG_GETOBJ] = {
                .call           = nf_tables_getobj,
                .type           = NFNL_CB_RCU,
                .attr_count     = NFTA_OBJ_MAX,
                .policy                 = nft_obj_policy,
        },
        [NFT_MSG_DELOBJ] = {
                .call           = nf_tables_delobj,
                .type           = NFNL_CB_BATCH,
                .attr_count     = NFTA_OBJ_MAX,
                .policy                 = nft_obj_policy,
        },
        ...
};
```

`nf_tables_commit` and `nf_tables_abort` both iterate through the `nft_net->commit_list` and handle each item in the list. `nf_tables_abort` is more relevant for our context so we'll focus on that. Items in the `nft_net->commit_list` are basically transaction objects, which encapsulate the type of update that needs to be done for an `nf_tables` object and a data structure containing the target object. When `nf_tables` objects are being created or destroyed, they are wrapped in a `struct nft_trans` object and added to the `nft_net->commit_list`, eventually being processed together with other `nft_trans` instances at the end of processing a batch. Each `nft_trans` is removed from the list after it is processed.

```c
static int __nf_tables_abort(struct net *net, enum nfnl_abort_action action)
{
        ...
        list_for_each_entry_safe_reverse(trans, next, &nft_net->commit_list,
                                         list) {
                switch (trans->msg_type) {
                case NFT_MSG_NEWSETELEM:
                        if (nft_trans_elem_set_bound(trans)) {
                                nft_trans_destroy(trans);
                                break;
                        }
                        te = (struct nft_trans_elem *)trans->data;
                        nft_setelem_remove(net, te->set, &te->elem);
                        if (!nft_setelem_is_catchall(te->set, &te->elem))
                                atomic_dec(&te->set->nelems);
                        break;
                ...
                case NFT_MSG_NEWOBJ:
                        if (nft_trans_obj_update(trans)) {
                                nft_obj_destroy(&trans->ctx,
                                                nft_trans_obj_newobj(trans));
                                nft_trans_destroy(trans);
                        } else {
                                trans->ctx.table->use--;
                                nft_obj_del(nft_trans_obj(trans));
                        }
                        break;
                ...
                }
        }
        list_for_each_entry_safe_reverse(trans, next,
                                         &nft_net->commit_list, list) {
                list_del(&trans->list);
                nf_tables_abort_release(trans);
        }
         ...
        return 0;
}
```

For instance, when an `nft_object` is created, the creation is handled by the function `nf_tables_newobj`. After the necessary initialization of the object, the object is added to an `nft_trans` [1] and this `nft_trans` is added to an `nft_net->commit_list` [2]. At the same time, the object is added to an `rhltable` for future lookups. During triggering of the vulnerability, `__nf_tables_abort` will be called, which accesses the `nft_net->commit_list`.

```c
static int nf_tables_newobj(struct sk_buff *skb, const struct nfnl_info *info,
                            const struct nlattr * const nla[])
{
        table = nft_table_lookup(net, nla[NFTA_OBJ_TABLE], family, genmask,
                                 NETLINK_CB(skb).portid);
        ...
        obj = nft_obj_init(&ctx, type, nla[NFTA_OBJ_DATA]);
        ...
        obj->key.table = table;
        obj->handle = nf_tables_alloc_handle(table);

        obj->key.name = nla_strdup(nla[NFTA_OBJ_NAME], GFP_KERNEL);
        if (!obj->key.name) {
                err = -ENOMEM;
                goto err_strdup;
        }
        ...
        err = nft_trans_obj_add(&ctx, NFT_MSG_NEWOBJ, obj);    <---
        if (err < 0)
                goto err_trans;
        err = rhltable_insert(&nft_objname_ht, &obj->rhlhead,
                              nft_objname_ht_params);
        ...
        list_add_tail_rcu(&obj->list, &table->objects);
        table->use++;
        return 0;
}

static int nft_trans_obj_add(struct nft_ctx *ctx, int msg_type,
                             struct nft_object *obj)
{
        struct nft_trans *trans;

        trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_obj));
        if (trans == NULL)
                return -ENOMEM;

        if (msg_type == NFT_MSG_NEWOBJ)
                nft_activate_next(ctx->net, obj);

        nft_trans_obj(trans) = obj;    <--- [1]
        nft_trans_commit_list_add_tail(ctx->net, trans);

        return 0;
}

static void nft_trans_commit_list_add_tail(struct net *net, struct nft_trans *trans)
{
        struct nftables_pernet *nft_net = nft_pernet(net);

        list_add_tail(&trans->list, &nft_net->commit_list);    <--- [2]
}
```

# The vulnerability
The actual bug is due to the ordering of [1] and [2] in `nft_set_elem_expr_alloc`. `nft_expr_init` is called regardless of the type of `nf_tables` expression and the check `if (!(expr->ops->type->flags & NFT_EXPR_STATEFUL))` is only performed subsequently. When the check at [2] fails, it goes to the error handling code and returns an error.

```c
struct nft_expr *nft_set_elem_expr_alloc(const struct nft_ctx *ctx,
					 const struct nft_set *set,
					 const struct nlattr *attr)
{
	struct nft_expr *expr;
	int err;

	expr = nft_expr_init(ctx, attr);    <--- [1]
	if (IS_ERR(expr))
		return expr;

	err = -EOPNOTSUPP;
	if (!(expr->ops->type->flags & NFT_EXPR_STATEFUL))    <--- [2]
		goto err_set_elem_expr;

	if (expr->ops->type->flags & NFT_EXPR_GC) {
		if (set->flags & NFT_SET_TIMEOUT)
			goto err_set_elem_expr;
		if (!set->ops->gc_init)
			goto err_set_elem_expr;
		set->ops->gc_init(set);
	}

	return expr;

err_set_elem_expr:
	nft_expr_destroy(ctx, expr);
	return ERR_PTR(err);
}
```
# Triggering the vulnerability
To see how this is a problem that causes a UAF, we can examine what happens when we create certain `nf_tables` entities in a particular order. For example, we can create `nft_table`, `nft_set`, `nft_object`, `nft_set_elem` etc. `nft_set` and `nft_object` must belong to an `nft_table`, and `nft_set_elem` can be created as an element of an `nft_set`. We can also specify expressions and/or a reference to an `nft_object` when creating an `nft_set_elem`. To trigger a UAF, we will need to send two separate batches of messages to netlink. In the first batch, we use messages to create an `nft_table` and an `nft_set`, and in the second batch we create an `nft_object`, followed by an `nft_set_elem` with a reference to the created `nft_object`, and finally an `nft_set_elem` with an `nft_objref_map` expression. Note that the order of operations must be in that sequence.
When creating an `nft_object`, recall that the object is added to an `nft_trans` and this `nft_trans` is added to an `nft_net->commit_list`. Meanwhile, the object is added to an `rhltable` for future lookups. This means that `nft_net->commit_list` will contain one `nft_trans` object upon `nft_object` creation.

The next message in the batch is to create an `nft_set_elem`, and the function `nf_tables_newsetelem` is invoked which calls `nft_add_set_elem` to actually carry out the logic of parsing the message data and creating the elem.

```c
static int nf_tables_newsetelem(struct sk_buff *skb,
                                const struct nfnl_info *info,
                                const struct nlattr * const nla[])
{
        table = nft_table_lookup(net, nla[NFTA_SET_ELEM_LIST_TABLE], family,
                                 genmask, NETLINK_CB(skb).portid);
        ...
        set = nft_set_lookup_global(net, table, nla[NFTA_SET_ELEM_LIST_SET],
                                    nla[NFTA_SET_ELEM_LIST_SET_ID], genmask);
        ...
        nla_for_each_nested(attr, nla[NFTA_SET_ELEM_LIST_ELEMENTS], rem) {
                err = nft_add_set_elem(&ctx, set, attr, info->nlh->nlmsg_flags);
                if (err < 0)
                        return err;
        }
        ...
}
```

`nft_add_set_elem` first parses the netlink message data to prepare an `nft_set_ext_tmpl` which is a template that will be used to initialize the set elem. One step in preparing the template is to check if the message contains a reference to an object that we want the set elem to reference (specified by a netlink attribute `NFTA_SET_ELEM_OBJREF` in the message). If there was such an attribute specified, then it looks up the object with `nft_obj_lookup` [1] which just looks up the object in the `rhltable` containing all objects for that table. It then adds the reference to the `nft_object` to the `nft_set_elem`'s `nft_set_ext` [2]. Finally, the `nft_set_elem` is added to an `nft_trans`, which is ultimately added to the `nft_net->commit_list` [3]. At this point, `nft_net->commit_list` contains two `nft_trans` entries; one for the `nft_object` created earlier and one for the new `nft_set_elem`.

```c
static int nft_add_set_elem(struct nft_ctx *ctx, struct nft_set *set,
                            const struct nlattr *attr, u32 nlmsg_flags)
{
         ...
        if (nla[NFTA_SET_ELEM_EXPR]) {
                struct nft_expr *expr;

                if (set->num_exprs && set->num_exprs != 1)
                        return -EOPNOTSUPP;

                expr = nft_set_elem_expr_alloc(ctx, set,
                                               nla[NFTA_SET_ELEM_EXPR]);
                ...
        }
        ...
        if (nla[NFTA_SET_ELEM_OBJREF] != NULL) {
                if (!(set->flags & NFT_SET_OBJECT)) {
                        err = -EINVAL;
                        goto err_parse_key_end;
                }
                obj = nft_obj_lookup(ctx->net, ctx->table,    <--- [1]
                                     nla[NFTA_SET_ELEM_OBJREF],
                                     set->objtype, genmask);
                ...
                nft_set_ext_add(&tmpl, NFT_SET_EXT_OBJREF);    <--- [2]
        }
        ...
        if (obj) {
                *nft_set_ext_obj(ext) = obj;
                obj->use++;
        }
         ...
        trans = nft_trans_elem_alloc(ctx, NFT_MSG_NEWSETELEM, set);
        if (trans == NULL) {
                err = -ENOMEM;
                goto err_elem_expr;
        }
        ...
        nft_trans_elem(trans) = elem;
        nft_trans_commit_list_add_tail(ctx->net, trans);    <--- [3]
        return 0;
        ...
}
```

The third netlink message in our batch is the message to create a second `nft_set_elem` with an expression in it. To be clear, we don't specify an object for this set elem to reference. In the same code block above, we can see that `nft_set_elem_expr_alloc` (the buggy function) is called when the netlink message contains a netlink attribute for an expression. The function (shown again) initializes the expression with `nft_expr_init` [1] and if the `expr->ops->type->flags` [2] does not contain the `NFT_EXPR_STATEFUL` flag, then the expression is destroyed and an error is returned.

```c
struct nft_expr *nft_set_elem_expr_alloc(const struct nft_ctx *ctx,
                                         const struct nft_set *set,
                                         const struct nlattr *attr)
{
        struct nft_expr *expr;
        int err;

        expr = nft_expr_init(ctx, attr);    <--- [1]
        if (IS_ERR(expr))
                return expr;

        err = -EOPNOTSUPP;
        if (!(expr->ops->type->flags & NFT_EXPR_STATEFUL))   <--- [2]
                goto err_set_elem_expr;

        if (expr->ops->type->flags & NFT_EXPR_GC) {
                if (set->flags & NFT_SET_TIMEOUT)
                        goto err_set_elem_expr;
                if (!set->ops->gc_init)
                        goto err_set_elem_expr;
                set->ops->gc_init(set);
        }

        return expr;

err_set_elem_expr:
        nft_expr_destroy(ctx, expr);
        return ERR_PTR(err);
}
```

Even if the expression we tried to create does not have the `NFT_EXPR_STATEFUL` flag, `nft_expr_init` is still called first. If we created an expression of `nft_objref_type` that has `nft_objref_map_ops`, we can see that it does initialize such a flag.

```c
static const struct nft_expr_ops nft_objref_map_ops = {
        .type           = &nft_objref_type,
        .size           = NFT_EXPR_SIZE(sizeof(struct nft_objref_map)),
        .eval           = nft_objref_map_eval,
        .init           = nft_objref_map_init,
        .activate       = nft_objref_map_activate,
        .deactivate     = nft_objref_map_deactivate,
        .destroy        = nft_objref_map_destroy,
        .dump           = nft_objref_map_dump,
};

static struct nft_expr_type nft_objref_type __read_mostly = {
        .name           = "objref",
        .select_ops     = nft_objref_select_ops,
        .policy         = nft_objref_policy,
        .maxattr        = NFTA_OBJREF_MAX,
        .owner          = THIS_MODULE,
};
```

But when `nft_expr_init` is called, it parses the expression data, allocates space for it and finally calls `nf_tables_newexpr` [1] which just calls the init function of the particular ops for that expression.

```c
static struct nft_expr *nft_expr_init(const struct nft_ctx *ctx,
                                      const struct nlattr *nla)
{
        struct nft_expr_info expr_info;
        struct nft_expr *expr;
        struct module *owner;
        int err;

        err = nf_tables_expr_parse(ctx, nla, &expr_info);
        if (err < 0)
                goto err1;

        err = -ENOMEM;
        expr = kzalloc(expr_info.ops->size, GFP_KERNEL);
        if (expr == NULL)
                goto err2;

        err = nf_tables_newexpr(ctx, &expr_info, expr);    <--- [1]
        if (err < 0)
                goto err3;

        return expr;
        ...
}

static int nf_tables_newexpr(const struct nft_ctx *ctx,
                             const struct nft_expr_info *expr_info,
                             struct nft_expr *expr)
{
        const struct nft_expr_ops *ops = expr_info->ops;
        int err;

        expr->ops = ops;
        if (ops->init) {
                err = ops->init(ctx, expr, (const struct nlattr **)expr_info->tb);
                if (err < 0)
                        goto err1;
        }

        return 0;
err1:
        expr->ops = NULL;
        return err;
}
```

For an `objref_map` expression, it calls `nft_objref_map_init` which looks up the set we are trying to reference using the `objref_map` expression and then calls `nf_tables_bind_set` on that set.

```c
static int nft_objref_map_init(const struct nft_ctx *ctx,
                               const struct nft_expr *expr,
                               const struct nlattr * const tb[])
{
        ...
        set = nft_set_lookup_global(ctx->net, ctx->table,
                                    tb[NFTA_OBJREF_SET_NAME],
                                    tb[NFTA_OBJREF_SET_ID], genmask);
        if (IS_ERR(set))
                return PTR_ERR(set);
        ...
        err = nf_tables_bind_set(ctx, set, &priv->binding);
        if (err < 0)
                return err;

        priv->set = set;
        return 0;
}
```

In `nf_tables_bind_set`, `nft_set_trans_bind` is called which checks that the set has the `NFT_SET_ANONYMOUS` flag set [1] (configurable by the `nf_tables` API user), adds a binding to the set's bindings list [2] and then goes through the `nft_trans` objects currently in the `nft_net->commit_list` [3]. If the `nft_trans` was created when we created a new `nft_set_elem` (indicated by a netlink message of type `NFT_MSG_NEWSETELEM`), it sets the `nft_set_elem` to a bound state [4]. Since the `nft_net->commit_list` at this point already contains that first `nft_set_elem` which holds a reference to the `nft_object` we created, that set elem will be bound.

```c
int nf_tables_bind_set(const struct nft_ctx *ctx, struct nft_set *set,
                       struct nft_set_binding *binding)
{
        ...
        if (!list_empty(&set->bindings) && nft_set_is_anonymous(set))    <--- [1]
                return -EBUSY;
        ...
bind:
        ...
        list_add_tail_rcu(&binding->list, &set->bindings);    <--- [2]
        nft_set_trans_bind(ctx, set);
        set->use++;

        return 0;
}


static void nft_set_trans_bind(const struct nft_ctx *ctx, struct nft_set *set)
{
        struct nftables_pernet *nft_net;
        struct net *net = ctx->net;
        struct nft_trans *trans;

        if (!nft_set_is_anonymous(set))
                return;

        nft_net = nft_pernet(net);
        list_for_each_entry_reverse(trans, &nft_net->commit_list, list) {   <--- [3]
                switch (trans->msg_type) {
                case NFT_MSG_NEWSET:
                        if (nft_trans_set(trans) == set)
                                nft_trans_set_bound(trans) = true;
                        break;
                case NFT_MSG_NEWSETELEM:
                        if (nft_trans_elem_set(trans) == set)
                                nft_trans_elem_set_bound(trans) = true;    <--- [4]
                        break;
                }
        }
}

static inline bool nft_set_is_anonymous(const struct nft_set *set)
{
        return set->flags & NFT_SET_ANONYMOUS;
}

#define nft_trans_elem_set_bound(trans) \
        (((struct nft_trans_elem *)trans->data)->bound)
```

After `nft_expr_init` returns, execution flow is back in `nft_set_elem_expr_alloc` where the function will bail out [1] with an error because the `objref_map` expression we tried to create does not have the `NFT_EXPR_STATEFUL` flag. Even though `nft_expr_destroy` [2] is invoked, it eventually calls `nft_objref_map_destroy->nf_tables_destroy_set` as this is an `objref_map` expression, and does not destroy the set as the set has a binding [3].

```c
struct nft_expr *nft_set_elem_expr_alloc(const struct nft_ctx *ctx,
                                         const struct nft_set *set,
                                         const struct nlattr *attr)
{
        struct nft_expr *expr;
        int err;

        expr = nft_expr_init(ctx, attr);
        if (IS_ERR(expr))
                return expr;

        err = -EOPNOTSUPP;
        if (!(expr->ops->type->flags & NFT_EXPR_STATEFUL))
                goto err_set_elem_expr;    <--- [1]

        if (expr->ops->type->flags & NFT_EXPR_GC) {
                if (set->flags & NFT_SET_TIMEOUT)
                        goto err_set_elem_expr;
                if (!set->ops->gc_init)
                        goto err_set_elem_expr;
                set->ops->gc_init(set);
        }

        return expr;

err_set_elem_expr:
        nft_expr_destroy(ctx, expr);    <--- [2]
        return ERR_PTR(err);
}

void nf_tables_destroy_set(const struct nft_ctx *ctx, struct nft_set *set)
{
	if (list_empty(&set->bindings) && nft_set_is_anonymous(set))   <--- [3]
		nft_set_destroy(ctx, set);
}
```

Ultimately, the failure returns back to `nfnetlink_rcv_batch`, and since processing of the batch failed somewhere along the way, `nf_tables_abort` is called (detailed at the start of this section). `nf_tables_abort` calls `__nf_tables_abort`, which processes every `nft_trans` in the `nft_net->commit_list` in reverse order. At this point there are two `nft_trans` entries: one from creating the new `nft_object`, and one from creating the `nft_set_elem` that references it. The `nft_set_elem` entry is therefore processed first, then the `nft_object` entry. Because the `nft_set_elem` was bound earlier, its `nft_trans` is simply destroyed [1][1A] with no further processing. The `nft_object` is not an existing object being updated, so its handler just decrements the use count of the table the object belongs to and calls `nft_obj_del` [2]. `nft_obj_del` deletes the object from the `rhltable` that it belongs to and deletes the reference to the object from an RCU linked list that it belongs to [2A], but does not free the object. Finally, `nf_tables_abort_release` [3] is called for every `nft_trans` still remaining in the `nft_net->commit_list`. There is only one `nft_trans` remaining in the commit list and this is the one with the `nft_object`.

```c
static int __nf_tables_abort(struct net *net, enum nfnl_abort_action action)
{
        ...
        list_for_each_entry_safe_reverse(trans, next, &nft_net->commit_list,
                                         list) {
                switch (trans->msg_type) {
                case NFT_MSG_NEWSETELEM:
                        if (nft_trans_elem_set_bound(trans)) {
                                nft_trans_destroy(trans);    <--- [1]
                                break;
                        }
                        te = (struct nft_trans_elem *)trans->data;
                        nft_setelem_remove(net, te->set, &te->elem);
                        if (!nft_setelem_is_catchall(te->set, &te->elem))
                                atomic_dec(&te->set->nelems);
                        break;
                ...
                case NFT_MSG_NEWOBJ:
                        if (nft_trans_obj_update(trans)) {
                                nft_obj_destroy(&trans->ctx,
                                                nft_trans_obj_newobj(trans));
                                nft_trans_destroy(trans);
                        } else {
                                trans->ctx.table->use--;    <--- [2]
                                nft_obj_del(nft_trans_obj(trans));
                        }
                        break;
                ...
                }
        }
        list_for_each_entry_safe_reverse(trans, next,
                                         &nft_net->commit_list, list) {
                list_del(&trans->list);
                nf_tables_abort_release(trans);    <--- [3]
        }
         ...
        return 0;
}

static void nft_obj_del(struct nft_object *obj)   <--- [2A]
{
        rhltable_remove(&nft_objname_ht, &obj->rhlhead, nft_objname_ht_params);
        list_del_rcu(&obj->list);
}

static void nft_trans_destroy(struct nft_trans *trans)    <--- [1A]
{
        list_del(&trans->list);
        kfree(trans);
}
```
In `nf_tables_abort_release`, `nft_obj_destroy` is called on the `nft_object` [1] that the `nft_trans` is referencing, which frees the object [2]. However, the `nft_set_elem` holding the pointer to the object's location in memory was not destroyed since the `nft_trans` referencing it was destroyed due to the set elem being bound. This means that there is now a use-after-free condition that we can leverage for further exploitation.

```c
static void nf_tables_abort_release(struct nft_trans *trans)
{
        switch (trans->msg_type) {
        ...
        case NFT_MSG_NEWOBJ:
                nft_obj_destroy(&trans->ctx, nft_trans_obj(trans));     <--- [1]
                break;
        ...
        }
        kfree(trans);
}

#define nft_trans_obj(trans)    \
        (((struct nft_trans_obj *)trans->data)->obj)

static void nft_obj_destroy(const struct nft_ctx *ctx, struct nft_object *obj)
{
        if (obj->ops->destroy)
                obj->ops->destroy(ctx, obj);

        module_put(obj->ops->type->owner);
        kfree(obj->key.name);
        kfree(obj->udata);
        kfree(obj);    <--- [2]
}
```

# Exploitation

This section will detail how the use-after-free can be leveraged to escalate privileges from an unprivileged user to root.

The freed `nft_object` is referenced from an `nft_set_elem` and that means performing leaks on the freed memory is limited to the use of `nf_tables_getsetelem`, which we can trigger by sending a netlink message of type `NFT_MSG_GETSETELEM`. This function eventually calls `nf_tables_fill_setelem` that will perform a memcpy of whatever the `nft_object`'s `key.name` member is pointing to [1] and return that to the user.

```c
static int nf_tables_getsetelem(struct sk_buff *skb,
                                const struct nfnl_info *info,
                                const struct nlattr * const nla[])
{
        ...
        nla_for_each_nested(attr, nla[NFTA_SET_ELEM_LIST_ELEMENTS], rem) {
                err = nft_get_set_elem(&ctx, set, attr);
                if (err < 0)
                        break;
        }
        ...
}

static int nf_tables_fill_setelem(struct sk_buff *skb,
                                  const struct nft_set *set,
                                  const struct nft_set_elem *elem)
{
        const struct nft_set_ext *ext = nft_set_elem_ext(set, elem->priv);
        ...
        if (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF) &&
            nla_put_string(skb, NFTA_SET_ELEM_OBJREF,
                           (*nft_set_ext_obj(ext))->key.name) < 0)
                goto nla_put_failure;
        ...
}

static inline int nla_put_string(struct sk_buff *skb, int attrtype,
                                 const char *str)
{
        return nla_put(skb, attrtype, strlen(str) + 1, str);
}

int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)
{
        if (unlikely(skb_tailroom(skb) < nla_total_size(attrlen)))
                return -EMSGSIZE;

        __nla_put(skb, attrtype, attrlen, data);
        return 0;
}

void __nla_put(struct sk_buff *skb, int attrtype, int attrlen,
               const void *data)
{
        struct nlattr *nla;

        nla = __nla_reserve(skb, attrtype, attrlen);
        memcpy(nla_data(nla), data, attrlen);    <--- [1]
}
```

So when another entity gets allocated into the freed memory location, whatever is at the offset of the `nft_object`'s `key.name` member is treated as the source pointer for the memcpy, leaking whatever data lies at that location. This happens to be offset 32 of the `nft_object` and the `nft_object` is allocated on the kmalloc-256 slab.

## Leaking the address of an `nft_set`

A candidate to leak an initial memory address from a heap object is to craft a specific `nft_rule` that is large enough to be allocated with kmalloc-256. An `nft_rule` can contain multiple `nft_expr` that can be specified when creating the rule. The size of an `nft_rule` is 24 bytes (not counting the expressions and userdata it contains) and has the following structure.

```
+ ------------------------------------------------------------------------------------ +
| Rule attributes (24 bytes) | nft_expr #1 | nft_expr #2 | other exprs | Rule USERDATA |
+ ------------------------------------------------------------------------------------ +
```

Since offset 32 from the start of the rule is treated as a source pointer we can leak data from, this means offset 8 from the start of the first `nft_expr` of the rule is used as the source pointer. This is the data member of the expression.

```c
struct nft_expr {
        const struct nft_expr_ops *ops;
        unsigned char           data[]
                __attribute__((aligned(__alignof__(u64))));
};
```

If the first `nft_expr` added to the rule is an `objref_map` expr, the data member is `struct nft_objref_map`. At the start of this is a pointer to an `nft_set` [1]. So when the leak is performed, we are leaking whatever is in the `struct list_head` [2] at the beginning of the set, which turns out to be a pointer to the next `list_head` that is linked (these are just nodes in a linked list of `nft_set`s).

```c
struct nft_objref_map {
        struct nft_set          *set;    <--- [1]
        u8                      sreg;
        struct nft_set_binding  binding;
};


struct nft_set {
        struct list_head        list;    <--- [2]
        struct list_head        bindings;
        struct nft_table        *table;
        possible_net_t          net;
        char                    *name;
        ...
        u32                     use;
        atomic_t                nelems;
        ...
        /* runtime data below here */
        const struct nft_set_ops        *ops ____cacheline_aligned;
        u16                             flags:14,
                                        genmask:2;
        u8                      klen;
        u8                      dlen;
        u8                      num_exprs;
        struct nft_expr         *exprs[NFT_SET_EXPR_MAX];
        struct list_head        catchall_list;
        unsigned char           data[]
                __attribute__((aligned(__alignof__(u64))));
};

struct list_head {
        struct list_head *next, *prev;
};
```

This `list_head` pointer that we leak is just a pointer to the start of the linked list of `nft_set`s, and this is a member of the `nft_table` that the set belongs to.

```c
struct nft_table {
        struct list_head        list;
        ...
        struct list_head        sets;
        ...
};
```

A note is that in order to create the `nft_rule` with multiple `objref_map` expressions, we cannot point the expressions to the original set that has the `NFT_SET_ANONYMOUS` flag and we have to create a new `nft_set` without that flag to point our expressions to. This is because an anonymous set can only be bound once by an expression while there is no such restriction if the set isn't anonymous. So after creating our second set, the linked list of `nft_set`s looks like this.

{% include nft-set-linked-list.svg %}

To actually allocate the `nft_rule` with kmalloc-256, we just need to create a rule with 4 `objref_map` expressions, because the rule attributes itself will take up 24 bytes and each `objref_map` expression takes up 48 bytes. We just have to spray the heap with multiple rules that are like this and send a netlink message of type `NFT_MSG_GETSETELEM` which will leak the address of the `sets` member in the `nft_table`.

If we use the address of the `sets` member as the leak source pointer, the next read will be the address of the anonymous set's `list_head`, which also happens to be the starting address of that set on the heap (this is the member with the identifier `list` in the `nft_set`). To craft a primitive that allows the read of an arbitrary address, we can make use of `nft_chain` allocations. When we create an `nft_chain`, we can specify the udata (i.e. userdata) that is associated with the chain. During the creation of an `nft_chain`, `nf_tables_addchain` is called which calls `nla_memdup` [1] that eventually calls `kmemdup` that does a `kmalloc_track_caller` [2] to allocate a chunk of memory of the size of the userdata and copies the supplied `nft_chain` userdata over [3]. When we specify a chain userdata of size 256, this performs the allocation using kmalloc-256. The `nft_chain` would fill the UAF slot, becoming an arbitrary read primitive and we just need to supply whatever address we want to use as the source pointer for a read at offset 32 of the chain userdata.

```c
static int nf_tables_addchain(struct nft_ctx *ctx, u8 family, u8 genmask,
                              u8 policy, u32 flags,
                              struct netlink_ext_ack *extack)
{
        ...
        if (nla[NFTA_CHAIN_USERDATA]) {
                chain->udata = nla_memdup(nla[NFTA_CHAIN_USERDATA], GFP_KERNEL);    <--- [1]
                if (chain->udata == NULL) {
                        err = -ENOMEM;
                        goto err_destroy_chain;
                }
                chain->udlen = nla_len(nla[NFTA_CHAIN_USERDATA]);
        }
        ...
}

static inline void *nla_memdup(const struct nlattr *src, gfp_t gfp)
{
        return kmemdup(nla_data(src), nla_len(src), gfp);
}

void *kmemdup(const void *src, size_t len, gfp_t gfp)
{
        void *p;

        p = kmalloc_track_caller(len, gfp);    <--- [2]
        if (p)
                memcpy(p, src, len);    <--- [3]
        return p;
}
```

To reiterate, we wanted to leak our anonymous set's address next and all that needs to be done here is to write the leaked address of the table's `sets` member at offset 32 of the `nft_chain` userdata (which we create to be size 256) and do a heap spray. Afterwards, perform the read with a netlink message of type `NFT_MSG_GETSETELEM`.

## Bypassing KASLR

We want to begin by obtaining the base address of the loaded `nf_tables` `.text` section. Initially, we want to leak a function pointer for an `nf_tables` function using the leaked set address that we obtained and then use that to get the `nf_tables` base address. A prime candidate is the `set->ops` pointer (a pointer to `nft_set_ops`). This is at offset 192 of the set so we just use the read primitive to read whatever is stored at the set base address + 192. Next, we can leak the `ops->lookup` function pointer which is at offset 0 from the beginning of `nft_set_ops`. This will leak the address of the function `nft_hash_lookup` because our set has its actual `ops` assigned to be `nft_set_hash_type.ops` since it is of type `nft_set_hash_type`. The `ops` that is assigned can be controlled by flags set by the user when creating the set. 

```c
struct nft_set_ops {
        bool                    (*lookup)(const struct net *net,
                                          const struct nft_set *set,
                                          const u32 *key,
                                          const struct nft_set_ext **ext);

        ...
}

const struct nft_set_type nft_set_hash_type = {
        .features       = NFT_SET_MAP | NFT_SET_OBJECT,
        .ops            = {
                .privsize       = nft_hash_privsize,
                .elemsize       = offsetof(struct nft_hash_elem, ext),
                .estimate       = nft_hash_estimate,
                .init           = nft_hash_init,
                .destroy        = nft_hash_destroy,
                .insert                 = nft_hash_insert,
                .activate       = nft_hash_activate,
                .deactivate     = nft_hash_deactivate,
                .flush          = nft_hash_flush,
                .remove                 = nft_hash_remove,
                .lookup                 = nft_hash_lookup,
                .walk           = nft_hash_walk,
                .get            = nft_hash_get,
        },
};
```

Using the address of this function we can get the base address of the `.text` section of `nf_tables`. With the `nf_tables` base address, we can use it to leak a function in the `.text` section of `vmlinux` itself. Since there are a plethora of `kfree` calls within the `nf_tables_api`, we can use the relative offset of those calls to get the address of the actual `kfree` function. A candidate to achieve this is the function `nft_set_destroy`, which contains a call to `kfree`. We simply trigger the read primitive using the `nf_tables` base address plus `kfree` invocation offset within `nft_set_destroy`. With the relative jump offset to the true `kfree` function in `nft_set_destroy`, we can determine the `kfree` function definition address and hence the base address of the kernel `.text` section.

## Hijacking execution flow

### Leaking the address of an `nft_object`

One way of triggering a ROP chain to hijack execution flow is to make use of the `eval` function pointer of the `ops` member of an `nft_object`. This function pointer can be easily triggered by just registering an `nft_expr` of `objref` type as part of a rule and then sending a packet which will cause this expression to be processed. To execute our ROP chain, we leverage the UAF to cause a type confusion where the supposed `eval` function pointer is actually pointing to some region in memory containing our payload. An `nft_expr` of `objref` type holds a pointer to an `nft_object` as its private data [1] and upon evaluation, it simply delegates the evaluation to its `nft_object`'s `eval` function [2]. Since our UAF involves a freed `nft_object` that we can freely replace, this makes an `nft_expr` of `objref` type a perfect candidate to abuse for hijacking execution flow.

```c
static int nft_objref_init(const struct nft_ctx *ctx,
			   const struct nft_expr *expr,
			   const struct nlattr * const tb[])
{
	struct nft_object *obj = nft_objref_priv(expr);
	u8 genmask = nft_genmask_next(ctx->net);
	u32 objtype;

	if (!tb[NFTA_OBJREF_IMM_NAME] ||
	    !tb[NFTA_OBJREF_IMM_TYPE])
		return -EINVAL;

	objtype = ntohl(nla_get_be32(tb[NFTA_OBJREF_IMM_TYPE]));
	obj = nft_obj_lookup(ctx->net, ctx->table,
			     tb[NFTA_OBJREF_IMM_NAME], objtype,
			     genmask);
	if (IS_ERR(obj))
		return -ENOENT;

	nft_objref_priv(expr) = obj;    <--- [1]
	obj->use++;

	return 0;
}

static void nft_objref_eval(const struct nft_expr *expr,
			    struct nft_regs *regs,
			    const struct nft_pktinfo *pkt)
{
	struct nft_object *obj = nft_objref_priv(expr);

	obj->ops->eval(obj, regs, pkt);    <--- [2]
}
```

The `ops` member is at offset 128 [1] from the start of the `nft_object` and the eval function is at offset 0 [2] of the ops member. We simply need to make sure that the address of the start of our ROP chain is stored at offset 128 of whatever we replace the freed UAF slot with and this conveniently means the first 128 bytes of the slot are free for us to use to store the payload.

```c
struct nft_object {
        struct list_head        list;
        struct rhlist_head      rhlhead;
        struct nft_object_hash_key      key;
        u32                     genmask:2,
                                use:30;
        u64                     handle;
        u16                     udlen;
        u8                      *udata;
        /* runtime data below here */
        const struct nft_object_ops     *ops ____cacheline_aligned;    <--- [1]
        unsigned char           data[]
                __attribute__((aligned(__alignof__(u64))));
};

struct nft_object_ops {
        void                    (*eval)(struct nft_object *obj,    <--- [2]
                                        struct nft_regs *regs,
                                        const struct nft_pktinfo *pkt);
        unsigned int            size;
        int                     (*init)(const struct nft_ctx *ctx,
                                        const struct nlattr *const tb[],
                                        struct nft_object *obj);
        void                    (*destroy)(const struct nft_ctx *ctx,
                                           struct nft_object *obj);
        int                     (*dump)(struct sk_buff *skb,
                                        struct nft_object *obj,
                                        bool reset);
        void                    (*update)(struct nft_object *obj,
                                          struct nft_object *newobj);
        const struct nft_object_type    *type;
};
```

Consequently, the address of the start of our ROP chain is just the base address of the freed `nft_object`, which we now have to leak. Since the anonymous `nft_set` has a reference to the freed `nft_object` through its `nft_set_elem`, we can just leak the address of the freed memory location from the `nft_set_elem`. As mentioned earlier, our anonymous `nft_set` has type `nft_set_hash_type` and has space reserved [1] for a `struct nft_hash` plus the linked list heads for its hash buckets [2].

```c
static int nf_tables_newset(struct sk_buff *skb, const struct nfnl_info *info,
			    const struct nlattr * const nla[])
{
        ...
        ops = nft_select_set_ops(&ctx, nla, &desc, policy);
	if (IS_ERR(ops))
		return PTR_ERR(ops);

	udlen = 0;
	if (nla[NFTA_SET_USERDATA])
		udlen = nla_len(nla[NFTA_SET_USERDATA]);

	size = 0;
	if (ops->privsize != NULL)
		size = ops->privsize(nla, &desc);    <--- [1]
	alloc_size = sizeof(*set) + size + udlen;
	if (alloc_size < size || alloc_size > INT_MAX)
		return -ENOMEM;
	set = kvzalloc(alloc_size, GFP_KERNEL);
        ...
}

const struct nft_set_type nft_set_hash_type = {
	.features	= NFT_SET_MAP | NFT_SET_OBJECT,
	.ops		= {
		.privsize       = nft_hash_privsize,
		...
	},
};

static u64 nft_hash_privsize(const struct nlattr * const nla[],
			     const struct nft_set_desc *desc)
{
	return sizeof(struct nft_hash) +
	       (u64)nft_hash_buckets(desc->size) * sizeof(struct hlist_head);    <--- [2]
}
```


 The `struct nft_hash` trails the `struct nft_set` and has a table member [1] that represents the hash table which holds the `nft_set_elem`s of that set. Each index of the table contains a `struct hlist_head` which is the head of a linked list that contains set elems that were hashed into that index in the table. Each `struct hlist_head` just contains a pointer to a `struct hlist_node` which is a node in the linked list as well as a member within a `struct nft_hash_elem` [2]. A pointer to an `nft_hash_elem` is stored as the `priv` member of an `nft_set_elem` for hash type sets [3]. Basically, our set elem within our set is an `nft_set_elem` with `priv` pointing to an `nft_hash_elem`, which itself contains a member `node` that is added to a linked list of a hash table for the set. If such a set elem is specified to have an object reference during creation, a pointer to the object is stored within the `ext` member of the elem [4]. The memory layout of the `nft_set` of type `nft_set_hash_type` is illustrated in the diagram following the function and struct definitions below.

 ```c
struct nft_hash {
	u32				seed;
	u32				buckets;
	struct hlist_head		table[];    <--- [1]
};

struct hlist_head {
        struct hlist_node *first;
};

struct hlist_node {
        struct hlist_node *next, **pprev;
};

struct nft_hash_elem {
        struct hlist_node       node;    <--- [2]
        struct nft_set_ext      ext;
};

struct nft_set_elem {
	union {
		u32		buf[NFT_DATA_VALUE_MAXLEN / sizeof(u32)];
		struct nft_data	val;
	} key;
	union {
		u32		buf[NFT_DATA_VALUE_MAXLEN / sizeof(u32)];
		struct nft_data	val;
	} key_end;
	union {
		u32		buf[NFT_DATA_VALUE_MAXLEN / sizeof(u32)];
		struct nft_data val;
	} data;
	void			*priv;    <--- [3]
};

static int nft_add_set_elem(struct nft_ctx *ctx, struct nft_set *set,
			    const struct nlattr *attr, u32 nlmsg_flags)
{
        if (nla[NFTA_SET_ELEM_OBJREF] != NULL) {
                obj = nft_obj_lookup(ctx->net, ctx->table,
				     nla[NFTA_SET_ELEM_OBJREF],
				     set->objtype, genmask);
        }
        ...
        ext = nft_set_elem_ext(set, elem.priv);
        ...
        if (obj) {
		*nft_set_ext_obj(ext) = obj;    <--- [4]
		obj->use++;
	}
        ...
}
 ```
```
+ ---------------------------------------------------------------------------------------------- +
| + -------------- + | + --------------------------------------------------------------------- + |
| | struct nft_set | | | struct nft_hash:  u32 seed | u32 buckets | struct hlist_head table[ ] | |
| + -------------- + | + --------------------------------------------------------------------- + |
+ ---------------------------------------------------------------------------------------------- +
```

We only have one `nft_set_elem` in our set, and to easily find its `node` member within the set's hash table, we can ensure the table contains only one linked list (i.e. one hash bucket). This is controllable when creating the set. As a result, the `node` of our `nft_set_elem` can be found in the linked list at index 0 of the set's hash table. Since that list contains only one entry (we created only one set elem successfully), we can leak the address of the `node` member of the `nft_hash_elem` by applying our read primitive to the address of the hash table (a `struct hlist_head`), which simply holds a pointer to the first `hlist_node`. With the address of the set elem's `hlist_node`, we can then leak the freed `nft_object`'s address, since it lies within the `nft_set_ext` that follows the `hlist_node` inside the `nft_hash_elem`. We just need to compute the appropriate offsets from the `hlist_node` to the `nft_object` pointer within the `nft_set_ext`. With the leaked address, we now know the address we need the `eval` function pointer to point to.

### Creating an objref expression trigger for ROP

The next step is to create an `objref` expression to an `nft_object` that fills the UAF slot, which is then freed and replaced with arbitrary data after. We perform a heap spray of `nft_object`s, find out which object was allocated into the previous freed memory location, create an `objref` expression to that particular object and finally destroy the `nft_object` again, while the `objref` continues to hold a pointer to the `nft_object`. The issue here is that the object now has use = 1 (which is a reference counting mechanism for `nft_object`s) after creating an `objref` that holds a pointer to it and it cannot be deleted directly by sending a netlink message of type `NFT_MSG_DELOBJ`. However, this new object that we formed the `objref` expression to now lies in the UAF slot, and the `nft_set_elem` in our anonymous set still mistakenly assumes it's holding a valid pointer to an `nft_object` there. When we delete this set elem from the set without specifying the exact set elem to delete, `nf_tables_delsetelem` is called which calls `nft_set_flush` [1] and this in turn calls `nft_setelem_flush` [2] for every set elem in the set. `nft_setelem_flush` invokes `nft_setelem_data_deactivate` [3] which decrements the use of the `nft_object` it is referencing [4].

```c
static int nf_tables_delsetelem(struct sk_buff *skb,
                                const struct nfnl_info *info,
                                const struct nlattr * const nla[])
{
        ...
        table = nft_table_lookup(net, nla[NFTA_SET_ELEM_LIST_TABLE], family,
                                 genmask, NETLINK_CB(skb).portid);
        ...
        set = nft_set_lookup(table, nla[NFTA_SET_ELEM_LIST_SET], genmask);
        if (IS_ERR(set))
                return PTR_ERR(set);
        ...
        if (!nla[NFTA_SET_ELEM_LIST_ELEMENTS])
                return nft_set_flush(&ctx, set, genmask);    <--- [1]

        nla_for_each_nested(attr, nla[NFTA_SET_ELEM_LIST_ELEMENTS], rem) {
                err = nft_del_setelem(&ctx, set, attr);
                if (err < 0)
                        break;
        }
        return err;
}

static int nft_set_flush(struct nft_ctx *ctx, struct nft_set *set, u8 genmask)
{
        struct nft_set_iter iter = {
                .genmask        = genmask,
                .fn             = nft_setelem_flush,    <--- [2] // called for each elem in set->ops->walk
        };

        set->ops->walk(ctx, set, &iter);
        if (!iter.err)
                iter.err = nft_set_catchall_flush(ctx, set);

        return iter.err;
}

static int nft_setelem_flush(const struct nft_ctx *ctx,
                             struct nft_set *set,
                             const struct nft_set_iter *iter,
                             struct nft_set_elem *elem)
{
        struct nft_trans *trans;
        int err;

        trans = nft_trans_alloc_gfp(ctx, NFT_MSG_DELSETELEM,
                                    sizeof(struct nft_trans_elem), GFP_ATOMIC);
        if (!trans)
                return -ENOMEM;

        if (!set->ops->flush(ctx->net, set, elem->priv)) {
                err = -ENOENT;
                goto err1;
        }
        set->ndeact++;

        nft_setelem_data_deactivate(ctx->net, set, elem);    <--- [3]
        nft_trans_elem_set(trans) = set;
        nft_trans_elem(trans) = *elem;
        nft_trans_commit_list_add_tail(ctx->net, trans);

        return 0;
err1:
        kfree(trans);
        return err;
}

static void nft_setelem_data_deactivate(const struct net *net,
                                        const struct nft_set *set,
                                        struct nft_set_elem *elem)
{
        const struct nft_set_ext *ext = nft_set_elem_ext(set, elem->priv);

        if (nft_set_ext_exists(ext, NFT_SET_EXT_DATA))
                nft_data_release(nft_set_ext_data(ext), set->dtype);
        if (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF))
                (*nft_set_ext_obj(ext))->use--;    <--- [4]
}
```

This means that after we successfully delete the set elem, the `nft_object` it is referencing now has a use count of 0 and we can delete it by just sending a `NFT_MSG_DELOBJ` netlink message that will invoke `nf_tables_delobj` to delete the object, leaving us with an `objref` expression pointing to a freed slot that we can now fill with arbitrary data specified by an `nft_chain`'s userdata.

### ROP chain execution and namespace re-association

 A point to note is that the `objref` expression belongs to an `nft_rule` and that rule is actually added to a basechain in `nf_tables`. A basechain is registered with a netfilter hook (in our case we set it to be an output hook) and this would act as a filter for outgoing packets for the system as rules in that chain will be used to process the traffic. In order to actually trigger the ROP chain, we just have to send a UDP datagram using the `sendto` syscall. This will result in `nft_do_chain` processing every expression in every rule for the chain, eventually invoking the `eval` function pointer (pointing to `nft_objref_eval`) on our `objref` expression. This triggers `obj->ops->eval` of the `nft_object` pointer stored in the `objref` expression. Recall that offset 128 from the start of the `nft_object` is where the `obj->ops->eval` function pointer is supposedly located. This means that if we spray `nft_chain`s, with ROP chain contents at the beginning of the chain's `userdata` and offset 128 storing the starting address of the UAF slot, this will kick off execution of our shellcode. As the `eval` function is called with the `nft_object` (replaced with chain `userdata` now) itself as the first parameter, we can first perform a stack pivot in the ROP chain using a gadget similar to `push rdi; pop rsp; ret;`. In the rest of the ROP chain, the `init` process' credentials are committed using `commit_creds(init_cred)` and `swapgs_restore_regs_and_ret_to_usermode` is used to cleanly return to usermode, with the RIP in userland pointing to a function in the exploit code responsible for escaping the namespace jails and spawning a shell. The namespace jails are escaped using the `setns` syscall (for instance `setns(open("/proc/1/ns/net", O_RDONLY), 0);`) which re-associates that namespace of the process with that of the init process.