module Site;

export {
    # These should be figured out based on how large local_nets is
    # if local_nets is a single /24, v4_aggregation_bits can be 32
    ## When adding a host, truncate it to this many bits and assume the entire
    ## subnet is in use

    const v4_aggregation_bits = 24 &redef;
    const v6_aggregation_bits = 64 &redef;

    ## A set containing subnets from local_nets that are in use
    global used_address_space: set[subnet] &redef;

    ## A set containing subnets from local_nets that are dark
    global darknet_address_space: set[subnet] &redef;

    ## Return true if an address is dark
    global is_darknet: function(a: addr): bool;

    type DarknetMode: enum {
        ## Only hosts defined in darknet_address_space are dark
        DARKNET,

        ## Only hosts NOT listed in used_address_space are dark
        NOT_ALLOCATED,

        ## Only hosts defined in darknet_address_space OR NOT listed in used_address_space are dark
        ## Useful if you reuse part of darknet space for honey net purposes
        DARKNET_OR_NOT_ALLOCATED,

        ## Only hosts both defined in darknet_address_space AND NOT listed in used_address_space are dark
        ## Useful if your networking group may reallocate your darknet subnets out from under you.
        DARKNET_AND_NOT_ALLOCATED,
    };
    const darknet_mode: DarknetMode=DARKNET &redef;

    ## Automatically add newly seen hosts to used_address_space after
    ## truncating to v4_aggregation_bits or v6_aggregation_bits
    const auto_manage_allocated: bool=F &redef;

    redef enum Notice::Type += {
    	     New_Used_Address_Space
    };
    global new_used_address_space: event(sn: subnet);
}

function aggregate_address(a: addr): subnet
{
    if(is_v4_addr(a)) {
        return mask_addr(a, v4_aggregation_bits);
    } else {
        return mask_addr(a, v6_aggregation_bits);
    }
}

######################################
# Cluster mode
@if ( Cluster::is_enabled() )
event zeek_init()
{
    Broker::auto_publish(Cluster::manager_topic, Site::new_used_address_space);
    Broker::auto_publish(Cluster::proxy_topic, Site::new_used_address_space);
}

event Site::new_used_address_space(sn: subnet)
{
    add used_address_space[sn];
}
@endif
######################################

function add_host(a: addr)
{
    if (a !in used_address_space) {
        local masked = aggregate_address(a);
        add used_address_space[masked];
        event Site::new_used_address_space(masked);
        NOTICE([$note=New_Used_Address_Space,
                $identifier=fmt("%s",masked),
                $msg=fmt("%s",masked)]);
    }
}

function is_darknet(a: addr): bool
{
    switch ( darknet_mode) {
    case DARKNET:
        return (a in darknet_address_space);
    case NOT_ALLOCATED:
        return (a in local_nets && |used_address_space| != 0 && a !in used_address_space);
    case DARKNET_OR_NOT_ALLOCATED:
        return (a in darknet_address_space || (|used_address_space| != 0 && a in local_nets && a !in used_address_space));
    case DARKNET_AND_NOT_ALLOCATED:
        return (a in darknet_address_space && (|used_address_space| != 0 && a in local_nets && a !in used_address_space));
    }
    Reporter::error(fmt("Invalid darknet_mode %s(%d)", darknet_mode, darknet_mode));
    return F;
}

#Similar to how known hosts works, but this will also catch udp only hosts.
event Conn::log_conn(rec: Conn::Info)
{
    if (!auto_manage_allocated)
        return;
    if (|Site::local_nets| == 0)
        return;
    if (rec$local_orig && rec$orig_pkts > 0)
        add_host(rec$id$orig_h);
    if (rec$local_resp && rec$resp_pkts > 0)
        add_host(rec$id$resp_h);
}
