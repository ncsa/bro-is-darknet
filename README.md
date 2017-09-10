# Bro Is Darknet?
This plugin adds a Site::is\_darknet function.
This is useful for scripts that track scan attempts or other probes.
It can handle purely dark address space as well as honeynet space.

## Configuration.

### Mode

`is_darknet` can operate in four different modes by `redef`ing `Site::darknet_mode` to one of these values:

* `DARKNET` - Only hosts defined in darknet_address_space are dark
* `NOT_ALLOCATED` - Only hosts NOT listed in used_address_space are dark
* `DARKNET_OR_NOT_ALLOCATED` - Only hosts defined in darknet_address_space OR
  NOT listed in used_address_space are dark. Useful if you reuse part of darknet
  space for honey net purposes
* `DARKNET_AND_NOT_ALLOCATED` - Only hosts both defined in
  darknet_address_space AND NOT listed in used_address_space are dark. Useful if
  your networking group may reallocate your darknet subnets out from under you.

## subnet sets

`is_darknet` uses two sets to determine if an address is darknet or not

* `used_address_space: set[subnet]` - A set containing subnets from local_nets that are in use
* `darknet_address_space: set[subnet]` -  A set containing subnets from local_nets that are dark

You should `redef` these in `local.bro` using something like

    redef Site::used_address_space = {
        192.168.1.0/24, 192.168.2.0/24, 192.168.4.0/24,
        192.168.10.0/24, 192.168.11.0/24, 192.168.13.0/24,
    }

or

    redef Site::darknet_address_space = {
        192.168.0.0/24, 192.168.253.0/24, 192.168.2544.0/24,
    }

## Auto used_address_space tracking

This plugin will also add any host that it sees a bidirectional connection from
to `used_address_space`.  It does this by first aggregating the address up to
the subnet it was seen in using the `v4_aggregation_bits` (default 24) or
`v6_aggregation_bits` (default 64) values.

This is for the extra paranoid configuration of `darknet_mode = DARKNET_AND_NOT_ALLOCATED`.
If you have `192.168.0.0/24` listed under `darknet_address_space`, but bro sees
a bidirectional connection to `192.168.0.55` it will no longer treat all of
`192.168.0.0/24` as dark.
