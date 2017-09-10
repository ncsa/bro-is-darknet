# @TEST-EXEC: bro  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

redef v4_aggregation_bits = 32;
print aggregate_address(192.168.2.22) == 192.168.2.22/32;
