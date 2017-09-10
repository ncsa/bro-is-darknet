# @TEST-EXEC: bro  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

print aggregate_address(192.168.2.22) == 192.168.2.0/24;
