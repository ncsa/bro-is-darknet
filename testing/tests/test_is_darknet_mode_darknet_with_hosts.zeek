# @TEST-EXEC: zeek  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

redef darknet_mode=DARKNET;
#Let's say the bottom half of the subnet is dark
redef darknet_address_space += {192.168.2.0/25};

print is_darknet(192.168.2.22) == T;
print is_darknet(192.168.2.222) == F;

