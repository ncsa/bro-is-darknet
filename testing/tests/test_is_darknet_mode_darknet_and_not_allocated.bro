
# @TEST-EXEC: bro  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

redef darknet_mode=DARKNET_AND_NOT_ALLOCATED;
redef local_nets={192.168.0.0/16};
#Let's say that subnet 3 is currently allocated and that 1 and 2 are darknet
redef used_address_space={192.168.3.0/24};
redef darknet_address_space += {192.168.1.0/24};
redef darknet_address_space += {192.168.2.0/24};

#These will start out as darknet
print is_darknet(192.168.1.22) == T;
print is_darknet(192.168.2.22) == T;

#Let's say 192.168.1.0/24 is reassigned by networking group
#mark a host as allocated which will flag the /24
#This will update the used_address_space set
add_host(192.168.1.100);
#Now, 192.168.1.0/24 should be marked as allocated and NOT be darknet anymore
#Even though it is still defined undet darknet_address_space

print is_darknet(192.168.1.22) == F;
print is_darknet(192.168.2.22) == T;
