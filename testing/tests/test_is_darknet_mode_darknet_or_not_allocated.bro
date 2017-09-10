
# @TEST-EXEC: bro  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

redef darknet_mode=DARKNET_OR_NOT_ALLOCATED;
redef local_nets={192.168.0.0/16};
#Let's say these subnets are the darknet subnets
redef darknet_address_space += {192.168.1.0/24};
redef darknet_address_space += {192.168.2.0/24};

#These will start out as darknet
print is_darknet(192.168.1.22) == T;
print is_darknet(192.168.2.22) == T;

#Let's say 192.168.1.0/24 is used for honeynet purposes
#mark a host as allocated which will flag the /24
#This will update the used_address_space set
add_host(192.168.1.100);
#Now, 192.168.1.0/24 should be marked as allocated and NOT be darknet anymore
#but we are using DARKNET_OR_NOT_ALLOCATED so it should STILL be dark

print is_darknet(192.168.1.22) == T;
print is_darknet(192.168.2.22) == T;
