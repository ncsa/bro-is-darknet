# @TEST-EXEC: bro  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

redef darknet_mode=NOT_ALLOCATED;
redef local_nets={192.168.0.0/16};

#no used address space defined defined yet, so nothing is darknet
print is_darknet(192.168.1.22) == F;
print is_darknet(192.168.2.22) == F;

#mark a host as allocated which will flag the /24
#This will update the used_address_space set
add_host(192.168.1.100);
#Now, 192.168.1.0/24 should be marked as allocated and NOT be darknet anymore
#but 192.168.2.0 will be darknet

print is_darknet(192.168.1.22) == F;
print is_darknet(192.168.2.22) == T;
