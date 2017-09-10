# @TEST-EXEC: bro  ../../../scripts %INPUT > out
# @TEST-EXEC: btest-diff out

module Site;

redef darknet_mode=DARKNET;

#Nothing defined yet
print is_darknet(192.168.2.22) == F;
print is_darknet(192.168.2.222) == F;
