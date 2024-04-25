from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import sys

if len(sys.argv)<2:
	print("Please specify which switch (1-3) to connect to by passing the argument")
	exit()

p = int(sys.argv[1])

if p ==1:#s1
	controller = SimpleSwitchThriftAPI(9091)
	print("Connected to S1")
elif p ==2:#s2
	controller = SimpleSwitchThriftAPI(9092)
	print("Connected to S2")
elif p==3:#s3
	controller = SimpleSwitchThriftAPI(9093)
	print("Connected to S3")
else:
	print("Please specify which switch (1-3) to connect to by passing the argument")
	exit()


print("Time as observed by switch: {}".format(controller.register_read("t")[0]))