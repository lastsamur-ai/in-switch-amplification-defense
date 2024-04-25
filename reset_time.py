from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import sys

if len(sys.argv)<2:
	print("Please specify which switch (1-3) to connect to by passing the argument")
	exit()

N=350
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

controller.register_write("t",0,0)

print('Time is reset to 0')

for n in range(N):
	for i in range(32):
		controller.register_write("bin",n*32+i,0)

print("Bins are reset to 0")