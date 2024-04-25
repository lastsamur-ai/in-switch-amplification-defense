from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import sys
import csv

N= 350

if len(sys.argv)<2:
	print("Please specify which switch (1-3) to connect to by passing the argument")
	exit()

p = int(sys.argv[1])

if p ==1:#s1
	controller = SimpleSwitchThriftAPI(9091)
	filename = "presence/s1.csv"
	print("Connected to S1")
elif p ==2:#s2
	controller = SimpleSwitchThriftAPI(9092)
	filename = "presence/s2.csv"
	print("Connected to S2")
elif p==3:#s3
	controller = SimpleSwitchThriftAPI(9093)
	filename = "presence/s3.csv"
	print("Connected to S3")
else:
	print("Please specify which switch (1-3) to connect to by passing the argument")
	exit()


print("Time as observed by switch: {}".format(controller.register_read("t")[0]))

'''
field=[['time','label']]
rows=[]
for n in range(N):
	row=[]
	row.append(n)
	row.append(controller.register_read("Y")[n])
	rows.append(row)
CSVFILE=open('presence/labels.csv','w')
writer=csv.writer(CSVFILE,delimiter=',')
writer.writerows(field)
writer.writerows(rows)
CSVFILE.close()
print("Labels downloaded to {}".format('presence/labels.csv'))
'''

fields = [[
'time', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'b10', 'b11', 'b12', 'b13', 'b14', 'b15', 'b16',
        'b17', 'b18', 'b19', 'b20', 'b21', 'b22', 'b23', 'b24', 'b25', 'b26', 'b27', 'b28', 'b29', 'b30', 'b31', 'b32'
]]

rows=[]
for n in range(N):
	row=[]
	row.append(n)
	for i in range(32):
		row.append(controller.register_read("bin")[n*32+i])
	rows.append(row)

csvfile=open(filename,'w')
writer = csv.writer(csvfile,delimiter=',')
writer.writerows(fields)
writer.writerows(rows)
csvfile.close()
print("Bins were downloaded to {}".format(filename))

'''
rows=[]
for n in range(N):
	row=[]
	row.append(n)
	for i in range(32):
		row.append(controller.register_read("content")[(n*32)+i])
	rows.append(row)

cSvfile=open('presence/content.csv','w')
writer = csv.writer(cSvfile,delimiter=',')
writer.writerows(fields)
writer.writerows(rows)
cSvfile.close()
print("content downloaded to {}".format('presence/content.csv'))
'''