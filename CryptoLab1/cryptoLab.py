import os
import io


fname = 'infile.txt'
fname2 = 'outfile.txt'

path = os.path.abspath(fname)
path2 = os.path.abspath(fname2)

print('copying ', path, 'to ', path2)

blocksize = 16
totalsize = 0
data = bytearray(blocksize)

file = open(fname, 'rb')
file2 = open(fname2, 'wb')

while True:
    num = file.readinto(data)
    totalsize += num
    print(num, data)
    print(num, data.hex())

    if num == blocksize:
        file2.write(data)
    else:
        data2 = data[0:num]
        file2.write(data2)
        break

file.close()
file2.close()

print('read ',totalsize, ' bytes')
