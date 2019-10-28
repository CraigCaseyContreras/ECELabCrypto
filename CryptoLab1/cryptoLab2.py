import os
import io
# Program to show various ways to read and
# write data in a file.

fname = "myfile.txt"
fname2 = "myfile2.txt"

path = os.path.abspath(fname)
path2 = os.path.abspath(fname2)

file1 = open(fname,"w")
L = ["I am Craig\nI like football\nI am a grad student at the University of Miami\n"]

# \n is placed to indicate EOL (End of Line)
file1.write("Hello \n")
file1.writelines(L)
file1.close() #to change file access modes

file1 = open(fname,"r+")

print ("This is from ", path, "Output of Read function is: ")
test = file1.read()
print(test)

file1.close()

#Appended!!!
file1 = open(fname,"a")
file1.write("This is appended!!! \n")
file1.close()

file1 = open("myfile.txt","r+")

print ("This is from ", path, "Output of Read function after appending is: ")
print(file1.read())

file1.close()

print('copying ', path, 'to ', path2)


blocksize = 16
totalsize = 0
data = bytearray(blocksize)

file1 = open(fname, 'rb')
file2 = open(fname2, 'wb')

while True:
    num = file1.readinto(data)
    totalsize += num

    if num == blocksize:
        file2.write(data)
    else:
        data2 = data[0:num]
        file2.write(data2)
        break

file1.close()
file2.close()

file2 = open(fname2,"r+")

print ("\n\nThis is from ", path2, "Output of Read function is: ")
print(file2.read())
