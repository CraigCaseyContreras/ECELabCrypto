import hashlib
chars="abcdefghijklmnopqrstuvwxyz"
chars_len = len(chars)

def reduce(i):
    # reduces int i to a 5 char password
    # think of i as a number encoded in base l
    pwd=""
    while len(pwd)<5:
        pwd = pwd + chars[ i%chars_len ]
        i = i // chars_len
    print(pwd)
    return pwd


table=[]
# generate 10 chains of 1000 pwd, print start and end
for s in range(0,312):
    # we can use reduce to generate the start of a chain
    start=reduce(s)

    p=start
    for i in range(0,10000):
        # hash
        h=hashlib.md5(p.encode('ascii')).hexdigest()
        # reduce
        p=reduce(int(h,16))

    table.append([start,p])

print (table)