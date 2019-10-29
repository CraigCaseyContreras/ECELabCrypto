from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes

def digestMD5(user_input, byte_user):
	
	myhash = hashes.MD5()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	print("Output of original data: ", user_input)
	return digest


def digestSHA1(user_input, byte_user):
	
	myhash = hashes.SHA1()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	print("Output of original data: ", user_input)
	return digest
	
def digestSHA256(user_input, byte_user):
	
	myhash = hashes.SHA256()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	print("Output of original data: ", user_input)
	return digest

	
def digestSHA384(user_input, byte_user):
	
	myhash = hashes.SHA384()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	print("Output of original data: ", user_input)
	return digest


def digestSHA512(user_input, byte_user):
	
	myhash = hashes.SHA512()
	backend = default_backend()
	hasher = hashes.Hash(myhash, backend)
	hasher.update(byte_user)
	digest = hasher.finalize()
	print("Output of original data: ", user_input)
	return digest


def main():
	#MD5, SHA1, SHA256, SHA384, SHA512 
	#Try for different size messages and with slight differences in the message - already did this. Can type in anything
	
	user_input = input("Please enter an input to convert to bytearray data: ")
	byte_user = bytearray(user_input.encode())
	
	digests = ['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512']
	
	for i, item in enumerate(digests,1):
		print(i, '. ' + item + "\n")
	choose_digest = input("Please choose a digest from the list above (enter number): ")
	
	if choose_digest == '1':
		output = digestMD5(user_input, byte_user)
		print("Output of message digest: ", output)
	elif choose_digest == '2':
		output = digestSHA1(user_input, byte_user)
		print("Output of message digest: ", output)
	elif choose_digest == '3':
		output = digestSHA256(user_input, byte_user)
		print("Output of message digest: ", output)
	elif choose_digest == '4':
		output = digestSHA384(user_input, byte_user)
		print("Output of message digest: ", output)
	elif choose_digest == '5':
		output = digestSHA512(user_input, byte_user)
		print("Output of message digest: ", output)
	else:
		print("Sorry! Number is invalid! Please run program again and choose a number from the list.")
	

if __name__ == "__main__":
	main()
