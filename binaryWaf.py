'''
    add payload into shell
    last 4 bytes record length of payload
'''



import struct
import getopt
import sys

def help():
	print ''''
Usage:
    python binaryWaf.py -s shell -p payload -o outfile
    -s equal to --shell
    -p equal to --payload
    -o equal to --output
	'''
	
if __name__ == '__main__':
	
	if len(sys.argv) == 1:
		help()
		exit(0)
	
	try:
		options, args = getopt.getopt(sys.argv[1:], "hs:p:o:", ["help", "shell", "payload"])
	except getopt.GetoptError:
		help()
		exit(0)
	
	file_shell = ''
	file_payload = ''
	file_output = ''
	for name, value in options:
		if name in ("-h", "--help"):
			help()
			exit(0)
		elif name in ("-s", "--shell"):
			file_shell = value
		elif name in ("-p", "--payload"):
			file_payload = value
		elif name in ("-o"):
			file_output = value

	if file_shell == "":
		print 'no parameter for -s'
		exit(0)
	elif file_payload == "":
		print 'no parameter for -p'
		exit(0)
	elif file_output == "":
		print 'no parameter for -o'
		exit(0)
		
	payload = open(file_payload,'r').read()
	payload_len = len(payload)
	print 'payload len is', hex(payload_len)
	shell = open(file_shell,'r').read()
	new_binary = shell + payload + struct.pack('I', payload_len)
	open(file_output, 'w').write(new_binary)
