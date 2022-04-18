import base64 
import pwn
import Crypto
from Crypto.Util.number import *


#L = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

#print(''.join(chr(i) for i in L))



#hex_string = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

#print(bytes.fromhex(hex_string))

#hex_string = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

#bytes_rep = bytes.fromhex(hex_string)

#print(base64.b64encode(bytes_rep))


#crypto/Base+64+Encoding+is+Web+Safe/

#integer = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

#print(Crypto.Util.number.long_to_bytes(integer))

#b''
#pseudo code:
#
#take the string label 
#for each char in label xor it with 13
#take the resulting integers back into a string and submit the flag 
#crypto{new_string}



# a = 'label'
# b = 13 
# result = ""
# flag = []
# for l in a:
# 	result += chr(int(str(ord(l)^b)))

# print("crypto{"+result+"}")


# Commutative: A ⊕ B = B ⊕ A
# Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
# Identity: A ⊕ 0 = A
# Self-Inverse: A ⊕ A = 0

#okay I had trouble with this so this guy needs props!
#https://github.com/s-nikravesh/crypto-hack/blob/master/General/XOR%20Properties.py

KEY1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY2_KEY1 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
KEY2_KEY3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
FLAG_KEY1_KEY3_KEY2 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

KEY1_ORD = [o for o in bytes.fromhex(KEY1)]
KEY2_KEY3_ORD = [o for o in bytes.fromhex(KEY2_KEY3)]
FLAG_KEY1_KEY3_KEY2_ORD = [ o for o in bytes.fromhex(FLAG_KEY1_KEY3_KEY2)]


FLAG_KEY1_ORD = [
	o_f132 ^ o23 for (o_f132, o23) in zip(FLAG_KEY1_KEY3_KEY2_ORD, KEY2_KEY3_ORD)
]
FLAG_ORD = [o_f1 ^ o1 for (o_f1, o1) in zip(FLAG_KEY1_ORD, KEY1_ORD)]
flag = "".join(chr(o) for o in FLAG_ORD)
# print("Flag:")
# print(flag)

#btw when I looked at solutions, bruh people using pwn tools I didn't know I could do that, I've been trying to learn the MATH along the way.

# from pwn import xor
# k1=bytes.fromhex('a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313')
# k2_3=bytes.fromhex('c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1')
# flag=bytes.fromhex('04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf')
# print(xor(k1,k2_3,flag))  

#string = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
string = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
string_ord = [ o for o in bytes.fromhex(string)]
for order in range(256):
	possible_flag_ord = [order ^ o for o in string_ord]
	possible_flag = "".join(chr(o) for o in possible_flag_ord)
	if possible_flag.startswith("crypto{"):
		flag = possible_flag
		break

print("Flag:")
print(flag)


#https://github.com/s-nikravesh/crypto-hack/blob/master/General/Favourite%20byte.py
