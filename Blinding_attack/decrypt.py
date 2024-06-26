#exploit-blind.py

from pwn import *
from time import sleep
import binascii
from gmpy2 import mpz, powmod, mul, divm

DELAY = 0.5
local = False
debug = True
e = mpz(65537)
d = mpz(1568285263768501732818328320511629642875064318126264773176402162063414029019552015208378147415135584397039600737080993027702630930696379133941301092371841712833615433127126841619464574827015780577329215130743142304356963372974314300549251037297089095888613813025849461961689136723457981196984901634305044882572884429636926589307978155389584182278408495724608043621991280167408620534651830073093136272231629494826910936016933211209155663316948185922751060616648342097882005697026783567976368285160591751813938075036356113489495762878707450272084659301801564293123458920666027344212043777409046272492671188377827505457)

if local:
	p = process('./local.py')
	n = mpz(22678885995497859237359837409834658408010390603936675736906855360800963199438301063705092375804444129441479327781570397188117238152040732414190434618440730435564133857204879042192155745904265933737075192414720502471456820073834429901830596917771255092067979581702360147524982558130023326060635370345862693395971869907940712129405277579994126963033117569220694056962409098580444767623301289484274757401588341649346335157605898367428193861286290895380925167854010745241200707970331694303405414452197886125252783330442313175217854953051589125237129765483421120589637801644296802772127692576775865505959688257172232082269)
else:
	p = remote('blind.q.2019.volgactf.ru',7070)
	n = mpz(26507591511689883990023896389022361811173033984051016489514421457013639621509962613332324662222154683066173937658495362448733162728817642341239457485221865493926211958117034923747221236176204216845182311004742474549095130306550623190917480615151093941494688906907516349433681015204941620716162038586590895058816430264415335805881575305773073358135217732591500750773744464142282514963376379623449776844046465746330691788777566563856886778143019387464133144867446731438967247646981498812182658347753229511846953659235528803754112114516623201792727787856347729085966824435377279429992530935232902223909659507613583396967)


def get_signature(message):
	p.send('a sign\n')
	sleep(DELAY)
	p.recvuntil("to sign:")
	encoded_message = message.encode('base64').replace('\n','')+'\n'
	p.send(encoded_message)
	p.recvuntil("\n")
	sleep(DELAY)
	signature = p.recvuntil("\n")
	return signature

def send_command(signature, cmd):
	p.send(signature + ' ' + cmd + "\n")

def to_int(message):
	return int(message.encode('hex'),16)

def replace_backslashes(s, debug=True):
	done = False
	cursor = 0
	while not done:
		try:
			cursor = s.index('5c',cursor)
			if cursor % 2 == 0:
				s = s[0:cursor] + '5c5c' + s[(cursor+2):len(s)]
				cursor = cursor + 4
			else:
				cursor = cursor + 1
		except ValueError as e:
			if debug:
				log.info("cursor = " + str(cursor))
			done = True 
	return s

def escape_character(char, s, debug=True):
	done = False
	cursor = 0
	while not done:
		try:
			cursor = s.index(char,cursor)
			if cursor % 2 == 0:
				s = s[0:cursor] + '5c' + char + s[(cursor+2):len(s)]
				cursor = cursor + 4
			else:
				cursor = cursor + 1
		except ValueError as e:
			if debug:
				log.info("cursor = " + str(cursor))
			done = True 
	return s


def to_text(number, debug=True):
	tmp = hex(number)
	if debug:
		log.info("Starting to_text\n\n\n")
		log.info("number = " + str(number))
		log.info("tmp = " + tmp)
	if tmp[len(tmp)-1:len(tmp)]=='L':
		if debug:
			log.info("contains L")
		result = tmp[2:(len(tmp)-1)]
	else:
		result = tmp[2:len(tmp)]
	if debug:
		log.info("result = " + str(result))
	if len(result) % 2 == 1:
		result = '0' + result
	if debug:
		log.info("result = " + str(result))
	# Replace \\ with \\\ to make the string parsing work properly
	# This is buggy. Will only work half the time. Need to check that '5c' is
	# located at an even index for this to work...
	#result = replace_backslashes(result, debug=debug)
	# handle backslashes first since I'll be adding more backslashes
	result = escape_character('5c', result, debug=debug)
	result = escape_character('27', result, debug=debug) # single quote
	result = escape_character('22', result, debug=debug) # double quote
	# TODO: Double quotes too?

	# Return none if there's a newline or space or carriage return or tab.
	space_in_result = (find_hex_char_in_message('20',str(result),debug=debug) > -1)
	newline_in_result = (find_hex_char_in_message('0a',str(result),debug=debug) > -1)
	carriage_return_in_result = (find_hex_char_in_message('0d',str(result),debug=debug) > -1)
	tab_in_result = (find_hex_char_in_message('09',str(result),debug=debug) > -1)
	if debug:
		log.info("result = " + str(result))
		log.info("checking if there's a space or newline or carriage return.\n")
		log.info("Result of the space check is " + str(find_hex_char_in_message('20',str(result),debug=debug)))
		log.info("Result of the newline check is " + str(find_hex_char_in_message('0a',str(result),debug=debug)))
		log.info("Result of the carriage return check is " + str(find_hex_char_in_message('0d',str(result),debug=debug)))
		log.info("Result of the tab check is " + str(find_hex_char_in_message('09',str(result),debug=debug)))
	if space_in_result or newline_in_result or carriage_return_in_result or tab_in_result:
		return None

	if debug:
		log.info("result = " + str(result))
		log.info("returning " + binascii.unhexlify(result))
		log.info(str(len(binascii.unhexlify(result))))
		log.info(str(len(result)))
	return binascii.unhexlify(result)


def find_hex_char_in_message(char, message,debug=True):
	done = False
	cursor = 0
	while not done:
		try:
			cursor = message.index(char,cursor)
			if cursor % 2 == 0:
				return cursor
			else:
				cursor = cursor + 1
		except ValueError as e:
			if debug:
				log.info("cursor = " + str(cursor))
			done = True 
	return -1


def send_blind_attack(message, debug=True):
	message_failed_to_be_sent_correctly = True
	message_cannot_be_sent = True
	r = 319
	M = to_int(message)
	while message_failed_to_be_sent_correctly:
		while message_cannot_be_sent:
			r = r + 1
			mprime = mul(powmod(r,e,n),mpz(M)) % n
			if debug:
				log.info("r = " + str(r))
				log.info("M = " + str(M))
				log.info("m_prime = " + str(mprime))
			message2 = to_text(mprime, debug=debug)
			if debug:
				log.info("message2 = " + str(message2))
			if not message2 is None: # we didn't find '20' or '0a' or '0d' somewhere
				encoded_message = message2.encode('base64').replace('\n','')+'\n'
				if debug:
					log.info("message2 = " + str(message2))
					log.info("encoded_message = " + str(encoded_message))
				if '\r' not in encoded_message and \
					encoded_message.index('\n',0) == len(encoded_message)-1:
						message_cannot_be_sent = False
				else:
					if '\r' not in encoded_message and debug:
						log.info("carriage return not in the encoded message.\n")
					log.info("Location of first newline in encoded message: " + str(encoded_message.index('\n',0)) + "\n")
			else:
				log.info("Message cannot be sent because of presence of a space, newline character, or carriage return.\n")
			if not message_cannot_be_sent and debug:
				log.info("sending message2.\n")
		if debug:
			log.info("About to call get_signature.\n")
		sprime = get_signature(message2)
		if not ('No closing quotation' in sprime):
			message_failed_to_be_sent_correctly = False
		if debug:
			log.info("called get_signature.\n")
			log.info(str(len(message2)))
			log.info("sprime = " + str(sprime) + "\n")
		message_cannot_be_sent = True # Resetting the inner while loop
	if debug:
		log.info("sprime = " + sprime)
		log.info("sprime as a number = " + str(mpz(int(sprime))))
		if local:
			log.info("I think this should be " + str(pow(mprime, d, n)))
	# I had a bug that lay in converting mprime to text.
	result = divm(mpz(int(sprime)), r, n)
	#log.info("s1 = " + str(s1))
	#log.info("result = " + str(s2))
	return result

log.info("Starting debugging\n")
s1 = get_signature('exit')
#s1 = get_signature('exit')

log.info("s1 = " + s1)

if local:
	log.info("that should be equal to " + str(pow(int('exit'.encode('hex'),16),d,n)))


s2 = send_blind_attack("cat flag", debug=debug)
send_command(str(s2), "cat flag")
p.interactive()

