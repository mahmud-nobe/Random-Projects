'''
Name: Mahmudun Nobe
Collaborators: Dan Hoogasian
Sources: 1.) Lu, J. (2022). Information Structures with Python [PDF modules].
    	 2.) Burstein, A. (2022). Information Structures with Python [Lecture notes].
'''

import binascii
import csv
import random
from base64 import b64encode

from sqlalchemy import all_

'''
A Set of helper functions.

'''

def binary_to_string(n):
	# Helper function that will return ascii from binary
	# Use this to get the original message from a binary number
	return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()


def string_to_binary(string):
	# Helper function that will return binary from string
	# Use this to get a number from the message
	return int.from_bytes(string.encode(), 'big')


def binary_to_binary_string(binary):
	# Helper function that will return binary as a bit string from binary
	# Use this to convert the binary number into a string of 0s and 1s.
	# This is needed to generate the appropriate random key
	return bin(binary)[2:]


def binary_string_to_binary(bin_string):
	# Helper function that will return binary from a bit string
	# Use this to convert the random key into a number for calculations
	return int(bin_string, 2)


def get_random_bit():
	# Helper function that will randomly return either 1 or 0 as a string
	# Use this to help generate the random key for the OTP
	return str(random.randint(0, 1))


def read_message(filename = 'message.txt'):
	# Helper function that will read and process message.txt which will provide a good testing message
	message = ''
	f = open(filename, 'r')
	for line in f:
		message += line.replace('\n', ' ').lower()
	return message


class Cipher:

	def __init__(self):
		# Initialize the suite
		# In part 1 create letter_dict and inverse_dict
		# In part 3 create letter_heuristics and call self.read_csv()
		self.letter_dict = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7,
							'i': 8, 'j': 9, 'k': 10, 'l': 11, 'm': 12, 'n': 13, 'o': 14,
							'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19, 'u': 20,
							'v': 21, 'w': 22, 'x': 23, 'y': 24, 'z': 25, ' ': 26}
		self.inverse_dict = {v: k for k, v in self.letter_dict.items()}
		# self.letter_heuristics = {}
		# self.wordlist = []
		self.read_csv()

	def rotate_letter(self, letter, n):
		# Rotate a letter by n and return the new letter
		order = self.letter_dict[letter] + n
		return self.inverse_dict[order % 27]

	def encode_caesar(self, message, n):
		# Encode message using rotate_letter on every letter and return the cipher text
		encoded_message = ''
		for character in message:
			new_character = self.rotate_letter(character, n)
			encoded_message += new_character
		return encoded_message

	def decode_caesar(self, cipher_text, n):
		# Decode a cipher text by using rotate_letter the opposite direction and return the original message
		decoded_message = ''
		for character in cipher_text:
			new_character = self.rotate_letter(character, -n)
			decoded_message += new_character
		return decoded_message

	def read_csv(self, file_name = 'letter_frequencies.csv'):
		# Read the letter frequency csv and create a heuristic save in a class variable
		rating_dict = {}
		with open(file_name, 'r') as file:
			values = csv.reader(file)
			next(values)
			for row in values:
				rating_dict[row[0].lower()] = float(row[1])
		freq_sum = sum(rating_dict.values())
		rating_dict = {key: values / freq_sum for key, values in rating_dict.items()}
		self.rating_dict = rating_dict

	def score_string(self, string):
		# Score every letter of a string and return the total
		message_freq = {key: 0 for key, values in self.rating_dict.items()}
		for i in string:
			message_freq[i] += 1
		message_freq = {key: values / len(string) for key, values in message_freq.items()}
		score = []
		for i in self.rating_dict.keys():
			score.append(1-abs(self.rating_dict[i]-message_freq[i]))
		return sum(score[:-1])

	def crack_caesar(self, cipher_text):
		# Break a caesar cipher by finding and returning the most probable outcome
		all_scores = []
		for n in range(0,27):
			decoded = self.decode_caesar(cipher_text, n)
			all_scores.append(self.score_string(decoded))
		best_n = all_scores.index(max(all_scores))
		return self.decode_caesar(cipher_text, best_n)

	def encode_vigenere(self, message, key):
		# Encode message using rotation by key string characters
		encoded_message = ''
		key_repeated = [key[(i % len(key))] for i in range(len(message))]
		for character, letter in zip(message, key_repeated):
			new_character = self.rotate_letter(character, int(self.letter_dict[letter]))
			encoded_message += new_character
		return encoded_message

	def decode_vigenere(self, cipher_text, key):
		# Decode ciphertext using rotation by key string characters
		decoded_message = ''
		key_repeated = [key[(i % len(key))] for i in range(len(cipher_text))]
		for character, letter in zip(cipher_text, key_repeated):
			new_character = self.rotate_letter(character, -int(self.letter_dict[letter]))
			decoded_message += new_character
		return decoded_message

	def encode_otp(self, message):
		# Similar to a vernan cipher, but we will generate a random key string and return it
		numeric_message = string_to_binary(message)
		binary_message = binary_to_binary_string(numeric_message)
		random_bits = ''
		for i in range(len(binary_message)):
			random_bits += get_random_bit()
		key = binary_string_to_binary(random_bits)
		cipher_text = numeric_message ^ key
		return cipher_text, key

	def decode_otp(self, cipher_text, key):
		# XOR cipher text and key. Convert result to string
		decoded_cipher_text = cipher_text ^ key
		decoded_message = binary_to_string(decoded_cipher_text)
		return decoded_message

	def read_wordlist(self, file_name = "wordlist.txt"):
		# Extra Credit: Read all words in wordlist and store in list. Remember to strip the endline characters
		words = open(file_name, 'r').readlines()
		self.wordlist = [line.strip() for line in words]

	def crack_vigenere(self, cipher_text):
		# Extra Credit: Break a vigenere cipher by trying common words as passwords
		# Return both the original message and the password used
		self.read_wordlist()
		all_scores = []
		for word in self.wordlist:
			decoded = self.decode_vigenere(cipher_text, word)
			all_scores.append(self.score_string(decoded))
		#print(max(all_scores), all_scores[self.wordlist.index('smart')], all_scores[self.wordlist.index('stars')])
		password = self.wordlist[all_scores.index(max(all_scores))]
		message = self.decode_vigenere(cipher_text, password)
		print(max(all_scores))
		return message, password


if __name__ == '__main__':
	print("---------------------TEST CASES---------------------------")
	cipher_suite = Cipher()
	print("---------------------PART 1: CAESAR-----------------------")
	message = read_message()
	cipher_text = cipher_suite.encode_caesar(message, 5)
	print('Encrypted Cipher Text:', cipher_text)
	decoded_message = cipher_suite.decode_caesar(cipher_text, 5)
	print('Decoded Message:', decoded_message)
	print("------------------PART 2: BREAKING CAESAR------------------")
	cracked = cipher_suite.crack_caesar(cipher_text)
	print('Cracked Code:', cracked)
	print("---------------------PART 3: Vignere----------------------")
	password = 'dog'
	print('Encryption key: ', password)
	cipher_text = cipher_suite.encode_vigenere(message, password)
	print('Encoded:', cipher_text)
	decoded_message = cipher_suite.decode_vigenere(cipher_text, password)
	print('Decoded:', decoded_message)


	print("-----------------------PART 4: OTP------------------------")

	cipher_text, key = cipher_suite.encode_otp(message)
	decoded_message = cipher_suite.decode_otp(cipher_text, key)
	print('Cipher Text:', cipher_text)
	print('Generated Key:', key)
	print('Decoded:', decoded_message)

	print('---------PART 5: Breaking Vignere (Extra Credit)----------')
	password = 'secret'
	cipher_text = cipher_suite.encode_vigenere(message, password)
	cracked, pwrd = cipher_suite.crack_vigenere(cipher_text)
	print('Cracked Code:', cracked)
	print('Password:',pwrd)
