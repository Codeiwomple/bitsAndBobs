import hashlib
import numpy as np
import argparse
from getpass import getpass
from termcolor import colored


BLOCK_SIZE = 128
PLAIN_TEXT = ''
PASSWORD = ''
ROUNDS = 10


def Main():
    global PLAIN_TEXT
    global PASSWORD

    parser = argparse.ArgumentParser(description='Simple 128 bit AES encryption')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-e', '--encrypt', help='Encryption mode', action="store_true")
    mode.add_argument('-d', '--decrypt', type=str, help='Decryption mode')
    args = parser.parse_args()

    printBanner()

    if args.encrypt:
        # If encrypt mode selected:

        # Get text and password
        PLAIN_TEXT = input(colored("Enter text to be encrypted:\n\n", 'blue'))
        PASSWORD = getpass("\nEnter key")

        # prep the input and gen keys
        state = prep_input()
        round_Keys = generate_keys(PASSWORD)

        # Encrypt
        enc = encrypt(state, round_Keys)

        np.save('cText', enc)

        # Output
        print(
            f"Your ciper text:\n {colored(matricies_to_text(enc),'cyan')}\nhas been saved in cText.npy")

    else:
        # Decryption mode selected

        # Get user input:
        state = np.load(args.decrypt)
        PASSWORD = getpass("Enter key")

        # prep the input and gen keys
        round_Keys = generate_keys(PASSWORD)

        # Decrypt

        dec = decrypt(state, round_Keys)
        # Output
        print(f"Your plain text:\n\n{unpad(matricies_to_text(dec))}")

    """

    print(f"Plain: \n {state}")

    enc = encrypt(state, round_Keys)
    print(f"Cipher text: \n {matricies_to_text(state)}")

    dec = decrypt(enc, round_Keys)
    print(f"Dec: \n {dec}")

    print(unpad(matricies_to_text(dec)))
    """


def printBanner():
    simple = """
         _           _
     ___|_|_____ ___| |___
    |_ -| |     | . | | -_|
    |___|_|_|_|_|  _|_|___|
                |_|
                """

    aes = """
                         _______  _______  _______
                        |   _   ||       ||       |
                        |  |_|  ||    ___||  _____|
                        |       ||   |___ | |_____
                        |       ||    ___||_____  |
                        |   _   ||   |___  _____| |
                        |__| |__||_______||_______|
                """

    print(colored(simple, 'red'))
    print(colored(aes, 'green'))


def encrypt(state, round_Keys):
    # Initial Round
    for i, block in enumerate(state):
        state[i] = addRoundKey(state[i], round_Keys[0])

    # Main rounds
    for round in range(ROUNDS):
        for i, block in enumerate(state):
            # Sub Bytes
            for j, word in enumerate(state[i]):
                block[j] = subBytes(block[j])
            # Shift Rows
            state[i] = shiftRows(state[i])
            # Mix Columns
            state[i] = np.array(mix_columns(state[i]))
            # Add RK
            state[i] = addRoundKey(state[i], round_Keys[round])

    # Final round
    for i, block in enumerate(state):
        # Sub Bytes
        for j, word in enumerate(state[i]):
            block[j] = subBytes(block[j])
        # Shift Rows
        state[i] = shiftRows(state[i])
        # Add RK
        state[i] = addRoundKey(state[i], round_Keys[ROUNDS-1])
    return state


def decrypt(state, round_Keys):
    # undo Final round
    for i, block in enumerate(state):
        # Remove RK
        state[i] = addRoundKey(state[i], round_Keys[ROUNDS-1])
        # unShift rows
        state[i] = unShiftRows(state[i])
        # unSub bytes
        for j, word in enumerate(state[i]):
            block[j] = unSubBytes(block[j])

    # undo Main rounds
    for round in range(ROUNDS, 0, -1):
        for i, block in enumerate(state):
            # Remove RK
            state[i] = addRoundKey(state[i], round_Keys[round-1])
            # unMix Columns
            state[i] = mix_columns(block)
            state[i] = mix_columns(state[i])
            state[i] = mix_columns(state[i])
            # unShift Rows
            state[i] = unShiftRows(state[i])
            # unSub Bytes
            for j, word in enumerate(state[i]):
                block[j] = unSubBytes(block[j])

    # undo Initial round
    for i, block in enumerate(state):
        state[i] = addRoundKey(state[i], round_Keys[0])
    return state


################## MIX COLUMNS #####################################

def multiply_by_2(v):
    # https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
    s = v << 1
    s &= 0xff
    if (v & 128) != 0:
        s = s ^ 0x1b
    return s


def multiply_by_3(v):
    # https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
    return multiply_by_2(v) ^ v


def mix_column(column):
    # Method mixes and retuns a single column

    r = [
        multiply_by_2(column[0]) ^ multiply_by_3(
            column[1]) ^ column[2] ^ column[3],
        multiply_by_2(column[1]) ^ multiply_by_3(
            column[2]) ^ column[3] ^ column[0],
        multiply_by_2(column[2]) ^ multiply_by_3(
            column[3]) ^ column[0] ^ column[1],
        multiply_by_2(column[3]) ^ multiply_by_3(
            column[0]) ^ column[1] ^ column[2],
    ]
    return r


def mix_columns(block):
    # Method performs a binary matrix transformation similar to dot product
    # but using XOR.
    # Algo described here: https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns

    new_block = [[], [], [], []]
    for i in range(4):
        col = [block[j][i] for j in range(4)]
        col = mix_column(col)
        for i in range(4):
            new_block[i].append(col[i])
    return new_block

################## INPUT MINIP ###############


def prep_input():
    # Mathod takes the input text and organises it for calculations

    # Pad the plainText to fit into 128bit chunks
    PADDED_PLAIN_TEXT = pad(PLAIN_TEXT)

    # Fill 128bit matricies with the padded plain text
    return text_to_matricies(PADDED_PLAIN_TEXT)


def text_to_matricies(text):
    # Method to take in text, convert it to bytes and organise it into
    # nx4x4 matricies

    # Calculate matricies required (note already padded so divisable by 16 i.e bytes)
    n = int(len(text) / 16)

    # define matricies, populate and reshape
    matrix = np.array(bytearray(text, 'utf-8'), dtype=np.byte)
    matrix.shape = (n, 4, 4)

    return matrix


def matricies_to_text(matrix):
    # Mathod takes in the matricies of bytes and returns their text from

    return(str(bytes(matrix)))


def pad(text):
    # Method pads text so that bytes are divisable by blocksize
    # Uses ascii rep of required bytes as padding

    # Calc number of bytes required
    bytes_to_pad = (BLOCK_SIZE) - (len(text) % (BLOCK_SIZE))
    # Duplicate required number of times using ascii rep
    padding = chr(bytes_to_pad) * bytes_to_pad
    # Add padding to orginal text
    return text + padding


def unpad(text):
    # Method undoes the operation from the pad Method
    # Uses the last byte to determine how much to unpad

    # Retrieve last char (remeber bytes are preceded by b' and end in ' chars)
    last_char = text[len(text) - 2:len(text) - 1]
    # Get the ascii code of last char (used to determine padding required)
    bytes_to_remove = ord(last_char)
    # remove bytes and return (remeber bytes are preceded by b' and end in ' chars)
    return text[2:-bytes_to_remove-1]

################# KEY GEN ######################################


def generate_keys(password):
    # Method takes an md5 sum off the password and uses it to
    # generate a key for each round of encryption

    # Convert to bytearray
    passByte = bytearray(password, 'utf-8')

    # Create md5 hash and put into 4x4 matrix
    keys = np.array(list(hashlib.md5(passByte).digest())*ROUNDS)
    keys.shape = (ROUNDS, 4, 4)

    # Apply key gen algo
    for i in range(ROUNDS - 1):
        # Rotate last word in PR
        keys[i+1][0] = rotWord(keys[i][3], 1)
        # sub bytes of last word
        keys[i+1][0] = subBytes(keys[i+1][0])
        # XOR : first word PRK, current RK state, rcon(round)
        keys[i+1][0] = np.bitwise_xor(keys[i][0], keys[i+1][0], RCON[i])
        # XOR the other words in sequential order
        for j in range(1, 4):
            keys[i+1][j] = np.bitwise_xor(keys[i][j], keys[i+1][j-1])

    return keys


def rotWord(word, n):
    # Method rotates the given list (word) by n

    return np.roll(word, n)


def addRoundKey(block, key):
    # Method XORs each column of block with the same column of round key
    for i in range(4):
        for j in range(4):
            block[i][j] = block[i][j] ^ key[i][j]
    return block

################# SHIFT ROWS #####################################


def shiftRows(block):
    # Method takes 128bit block: 4x4 matrix and rotates each row by its index
    # ie first row rotate by 0, second rotate by 1 etc.

    for i in range(4):
        block[i] = np.roll(block[i], i)
    return block


def unShiftRows(block):
    # Method reverts the shiftRows function

    for i in range(4):
        block[i] = np.roll(block[i], -i)
    return block

################## SUB BYTES METHODS ############################


def subBytes(word):
    # Method uses a hardcoded  AES SBOX lookup tables and substitues
    # the value accordingly

    for i in range(len(word)):
        word[i] = lookup(word[i])
    return word


def unSubBytes(word):
    # Method reverses the subBytes function using a hard coded inverse SBOX

    for i in range(len(word)):
        word[i] = rev_lookup(word[i])
    return(word)


def lookup(byte):
    # Performs the substitution for the SBOX lookup
    x = byte >> 4
    y = byte & 15
    return SBOX[x][y]


def rev_lookup(byte):
    # Performs the substitution for the inverse SBOX lookup
    x = byte >> 4
    y = byte & 15
    return REV_SBOX[x][y]

################### MATRIX CONSTANTS##############################


RCON = np.array([[0x01, 0x00, 0x00, 0x00],
                 [0x02, 0x00, 0x00, 0x00],
                 [0x04, 0x00, 0x00, 0x00],
                 [0x08, 0x00, 0x00, 0x00],
                 [0x10, 0x00, 0x00, 0x00],
                 [0x20, 0x00, 0x00, 0x00],
                 [0x40, 0x00, 0x00, 0x00],
                 [0x80, 0x00, 0x00, 0x00],
                 [0x1b, 0x00, 0x00, 0x00],
                 [0x36, 0x00, 0x00, 0x00]])
SBOX = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]]
REV_SBOX = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]


]
if __name__ == '__main__':
    Main()
