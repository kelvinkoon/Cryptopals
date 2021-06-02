# https://cryptopals.com/sets/2/challenges/10
import sys

sys.path.append("../")
from shared_functions import *
from challenge09 import *
import base64

CHALLENGE10_FILEPATH = "utils/challenge10data.txt"
BLOCK_SIZE = 16
INPUT_KEY_STR = "YELLOW SUBMARINE"
INIT_VECTOR = b"\x00" * BLOCK_SIZE
EXPECTED_STR = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"


# Refer to https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
def encryptAES_CBCMode(
    input_bytes: bytes, init_vector_bytes: bytes, key_bytes: bytes
) -> bytes:
    """
    Returns the bytes encrypted using AES in CBC Mode
    Assume input_bytes can be evenly broken into 16 byte blocks

    :param input_bytes The byte array to be encrypted
    :param init_vector_bytes The initialization vector for CBC Mode
    :param key_bytes The key to initialize the cipher with
    """
    bytes_blocks = breakByteArrayIntoBlocks(input_bytes, BLOCK_SIZE)

    # Initialize the ciphertext with first block and initialization vector
    prev_block = init_vector_bytes
    ciphertext_block = b""

    for i in range(0, len(bytes_blocks)):
        curr_xor_block = decodeFixedXOR(bytes_blocks[i], prev_block)
        aes_ecb_encrypt_block = encryptAES_ECBMode(curr_xor_block, key_bytes)
        prev_block = aes_ecb_encrypt_block
        ciphertext_block += aes_ecb_encrypt_block

    return ciphertext_block


# Refer to https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
def decryptAES_CBCMode(
    input_bytes: bytes, init_vector_bytes: bytes, key_bytes: bytes
) -> bytes:
    """
    Returns the bytes decrypted using AES in CBC Mode
    Assume input_bytes can be evenly broken into 16 byte blocks

    :param input_bytes The byte array to be decrypted
    :param init_vector_bytes The initialization vector for CBC Mode
    :param key_bytes The key to initialize the cipher with
    """
    bytes_blocks = breakByteArrayIntoBlocks(input_bytes, BLOCK_SIZE)

    # Initialize the plaintext with first block and initialization vector
    prev_block = init_vector_bytes
    plaintext_block = b""

    for i in range(0, len(bytes_blocks)):
        if len(bytes_blocks[i]) != BLOCK_SIZE:
            # Pad to 16 bytes (not to be confused with PKCS#7 padding)
            # Last input block does not fill into 16 byte block
            num_padding = BLOCK_SIZE - len(bytes_blocks[i])
            bytes_blocks[i] += b"\x00" * num_padding

        aes_ecb_decrypt_block = decryptAES_ECBMode(bytes_blocks[i], key_bytes)
        curr_xor_block = decodeFixedXOR(aes_ecb_decrypt_block, prev_block)
        prev_block = bytes_blocks[i]
        plaintext_block += curr_xor_block

    return plaintext_block


def main():
    # Read file
    input_file = open(CHALLENGE10_FILEPATH, "r")
    base64_enc_str = input_file.read()
    # Decode from base64
    ascii_bytes = base64.b64decode(base64_enc_str)
    key_bytes = INPUT_KEY_STR.encode("utf-8")

    # Test AES CBC Mode decryption
    plaintext_bytes = decryptAES_CBCMode(ascii_bytes, INIT_VECTOR, key_bytes)
    assert plaintext_bytes.decode("utf-8").strip() == EXPECTED_STR.strip()

    # Test AES CBC Mode encryption by verifying identical bytes from encryption + decryption
    test_bytes = b"this is 16 bytes"
    ciphertext_bytes = encryptAES_CBCMode(test_bytes, INIT_VECTOR, key_bytes)
    plaintext_bytes = decryptAES_CBCMode(ciphertext_bytes, INIT_VECTOR, key_bytes)
    assert test_bytes == plaintext_bytes


if __name__ == "__main__":
    main()
