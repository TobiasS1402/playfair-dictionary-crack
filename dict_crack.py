import ngram_score as ns
fitness = ns.ngram_score('english_quadgrams.txt')

"""
Author: Tobias Seijsener
Date: 10-09-2023
Description: A dictionary based attack on the Playfair cipher based on 20k most common Google searchwords.

References:
    - http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/
    - https://github.com/ViralPanda/PlayFair-Cracker
    - https://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html
    - https://github.com/first20hours/google-10000-english/blob/master/20k.txt
"""

def create_playfair_matrix(key):
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    matrix = []
    key = "".join(dict.fromkeys(key)) 
    key += alphabet

    for char in key:
        if char not in matrix:
            matrix.append(char)
    return matrix

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)

    if len(ciphertext) % 2 != 0:
        raise ValueError("Ciphertext length must be even.")

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]
        row1, col1 = divmod(matrix.index(char1), 5)
        row2, col2 = divmod(matrix.index(char2), 5)

        if row1 == row2:  # Same row
            plaintext += matrix[row1 * 5 + (col1 - 1) % 5]
            plaintext += matrix[row2 * 5 + (col2 - 1) % 5]
        elif col1 == col2:  # Same column
            plaintext += matrix[((row1 - 1) % 5) * 5 + col1]
            plaintext += matrix[((row2 - 1) % 5) * 5 + col2]
        else:  # Different rows and columns
            plaintext += matrix[row1 * 5 + col2]
            plaintext += matrix[row2 * 5 + col1]
    return plaintext

def decode_with_wordlist(ciphertext):
    f = open("20k.txt","r")
    stored_key = -10000
    lines = f.readlines()
    for line in lines:
        key = line.strip("\n").replace("j","i").lower()
        plaintext = playfair_decrypt(ciphertext, key)
        fitness_score = fitness.score(plaintext.upper())
        print(f"---CURRENT GUESS---\nKey: {key}\nFitness: {fitness_score}\nDecrypted Text: {plaintext}")
        if fitness_score > stored_key:
            stored_key = fitness_score
            cracked = f"Correct Key: {key}\nMeasured fitness: {stored_key}\nPlaintext: {plaintext}"
    print("✅ All dictionary words tried\n")
    print(f"{cracked}")

ciphertext = "ITVKONYSZSRGTZTIPOAPSWHIHTRMMONZRZSHBQSYSIUZNHGBURQZOPXUNOBNSNGYRNHAPVBZBGLATIPOACZBIFMZLABHYSGYBGZBEDFOITOERZHTACKPRHZGPZANDAOILGBHQRMXEGHOGHRKASBLIQPIASUXDBHQVACIKIFYSIUHCIHZATREANGBDIMXMKNUDAPAQIHOUHCIBUEPTPNGZNKIFMGRNOXMKLBHQWQKBNOFMQTIKABNAQITPNITVKHSANPYKMIRHNDBAQGBFOZSQAUHGXQOHIZXFVTFIBBHBSQAFCZY".lower()
decode_with_wordlist(ciphertext)
