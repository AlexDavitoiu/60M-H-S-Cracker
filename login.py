import hashlib
import os
import time
import threading

class colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    WARNING = '\033[93m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def hash_password_line_from_file(filename,hash_to_crack,hash_type):
    


    with open(filename, encoding="utf8") as f:
        lines = f.read().splitlines()
        start = time.time()
        for line in lines:

            hash = hash_password(line,hash_type)

            if hash == hash_to_crack:
                end = time.time()
                #clear_screen()
                print (colors.OKGREEN + hash + ":" + line + colors.ENDC , end = "")
                print(colors.OKBLUE + " | Time: %s seconds" % round((end - start), 2) + colors.ENDC)
                #exit()
        print(colors.FAIL + " | Hash not found in worldlist" + colors.ENDC , end = "")
            

def hash_password(password,hash_type):
    if hash_type == "md5":
        return hashlib.md5(password.encode('utf-8')).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode('utf-8')).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode('utf-8')).hexdigest()


def main():
    choice = input("Please choose operation (hash[1]/crack[2]) : ")

    if choice == "1" or choice == "hash":

        hash_type = input("Please choose hash type (md5[1]/sha1[2]/sha256[3]/sha512[4]) : ")

        while True:
            password = input("Please input password: ")
            if hash_type == "1" or hash_type == "md5":
                print("Hashed password: " + hash_password(password,"md5"))
            elif hash_type == "2" or hash_type == "sha1":
                print("Hashed password: " + hash_password(password,"sha1"))
            elif hash_type == "3" or hash_type == "sha256":
                print("Hashed password: " + hash_password(password,"sha256"))
            elif hash_type == "4" or hash_type == "sha512":
                print("Hashed password: " + hash_password(password,"sha512"))
            

    elif choice == "2" or choice == "crack":


        file_choice = input("Please choose between a file with hashes or a single hash (file[1]/single[2]) : ")

        if file_choice == "1" or file_choice == "file":
            
            hash_file = input("Please input file with hashes: ")

            wordlist = input("Please input worldlist location: ")

            counter = 829

            with open(hash_file, encoding="utf8") as g:
                lines = g.read().splitlines()
                start = time.time()
                for line in lines:

                    hash_to_crack = line
                    hash = hash_password_line_from_file(wordlist,hash_to_crack,"sha1")
                    print(colors.WARNING + " | Progress: " + str(counter) + colors.ENDC)
                    counter += 1

        print(colors.FAIL + "Hash not found in worldlist" + colors.ENDC)

        wordlist = input("Please input worldlist location: ")
        
        hash_to_crack = input("Please input hash to crack: ")
        user = "test"
        if len(hash_to_crack) == 32:
            print (colors.FAIL + "Hash type: md5  -- Please wait..." + colors.ENDC)
            hash_password_line_from_file(user,wordlist,hash_to_crack,"md5")
        elif len(hash_to_crack) == 40:
            print (colors.FAIL + "Hash type: sha1  -- Please wait..." + colors.ENDC)
            hash_password_line_from_file(user,wordlist,hash_to_crack,"sha1")
        elif len(hash_to_crack) == 64:
            print (colors.FAIL + "Hash type: sha256  -- Please wait..." + colors.ENDC)
            hash_password_line_from_file(user,wordlist,hash_to_crack,"sha256")
        elif len(hash_to_crack) == 128:
            print (colors.FAIL + "Hash type: sha512  -- Please wait..." + colors.ENDC)
            hash_password_line_from_file(user,wordlist,hash_to_crack,"sha512")
        else:
            print("Hash type not supported")  

main()    