# CYBR460-Exam-1

**These are the read-me tasks - I've essentially narrowed down my broader explanations within the pdf I'll attach, here, and given the run command for each in Ubtunu Linux. You'll need to have the Cryptodome library as I used that for my cryptography.**

Link to it is here: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

~~~~~

Task 1: Run python3 task1.py for it and it will give the lost block (the one you cannot retrieve) along with blocks 1 and 2, which should give the same numbers from my screenshot, for each, based on my test and code. I've written comments within the code too explaining what each part does.

Task 2: Run python3 task2.py. It will run through, encrypt a ciphertext before corrupting two bytes within it. These two bytes break it for a bit before the loop eventually fixes it.

Task 3: Run python3 task3.py and it runs the program, ultimately forcing the byte into the plaintext block, scrambling Odin_Allfather_ (preceding block) but leaves Fenrir_the_wolf_ (targeted block) unscathed. Essentially it over-rules the block after.

Task 4: Run python3 task4.py and it runs through each of the 5 tests, accepting the first two, and denying the last three with each being a unique trial for it. 

Task 5: Run python3 task5.py which has the program run through, encrypting a plaintext for testing. It runs through two tests: One where the file is not tampered and the other, where it is. The first will allow it to work, the second catches it and it fails.

Task 6: Run python3 task6.py which runs the program. It runs through 4 tests, testing a valid message, a tampered message, a replay, and an out of order message. It should accept the first and deny the following three!
