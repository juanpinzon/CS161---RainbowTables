# Rainbow Tables
CS 161 – Computer Security Instructor: Tygar 7 October 2014

## Notes
- Project is due on 14 October extended to 21 October 2014 at 3PM.
- Please work on this homework individually – no collaboration allowed.
- Please list your name, student ID, section, and TA at the top of your solution
- To submit your homework: please create a ~/hw4 directory in your class account. Create a tarball (including a Makefile and source code) entitled hw4.tar. Put your writeup in hw4.pdf. Run the command “submit hw4” from inside the ~/hw4 directory


## Assignment
In this assignment you will create a rainbow table and use it to “break” hash functions. You will write a program to generate a rainbow, a program to invert hashes using the rainbow table, you will prepare a write-up describing your strategy and you will invert three hashes.

We will use the following system to hash 𝑛-bit password: We will left-pad the password with 0s until it is 128-bits long, calling the result 𝑃. Then we will compute AES-128 using 𝑃 as a key on plaintext block of all zeros
        
        𝐻(𝑃)= 𝐴𝐸𝑆𝑃(0)
        
Thus, for the 12-bit password 𝑃=0xABC, the result should be

        𝐻(𝑃)= 0x970fc16e71b75463abafb3f8be939d1c

In this assignment, you may assume that 𝑛 is less than 32. You are given 𝐻(𝑃) and 𝑛 and must recover 𝑃. One way to do this would be to perform a brute-force attack using on the order of 2𝑛AES evaluations. Alternatively, you can pre-compute all 2𝑛possible hashes and then find 𝑃 in nearly constant time; this requires 𝑂(2𝑛) space. The goal of using a rainbow table is to do better. Success in this assignment requires finding an implementation that uses significantly less than 2𝑛time and space.

Both programs should be written in C (and should include an appropriate Makefile) and should run on the hive departmental machines. Use this implementation of AES: https://polarssl.org/aes-source-code

The first program is gentable. It takes two command-line arguments, and outputs to a file rainbow. The first command-line argument is the password length 𝑛 measured in bits. The second argument 𝑠 determines a bound on the size of rainbow; it must be no larger than 3×128×2𝑠bits (or 3×16×2^𝑠 bytes). (If you pre-computed all hashes, then 𝑠=𝑛). You may assume that 𝑛−𝑠≤10. You must meet this space limit to earn credit for the problem. You can use ls –l to check the size of your file.

The second program is crack. It takes three command-line arguments, and outputs to stdout. The first two command-line arguments are the same as for gentable (again, you may assume that 𝑛−𝑠≤10). The final argument is 𝐻(𝑃) in hex. When you run crack 𝑛 𝑠 𝐻(𝑃), you may assume that gentable 𝑛 𝑠 was previously run to generate rainbow. The output of crack includes two items: the password 𝑃 or “failure,” and the number of times AES was evaluated. Make sure your program accurately reports the number of AES evaluations; if this is not correct, you will not receive credit for the assignment. Thus running

        % gentable 12 12 
        % crack 12 12 0x970fc16e71b75463abafb3f8be939d1c

will give output

        Password is 0xABC. AES was evaluated 191 times
        
assuming that in this execution of crack, AES was actually evaluated 191 times.

You should include a 1-2 page writeup that describes your implementation, and gives a mathematical relationship between the space used by rainbow (which is proportional to 2𝑠) and the number of (expected) AES evaluation by crack. Your writeup should include a discussion of how you addressed the problem of collisions in your rainbow table chains. Finally, your writeup should include the inversions of the following three password challenges:

- A 20-bit password with hash 0xae60abdcb19d5f962a891044129d56d4
- A 24-bit password with hash 0xeb94f00c506705017ce61273667a0952
- A 28-bit password with hash 0xa2cf3f9d2e3000c5addea2d613acfda8

Project Specs [here](/specs/CS161-HW4.pdf)