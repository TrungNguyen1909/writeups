The binary loads the flag.txt to the memory and asks us to provide input.

Interesting things is that it loads to the same memory segment with the input.

Debugging locally, I found it at the offset 752 from the first input bytes.

Running it multiple times on the server and at sometimes, the null bytes will be all-cleared and puts will print it all.
