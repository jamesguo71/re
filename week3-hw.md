# RE Winter 22
## Homework 3
## Fei Guo

After decompiling the code in Ghidra, we can see that the constructor of `Encode` mallocs enough bytes for the first parameter (i.e, argv[1], refered as "shellcode" below) passed into the program, then `memcpy` all these bytes to the malloc'ed  memory. In addition, it saves the length of the shellcode in the second field of Encode object as well.

After that, `main` calls `Encode::decode`, which calls `Algorithm::algdecode`, in which all the functions calls point to the fact that this will decode the shellcode as Base64 encoded string.  Let's verify this first.

Get the base64 encoded string of my name:
```bash
(base) james:re-git/ (main*) $ echo -n "guofei" | base64                                                                            [16:34:08]
Z3VvZmVp
```
Then we fire up gdb with `gdb hw_w03_d01`, set a breakpoint after `algdecode()` returns:
```
(gdb) b main
(gdb) run Z3VvZmVp
Breakpoint 1, 0x0000555555556489 in main ()
(gdb) c
Continuing.

Breakpoint 6, 0x000055555555740a in Algorithm::algdecode() ()
(gdb) c
Continuing.

Breakpoint 7, 0x0000555555556543 in main ()
(gdb) x /10wx $rax
0x55555556ced0:	0x666f7567	0x00006965	0x00000000	0x00000000
0x55555556cee0:	0x00000000	0x00000000	0x0000f121	0x00000000
0x55555556cef0:	0x00000000	0x00000000
(gdb) x /10c $rax
0x55555556ced0:	103 'g'	117 'u'	111 'o'	102 'f'	101 'e'	105 'i'	0 '\000'	0 '\000'
0x55555556ced8:	0 '\000'	0 '\000'
(gdb) 
```
Not bad.

Now, we want to print out `SUCCESS`, so write a little assembly and save it to `writeSuccess.s`:
```asm
mov $0x1, %edi                      # Set %edi to 1 (file descriptor of stdout)
movabsq $0x0a53534543435553, %rax   # Put to %rax the little endian representation of "SUCCESS"
push %rax                           # Push %rax to stack
mov %rsp, %rsi                      # Put stack pointer to %rsi
mov $0x8, %rdx                      # Put the length of "SUCCESS" to $rdx
mov $0x1,%eax                       # write syscall is indexed at 1
syscall                             # Making the syscall
pop %rax                            # Pop the "SUCCESS" value from the stack
retq                                # return to last function
```
Then we `gcc -c writeSuccess.s` and `objdump -d writeSuccess.o`, to get the machine code of it, whic is:
```
bf 01 00 00 00      
48 b8 53 55 43 43 45
53 53 0a 
50                  
48 89 e6            
48 c7 c2 08 00 00 00
b8 01 00 00 00      
0f 05               
58                  
c3                 
```
Save it in "shell_hex.txt", and then `cat shell_hex.txt | xxd -r -p | base64` to get its base64 representation, which is 

`vwEAAABIuFNVQ0NFU1MAUEiJ5kjHwgcAAAC4AQAAAA8FWMM=`

Okay, here comes the moment of truth:
```
f004q67@babylon4:~/re/RE-basics-W22/homework3$ ./hw_w03_d01 vwEAAABIuFNVQ0NFU1MKUEiJ5kjHwggAAAC4AQAAAA8FWMM=
SUCCESS
f004q67@babylon4:~/re/RE-basics-W22/homework3$ 
```


