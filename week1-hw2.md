# COSC 169: Basics of Reverse Engineering
## Week 1 Homework 2
### Author: Fei Guo

## 1. First program

1. I use Babylon machines and below we can see the executable is ELF-64bit and the architecture is x86-64.
```sh
first: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b28fcb542af221459b48cbb0c70c7407ab90cfa2, not stripped
```

2. Here is the disassembly of `main`
```ass
000000000000063a <main>:
 63a:	55                   	push   %rbp
 63b:	48 89 e5             	mov    %rsp,%rbp
 63e:	48 83 ec 10          	sub    $0x10,%rsp
 642:	89 7d fc             	mov    %edi,-0x4(%rbp)
 645:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
                                ### Put addr of the 'hello...' string to %rdi
 649:	48 8d 3d 94 00 00 00 	lea    0x94(%rip),%rdi        # 6e4 <_IO_stdin_used+0x4>
 650:	e8 bb fe ff ff       	callq  510 <puts@plt>
 655:	b8 00 00 00 00       	mov    $0x0,%eax             ### Return 0
 65a:	c9                   	leaveq 
 65b:	c3                   	retq   
 65c:	0f 1f 40 00          	nopl   0x0(%rax)
```

3. See above. My annotation convention: 
   0) Annotations start with `###`
   1) Annotations are pre-comments or eol comments

4. Here is the disassembly of `.rodata`:
```
00000000000006e0 <_IO_stdin_used>:
 6e0:   01 00                   add    %eax,(%rax)
 6e2:   02 00                   add    (%rax),%al
 6e4:   48                      rex.W
 6e5:   65 6c                   gs insb (%dx),%es:(%rdi)
 6e7:   6c                      insb   (%dx),%es:(%rdi)
 6e8:   6f                      outsl  %ds:(%rsi),(%dx)
 6e9:   20 77 6f                and    %dh,0x6f(%rdi)
 6ec:   72 6c                   jb     75a <__GNU_EH_FRAME_HDR+0x66>
 6ee:   64                      fs
 6ef:   2e                      cs
        ...
```
5. As stated in the man page of `objdump`:
```
-D        --disassemble-all
       Like -d, but disassemble the contents of all sections, not just those expected to contain instructions. This option also has a subtle effect on the disassembly of instructions in code sections.  When option -d is in effect objdump will assume that any symbols present in a code section occur on the boundary between instructions and it will refuse to disassemble across such a boundary.  When option -D is in effect however this assumption is supressed.  This means that it is possible for the output of -d and -D to differ if, for example, data is stored in code sections.
```
6. The hex value of the string is `48656c6c 6f20776f 726c642e 00`, which translate to 'Hello, world.', which can also be confirmed by: 
 ```sh
 f004q67@babylon4:~/re/RE-basics-W22/homework2$ objdump -s -j .rodata first
first:     file format elf64-x86-64
Contents of section .rodata:
 06e0 01000200 48656c6c 6f20776f 726c642e  ....Hello world.
 06f0 00                                   .               
 ```

## 2. Second Program
The assembly code of `main` from `second-fast` and `second-small` look very similar, thus equally easy (or not so easy) to understand. 
What I found most confusing is their use of %rbp register for storing the addr of the format string.

Here is the assembly opf `main` from `second-fast`:
```
0000000000000560 <main>:
 560:   55                      push   %rbp
 561:   53                      push   %rbx
 562:   48 8d 2d db 01 00 00    lea    0x1db(%rip),%rbp        # 744 <_IO_stdin_used+0x4>
 569:   31 db                   xor    %ebx,%ebx
 56b:   48 83 ec 08             sub    $0x8,%rsp
 56f:   90                      nop
 570:   89 d9                   mov    %ebx,%ecx
 572:   89 da                   mov    %ebx,%edx
 574:   31 c0                   xor    %eax,%eax
 576:   0f af cb                imul   %ebx,%ecx
 579:   48 89 ee                mov    %rbp,%rsi
 57c:   bf 01 00 00 00          mov    $0x1,%edi
 581:   83 c3 01                add    $0x1,%ebx
 584:   e8 b7 ff ff ff          callq  540 <__printf_chk@plt>
 589:   83 fb 0a                cmp    $0xa,%ebx
 58c:   75 e2                   jne    570 <main+0x10>
 58e:   48 83 c4 08             add    $0x8,%rsp
 592:   31 c0                   xor    %eax,%eax
 594:   5b                      pop    %rbx
 595:   5d                      pop    %rbp
 596:   c3                      retq   
 597:   66 0f 1f 84 00 00 00    nopw   0x0(%rax,%rax,1)

```
Here is the assembly of `main` from `second-small`:
```
0000000000000560 <main>:
 560:   55                      push   %rbp
 561:   53                      push   %rbx
 562:   48 8d 2d cb 01 00 00    lea    0x1cb(%rip),%rbp        # 734 <_IO_stdin_used+0x4>
 569:   31 db                   xor    %ebx,%ebx
 56b:   48 83 ec 08             sub    $0x8,%rsp
 56f:   89 d9                   mov    %ebx,%ecx
 571:   89 da                   mov    %ebx,%edx
 573:   31 c0                   xor    %eax,%eax
 575:   0f af cb                imul   %ebx,%ecx
 578:   48 89 ee                mov    %rbp,%rsi
 57b:   bf 01 00 00 00          mov    $0x1,%edi
 580:   ff c3                   inc    %ebx
 582:   e8 b9 ff ff ff          callq  540 <__printf_chk@plt>
 587:   83 fb 0a                cmp    $0xa,%ebx
 58a:   75 e3                   jne    56f <main+0xf>
 58c:   5a                      pop    %rdx
 58d:   31 c0                   xor    %eax,%eax
 58f:   5b                      pop    %rbx
 590:   5d                      pop    %rbp
 591:   c3                      retq   
 592:   66 2e 0f 1f 84 00 00    nopw   %cs:0x0(%rax,%rax,1)
 599:   00 00 00 
 59c:   0f 1f 40 00             nopl   0x0(%rax)
```

## Third Program

Here is the pre-commented disassembly of `guess`:
```

                             guess                                           XREF[1]:     main:100003f1f(c)  
                                push %rbp onto the stack
       100003eb0 55              PUSH       RBP
                                store %rsp in %rbp
       100003eb1 48 89 e5        MOV        RBP,RSP                                          
                                stack pointer decrease by 0x10, 
       100003eb4 48 83 ec 10     SUB        RSP,0x10                                         
                                store g in the location of [rbp + local_c]
       100003eb8 89 7d fc        MOV        dword ptr [RBP + local_c],g                      
                                compare g's value with 0x2a
       100003ebb 83 7d fc 2a     CMP        dword ptr [RBP + local_c],0x2a                   
                                jump to Not_Equal if they are not equal
       100003ebf 0f 85 13        JNZ        Not_Equal                                        
                 00 00 00
                                put the addr of "That's right!\n" in %rdi
       100003ec5 48 8d 3d        LEA        g,[s_That's_right!_100003f70]                    
                 a4 00 00 00
                                set %al to 0 (since no floating point arguments for printf)
       100003ecc b0 00           MOV        AL,0x0                                           
                                call printf function
       100003ece e8 73 00        CALL       __stubs::_printf                                 
                 00 00
                                jump to the end of conditional
       100003ed3 e9 0e 00        JMP        Conditional_End                                  
                 00 00
                             Not_Equal                                       XREF[1]:     100003ebf(j)  
                                put the addr of the "Nope..." string to %rdi
       100003ed8 48 8d 3d        LEA        g,[s_Nope,_that's_the_wrong_number._100003f7f]   
                 a0 00 00 00
                                zero out %AL, since no floating point arguments passed
       100003edf b0 00           MOV        AL,0x0                                           
                                call library function printf
       100003ee1 e8 60 00        CALL       __stubs::_printf                                 
                 00 00
                             Conditional_End                                 XREF[1]:     100003ed3(j)  
                                dealloc the 16-byte local space
       100003ee6 48 83 c4 10     ADD        RSP,0x10                                        
                                restore %rbp's value 
       100003eea 5d              POP        RBP                                              
                                transfer control to caller       
       100003eeb c3              RET          
```


