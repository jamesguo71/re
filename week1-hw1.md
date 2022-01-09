# COSC 169: Basics of Reverse Engineering
## Week 1 Homework 1
### Author: Fei Guo


## 1. C code for the given assembly listing

The following C code illustrates what the given assembly code is trying to accomplish. `sub_1161` takes one argument and checks if it is above 0xff, if so, it calls `sub_1149` with the given argument and an additional argument `0xdead`; otherwise it calls the same routine but with the second argument being `0xdood`. The value returned from `sub_1149` will be returned to the caller of `sub_1161`.

`sub_1149` simply computes the sum of its two arguments and return it.

```C
#include <stdio.h> 

int sub_1149(int a, int b) {
	return a + b;
}

int sub_1161(int a) {
	if (a <= 0xff) {
		return sub_1149(a, 0xdead);
	}
	else {
		return sub_1149(a, 0xd00d);
	}
}

int main() {
	int i;	
	scanf("%x", &i);	
	printf("your input: i = %x\n", i);
	printf("%x\n", sub_1161(i));

	return 0;
}
```

### 2. Test it out
Now we compile and run the program above, and give it some input to have a look at what it produces.

```sh
(base) james:Desktop/ $ ./a.out                                                              
50
your input: i = 50
defd
(base) james:Desktop/ $ ./a.out                                                              
200
your input: i = 200
d20d

```

### 3. Unfamiliar instructions
The instructions of `endbr64` and `leave` were new to me, and here is what I found on Intel's Manual:
`endbr64`
>

1. `leave`
>Releases the stack frame set up by an earlier ENTER instruction. The LEAVE instruction copies the frame pointer (in the EBP register) into the stack pointer register (ESP), which releases the stack space allocated to the stack frame. The old frame pointer (the frame pointer for the calling procedure that was saved by the ENTER instruction) is then popped from the stack into the EBP register, restoring the calling procedure’s stack frame.

Basically, it is equivalent to the following assembly (in AT&T syntax):
```Assembly
mov %rbp, %rsp
pop %rbp
```

2. `endbr64`
> Terminate an indirect branch in 64 bit mode.

This is part of Intel's Control-Flow Enforcement technology which offers hardware protection against Jump/Call-Oriented Programming and it says that:

> if the next instruction retired after an indirect JMP/CALL is not an ENDBR32 instruction in legacy and compatibility mode, or ENDBR64 instruction in 64-bit mode, then a #CP fault is generated. 








