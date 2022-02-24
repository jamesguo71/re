# RE Winter 22: Midterm
### Fei Guo
### f004q67

## P1

For this one, I just used the 4q67-plain linux version (since the Game of Thrones version is not present).

By using strace or looking at the `eax` register values in the syscalls, we can easily grasp the syscalls made in the beginning: `stat` and `mprotect`.

With the auto-analysis of Ghidra we can see the program expects a `.probe` file, let's give it one:

`touch .probe`

And if given more arguments, we could see some special addresses, let's just give it:

`./4q67-plain 1 2`

```
f004q67@babylon2:~/re/RE-basics-W22/midterm/p1/4q67$ ./4q67-plain 1 2
************************************************************
* This program checks for certain condition(s) via syscalls *
************************************************************

Checking alignment... [49 0x55b5ea0807c3 0x55b5ea080989 0x55b5ea0809a6]
Some conditions are met, but not all! Exiting.
```

The alignment is not right. From the annotated C code below (and of course some time pondering the code), we can see that the number 49 will be used as the alignment. If it's not right, what else can be? Let's see the difference of the numbers in the previous output.
```
(base) james:ghidra_scripts/ $ python -c "print(0x55b5ea0809a6 - 0x55b5ea080989)"                                                   [22:39:27]
29
``` 

Is it so? Let's fire up GDB and change the value partway.

```

   0x5555555548ac                  shl    rax, 0x2
   0x5555555548b0                  sub    rcx, rax
   0x5555555548b3                  mov    rdx, rcx
 → 0x5555555548b6                  mov    BYTE PTR [rbp-0x21], dl
   0x5555555548b9                  cmp    DWORD PTR [rbp-0xc4], 0x2
   0x5555555548c0                  jg     0x5555555548d0
   0x5555555548c2                  lea    rdi, [rip+0x43a]        # 0x555555554d03
   0x5555555548c9                  call   0x555555554610 <puts@plt>
   0x5555555548ce                  jmp    0x5555555548fc

Breakpoint 2, 0x00005555555548b6 in ?? ()
gef➤  set $rdx = 29
gef➤  c
Continuing.
Checking alignment... [29 0x5555555547c3 0x555555554989 0x5555555549a6]
Congratulations, you've done it! Your token is SYSCALL_7647

```

Now the question is where does the 29 come from? This is initially where I was stuck and pushed to ask for a hint from Sergey.

Although the C pseudo-code looks clear, I didn't change the datatype of `local_c8` to `stat` in the beginning (Ghidra seems to omit `struct` in its type definitions). Why does this matter? Because Ghidra incorrectly thought that `local_c8` was 88 bytes long (`undefined mod60_from [88];`) which causes it to also miss the fact that the second parameter passed to `stat` syscall would be used later!

I fumbled around and finally learned it the hard way by touching and changing the .probe file. This is something I really shouldn't have missed but I did. It cost me hours.

> Rule: clean up the datatypes as best as you can!

Anyway, now we can see the seconds when the file is modified matters, let's touch it:

```bash
f004q67@babylon2:~/re/RE-basics-W22/midterm/p1/4q67$ touch -t 200001010101.29 .probe
f004q67@babylon2:~/re/RE-basics-W22/midterm/p1/4q67$ ./4q67-plain 
************************************************************
* This program checks for certain condition(s) via syscalls *
************************************************************

Checking alignment...
Congratulations, you've done it! Your token is SYSCALL_7647
```

Below is the main (offset: 7c3) function's annotated pseudo C code:

```c

void main(int first_arg,undefined8 second_arg)

{
  int iVar1;
  byte bVar2;
  ulong uVar3;
  long lVar4;
  code *some_Condtions_Met;
  undefined4 SIGSYS;
  undefined8 in_R9;
  stat local_c8;
  byte *end_of_token_bytep;
  byte *local_20;
  
  puts(
      "************************************************************\n* This program checks for certa in condition(s) via syscalls *\n************************************************************\n "
      );
  DAT_003020b8 = stat;
  mprotect = mprotect_func;
  iVar1 = stat(".probe",&local_c8);
  if (iVar1 != 0) {
    puts("Conditions are not met! Exiting.");
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  iVar1 = (*mprotect)(0x100000,0x1000,7);
  if (iVar1 == 0) {
    bVar2 = (char)local_c8.st_mtim.tv_sec + (char)(local_c8.st_mtim.tv_sec / 0x3c) * -0x3c;
    if (first_arg < 3) {
      puts("Checking alignment...");
    }
    else {
      printf("Checking alignment... [%d %p %p %p]\n",(ulong)bVar2,main,0x100989,&LAB_001009a6,in_R9,
             second_arg);
    }
    signal(0xb,Some_Condtions_Met);
    signal(7,Some_Condtions_Met);
    signal(4,Some_Condtions_Met);
    some_Condtions_Met = Some_Condtions_Met;
    SIGSYS = 0x1f;
    signal(0x1f,Some_Condtions_Met);
    end_of_token_bytep = &shellcode_start;
    uVar3 = (ulong)bVar2;
    local_20 = (byte *)(uVar3 + 0x100989);
    while (end_of_token_bytep < (byte *)0x3020a6) {
      uVar3 = (ulong)*end_of_token_bytep;
      *local_20 = *end_of_token_bytep;
      end_of_token_bytep = end_of_token_bytep + 1;
      local_20 = local_20 + 1;
    }
    syscall();
    _DT_INIT();
    lVar4 = 0;
    do {
      (*(code *)(&__DT_INIT_ARRAY)[lVar4])(SIGSYS,some_Condtions_Met,uVar3);
      lVar4 = lVar4 + 1;
    } while (lVar4 != 1);
    return;
  }
  perror("Sergey\'s syscall code failed. Tell Sergey!");
                    /* WARNING: Subroutine does not return */
  _exit(2);
}
```


## P2.

Here is the script I wrote:

```python
from ghidra.program.model.symbol import SourceType

# Assume _entry has been defined at 08000000
entry_addr = getGlobalFunctions('_entry')[0].getEntryPoint()

# >>> entry_addr
# 08000000

# The hexseq is the hex code for the four instructions we're looking for
hexseq = "01 00 2d e9 04 50 8f e2 00 00 15 e4 1e ff 2f e1" 	# function instruction count: 16
pointer_len = 4	# four bytes for the addresss following the instructions

code_len = len(hexseq.split())
total_len = code_len + pointer_len

# >>> find(entry_addr, "".join([chr(int(s, 16)) for s in hexseq.split()]))
# 08000354

LIMIT = 1000
all_matches = findBytes(entry_addr, "".join([chr(int(s, 16)) for s in hexseq.split()]), LIMIT)
# >>> len(all_matches)
# 171

for match in all_matches:
	# Make sure the pointer after the instruction is properly set up
    ptr_addr = match.add(code_len)   
    # Disassemble the code after the pointer
    limit_addr = match.add(total_len)
    
    # This wouldn't work, so stick to Sergey's demo
    # createData(ptr_addr, Pointer)
        
    createData(ptr_addr, getDataTypes('pointer')[0])
    # Get the actual address in the WRAM and put it into the function name
    pointer_val = getDataAt(ptr_addr).getValue().toString()

    func = getFunctionAt(match)
    if func is None:
        assert(disassemble(match))
        createFunction(match, "getter_" + pointer_val)
    else:
        cur_name = getFunctionAt(match).getName()
        if cur_name[:4] == 'FUN_':
            func.setName("getter_" + pointer_val, SourceType.USER_DEFINED)        

    assert(isinstance(getDataAt(ptr_addr).getDataType(), Pointer))
    assert(disassemble(limit_addr))

```

Running this, we get 171 getter functions.

Then let's fire up mGBA and capture some interesting positions.

1. Score

This one is easy. Just search for the score value in the memory and we can see only one result. Its address is: 02001fc0, so the global variable score resides in the address of 02001fc0. And so we rename the function at 0843e138 to `getter_score_02001fc0`.

2. Enemy count

24 enemies in the front-line in the beginning, so we search for this number in the memory and then kill one enemy and observe that the number does decrement. And it does. So 02001f9c is the enemy counter global variable. And we can name the function at 0843e084 to `getter_enemy_count_02001f9c`.

3. Mission Level

This one is the hardest among these three because there're a lot of 1's and 2's in the memory and I can't easily make it to level 3. But thanks to the memory tool of mGBA, we can get the address after a few tries. So we get the global variable of mission level resides in 020020d0. So we can change the function name at 0843e19c to `getter_missionlevel_020020d0`.


