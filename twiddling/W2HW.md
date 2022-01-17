# RE Winter 22
# Week 2 Homework
## Fei Guo

1. TryCrackMe

We can see a call to `strncmp@plt `, which gives away how the program does the comparison. Set a break point and inspect the string arguments, and we get the magic number is: `34407373373234353336`.
```
f004q67@babylon4:~/re/RE-basics-W22/gdb_tutorial$ gdb trycrackme
(gdb) b main
Breakpoint 1 at 0x11b3
(gdb) run
Starting program: /thayerfs/home/f004q67/re/RE-basics-W22/gdb_tutorial/trycrackme 

Breakpoint 1, 0x00005555555551b3 in main ()
(gdb) disas
Dump of assembler code for function main:
........Omitted.......
   0x00005555555552c8 <+281>:   lea    -0x70(%rbp),%rcx
   0x00005555555552cc <+285>:   lea    -0xb0(%rbp),%rax
   0x00005555555552d3 <+292>:   mov    %rcx,%rsi
   0x00005555555552d6 <+295>:   mov    %rax,%rdi
   0x00005555555552d9 <+298>:   callq  0x555555555030 <strncmp@plt>
   0x00005555555552de <+303>:   test   %eax,%eax
........Omitted.......
   0x000055555555532a <+379>:   leaveq 
   0x000055555555532b <+380>:   retq   
End of assembler dump.
(gdb) b *0x00005555555552d9
Breakpoint 2 at 0x5555555552d9
(gdb) c
Continuing.

  _____          ___             _   __  __     
 |_   _| _ _  _ / __|_ _ __ _ __| |_|  \/  |___ 
   | || '_| || | (__| '_/ _` / _| / / |\/| / -_)
   |_||_|  \_, |\___|_| \__,_\__|_\_\_|  |_\___|
           |__/                                 
                       
Put the key: lorem

Breakpoint 2, 0x00005555555552d9 in main ()
(gdb) disas
Dump of assembler code for function main:
   ........Omitted.......
   0x00005555555552cc <+285>:   lea    -0xb0(%rbp),%rax
   0x00005555555552d3 <+292>:   mov    %rcx,%rsi
   0x00005555555552d6 <+295>:   mov    %rax,%rdi
=> 0x00005555555552d9 <+298>:   callq  0x555555555030 <strncmp@plt>
   0x00005555555552de <+303>:   test   %eax,%eax
   0x00005555555552e0 <+305>:   je     0x5555555552fd <main+334>
........Omitted.......
   0x000055555555532a <+379>:   leaveq 
   0x000055555555532b <+380>:   retq   
End of assembler dump.
(gdb) i r $rdi
rdi            0x7fffffffe400   140737488348160
(gdb) x/s $rdi
0x7fffffffe400: "lorem"
(gdb) x/s $rsi
0x7fffffffe440: "34407373373234353336"
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /thayerfs/home/f004q67/re/RE-basics-W22/gdb_tutorial/trycrackme 

Breakpoint 1, 0x00005555555551b3 in main ()
(gdb) c
Continuing.

  _____          ___             _   __  __     
 |_   _| _ _  _ / __|_ _ __ _ __| |_|  \/  |___ 
   | || '_| || | (__| '_/ _` / _| / / |\/| / -_)
   |_||_|  \_, |\___|_| \__,_\__|_\_\_|  |_\___|
           |__/                                 
                       
Put the key: 34407373373234353336

Breakpoint 2, 0x00005555555552d9 in main ()
(gdb) c
Continuing.
[+] Correct key![Inferior 1 (process 64327) exited normally]
```

2. Twiddling

By inspecting the decompiled main below, we can figure out that the program expects to read a string, covert the ascii numbers of these characters to `unsigned int`, and save them in a uint array of 32 elements. After the input passes the string length check (0x20 elements), the program starts mangling the string with `this_is_where_the_fun_begins`.
```c

undefined8 main(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  int local_c0;
  int local_bc;
  uint local_b8 [32];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Enter flag (e.g. flag{3x4mpl3_fl4g})");
  fgets(local_38,0x21,stdin);
  stod(local_38,local_b8);
  local_bc = 0;
  sVar1 = strlen(local_38);
  if (sVar1 == 0x20) {
    this_is_where_the_fun_begins(local_b8);
    for (local_c0 = 0; local_c0 < 0x20; local_c0 = local_c0 + 1) {
      if (*(uint *)(ENCRYPTED + (long)local_c0 * 4) == local_b8[local_c0]) {
        local_bc = local_bc + 1;
      }
    }
  }
  if (local_bc == 0x20) {
    printf("You did it! What a good reverser you are ;)\n");
  }
  else {
    printf("I\'m sorry little one\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
It doesn't directly string compare, so we need to figure out how the program mangles the input. But first, first set a breakpoint at `main` and see what `ENCRYPTED` has:
```
(gdb) x /32wc 0x5555555560a0
0x5555555560a0 <ENCRYPTED>:	50 '2'	51 '3'	104 'h'	107 'k'
0x5555555560b0 <ENCRYPTED+16>:	95 '_'	95 '_'	53 '5'	55 '7'
0x5555555560c0 <ENCRYPTED+32>:	108 'l'	50 '2'	95 '_'	98 'b'
0x5555555560d0 <ENCRYPTED+48>:	119 'w'	107 'k'	68 'D'	50 '2'
0x5555555560e0 <ENCRYPTED+64>:	50 '2'	50 '2'	51 '3'	50 '2'
0x5555555560f0 <ENCRYPTED+80>:	102 'f'	107 'k'	123 '{'	81 'Q'
0x555555556100 <ENCRYPTED+96>:	124 '|'	97 'a'	53 '5'	125 '}'
0x555555556110 <ENCRYPTED+112>:	79 'O'	124 '|'	98 'b'	54 '6'
```
Collect them to get: `23hk__57l2_bwkD22232fk{Q|a5}O|b6`.


After some Ghidra renaming and retyping, we get the decompiled `this_is_where_the_fun_begins`:
```c
void this_is_where_the_fun_begins(uint *inp)
{
  int iVar1;
  uint uVar2;
  int i;
  int j;
  uint local_c;
  
  for (i = 0; i < 4; i = i + 1) {
    swap(inp + POS[i * 8 + 2],inp + POS[i * 8 + 7]);
    swap(inp + POS[i * 8 + 4],inp + POS[i * 8 + 2]);
    swap(inp + POS[i << 3],inp + POS[i * 8 + 3]);
    for (j = 0; j < 8; j = j + 1) {
        local_c = inp[POS[j + i * 8]];
        iVar1 = bit_parity(local_c);
        if (iVar1 == 0) {
        	// Ghidra doesn't give this function a param. But it shouldn't matter if the line below is decompiled correctly:
        	// inp[POS[j + i * 8]] = local_c;
          reverse_middle_bits(&inp[POS[j + i * 8]]);
        }
        else {
          uVar2 = num_bit1(local_c);
          local_c = local_c ^ uVar2;
        }
        inp[POS[j + i * 8]] = local_c;
    }
    swap(inp + POS[i * 8 + 1],inp + POS[i * 8 + 3]);
    swap(inp + POS[i * 8 + 7],inp + POS[i * 8 + 6]);
    swap(inp + POS[i * 8 + 5],inp + POS[i * 8 + 1]);
  }

  return;
}
```
Here are what each function does:

1. `swap` (originally: ive_never_been_stung_by_a_wasp): swap two elements in an array
2. `bit_parity` (originally: parry_this_you_casual): get the parity of the number of 1s in the binary form of the number
3. `reverse_middle_bits` (originally: you_turn_my_world_around): get the bits between the leftmost 1 bit and rightmost 1 bit and reverse these bits
4. `num_bit1` (originally: mr_krabs_likes_his_money): get the number of 1s in the binary form of the number

Also, the functon heavily uses the global symbol POS as the offset of inp array, here is the content of POS:
```
int POS[] = {
0x12,0x1A,0xC,0x1D,
0x6,0x19,0x1F,0x1B,
0x1E,0xB,0x10,0x3,
0xE,0x2,0x1,0x8,
0x7,0xF,0x16,0x15,
0x4,0x13,0x17,0x18,
0x11,0x9,0x5,0x1C,
0xD,0xA,0x0,0x14
};
```

So we need to figure out how `this_is_where_the_fun_begins` changes the positions of these elements and translate them.

Take a look at the function, and we can make two guesses:

1. that each character will only be translated once, regardless of which position it ends in after swapping. 

2. The swapping will not erase an element, so every element in the original array will be processed.

We can verify this by isolating out the swap calls and reversing them in another function, and observe that we get back the original input array.
```c
void forward_swap(uint *inp)
{
  int iVar1;
  uint uVar2;
  int i;
  int j;
  uint local_c;
  
  for (i = 0; i < 4; i = i + 1) {
    swap(inp + POS[i * 8 + 2],inp + POS[i * 8 + 7]);
    swap(inp + POS[i * 8 + 4],inp + POS[i * 8 + 2]);
    swap(inp + POS[i << 3],inp + POS[i * 8 + 3]);
    swap(inp + POS[i * 8 + 1],inp + POS[i * 8 + 3]);
    swap(inp + POS[i * 8 + 7],inp + POS[i * 8 + 6]);
    swap(inp + POS[i * 8 + 5],inp + POS[i * 8 + 1]);
  }
  return;
}

void reverse_swap(uint *inp)

{
  int iVar1;
  uint uVar2;
  int i;
  int j;
  uint local_c;
  
  for (i = 3; i >= 0; i = i - 1) {
    swap(inp + POS[i * 8 + 5],inp + POS[i * 8 + 1]);
    swap(inp + POS[i * 8 + 7],inp + POS[i * 8 + 6]);
    swap(inp + POS[i * 8 + 1],inp + POS[i * 8 + 3]);
    swap(inp + POS[i << 3],inp + POS[i * 8 + 3]);
    swap(inp + POS[i * 8 + 4],inp + POS[i * 8 + 2]);
    swap(inp + POS[i * 8 + 2],inp + POS[i * 8 + 7]);
  }
  return;
}

int main() {
	uint inp[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	forward_swap(inp);
	print_32_decimal(inp);
	reverse_swap(inp);
	print_32_decimal(inp);
}
``` 

Now we isolate the translation (character mangling) part in the `this_is_where_the_fun_begins` function, and put it in a new function:
```c
void only_translate(uint *inp)
{
  int iVar1;
  uint uVar2;
  int i;
  int j;
  uint local_c;
  
  for (i = 0; i < 4; i = i + 1) {
      for (i = 0; i < 4; i = i + 1) {
      for (j = 0; j < 8; j = j + 1) {
      local_c = inp[POS[j + i * 8]];
      iVar1 = bit_parity(local_c);
      if (iVar1 == 0) {
        // reverse_middle_bits(&inp[POS[j + i * 8]]);
      }
      else {
        uVar2 = num_bit1(local_c);
        local_c = local_c ^ uVar2;
      }
      inp[POS[j + i * 8]] = local_c;
    }
  }
  }
  return;
}
```
Now we can inspect if the same character in different positions of the array will give different results, e.g, to check if the mapping is one to many:
```c
void print_one_to_many() {
    uint inp[32];

    for (int i = 32; i <= 127; i += 1) {
      for (int j = 0; j < 32; j++) {
        inp[j] = i;
      }      
      printf("Preimage:  ");      
      printf("%d; ", inp[0]);          

      this_is_where_the_fun_begins(inp); 

      printf("Image: ");
      int prev = -1;
      for (int i = 0; i < sizeof(inp)/sizeof(inp[0]); i++){
        if (inp[i] != prev) {          
          printf("%d, ", inp[i]);
          prev = inp[i];
        }
      }
      printf("\n");
    }
}
```
Fortunately, they are not one-to-many, but also not one-to-one, instead, it's many-to-one. For example, both 40 and 52 will map to 33. We can print the mapping via:
```c
void print_map() {
    uint inp[32];

    for (int i = 32; i <= 127; i += 32) {
      for (int j = i; j < i + 32; j++) {
        inp[j%32] = j;
      }      
      printf("Preimage:  ");
      for (int i = 0; i < sizeof(inp)/sizeof(inp[0]); i++){
          printf("%d\t", inp[i]);
      }
      printf("\n");
      only_translate(inp); 
      
      printf("Image   : ");
      for (int i = 0; i < sizeof(inp)/sizeof(inp[0]); i++){
          printf("%d\t", inp[i]);
      }
      printf("\n");
    }
}
```
So we get:
```
Preimage:  32	33	34	35	36	37	38	39	40	41	42	43	44	45	46	47	48	49	50	51	52	53	54	55	56	57	58	59	60	61	62	63	
Image   :  33	33	34	32	36	38	37	39	40	42	41	43	47	45	46	42	48	50	49	51	55	53	54	50	59	57	58	62	60	56	59	63	
Preimage:  64	65	66	67	68	69	70	71	72	73	74	75	76	77	78	79	80	81	82	83	84	85	86	87	88	89	90	91	92	93	94	95	
Image   :  65	65	66	64	68	70	69	71	72	74	73	75	79	77	78	74	80	82	81	83	87	85	86	82	91	89	90	94	92	88	91	95	
Preimage:  96	97	98	99	100	101	102	103	104	105	106	107	108	109	110	111	112	113	114	115	116	117	118	119	120	121	122	123	124	125	126	127	
Image   :  96	98	97	99	103	101	102	98	107	105	106	110	108	104	107	111	115	113	114	118	116	112	115	119	120	124	127	123	121	125	126	120	
```

To get all the possible preimage strings, we need to map the ENCRYPTED string through the mapping above and then `reverse_swap` each one of them. To do this we make use of a little python:
```python
# The decimal representation of the ENCRYPTED string:
encrypt = [50, 51, 104, 107, 95, 95, 53, 55, 108, 50, 95, 98, 119, 107, 68, 50, 50, 50, 51, 50, 102, 107, 123, 81, 124, 97, 53, 125, 79, 124, 98, 54]

preimages = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127]

images = [33, 33, 34, 32, 36, 38, 37, 39, 40, 42, 41, 43, 47, 45, 46, 42, 48, 50, 49, 51, 55, 53, 54, 50, 59, 57, 58, 62, 60, 56, 59, 63, 65, 65, 66, 64, 68, 70, 69, 71, 72, 74, 73, 75, 79, 77, 78, 74, 80, 82, 81, 83, 87, 85, 86, 82, 91, 89, 90, 94, 92, 88, 91, 95, 96, 98, 97, 99, 103, 101, 102, 98, 107, 105, 106, 110, 108, 104, 107, 111, 115, 113, 114, 118, 116, 112, 115, 119, 120, 124, 127, 123, 121, 125, 126, 120]

def print_all_rev_translated(start):

	d = {}
	for i, t in enumerate(images):
		if t not in d:
			d[t] = []
		d[t].append(preimages[i])

	possibles = []
	for e in start:
		possibles.append(d[e])

	import itertools
	print(len(list(itertools.product(*possibles))))
	for element in itertools.product(*possibles):
		print("{",end="")
		for e in element:
			print(e, end=",")
		print("},")

print_all_rev_translated(encrypt)
```

The output is surprisingly long, thus abbreviated:

```
2048 # The number of valid inputs
{49,51,109,104,95,95,53,52,108,49,95,97,119,104,68,49,49,49,51,49,102,104,123,82,121,98,53,125,76,121,97,54,},
{49,51,109,104,95,95,53,52,108,49,95,97,119,104,68,49,49,49,51,49,102,104,123,82,121,98,53,125,76,121,103,54,},
{49,51,109,104,95,95,53,52,108,49,95,97,119,104,68,49,49,49,51,49,102,110,123,82,121,98,53,125,76,121,97,54,},
{49,51,109,104,95,95,53,52,108,49,95,97,119,104,68,49,49,49,51,49,102,110,123,82,121,98,53,125,76,121,103,54,},
{49,51,109,104,95,95,53,52,108,49,95,97,119,104,68,49,49,49,51,55,102,104,123,82,121,98,53,125,76,121,97,54,},
{49,51,109,104,95,95,53,52,108,49,95,97,119,104,68,49,49,49,51,55,102,104,123,82,121,98,53,125,76,121,103,54,},
```

To be extra safe, we save them in an array of type `uint possible[2048][32]` and check it in C and print them as characters if they match (they should):
```c
void try_possible() {
  uint encrypt[32] = {50, 51, 104, 107, 95, 95, 53, 55, 108, 50, 95, 98, 119, 107, 68, 50, 50, 50, 51, 50, 102, 107, 123, 81, 124, 97, 53, 125, 79, 124, 98, 54};
  int found = 0;
  for (int k = 0; k < 2048; k++) {        
    reverse_swap(possible[k]);

    uint copy[32];
    cp_32(possible[k], copy);
    this_is_where_the_fun_begins(possible[k]); 
    if (check_equal(encrypt, possible[k])){
      found = 1;
      for (int i = 0; i < 32; i++){
        printf("%c", copy[i]);
      }
      printf("\n");
    }
  }        
  if (!found)
    printf("No luck...\n");;
}
```
And we get 2048 valid strings, some of which listed below:
```
flaa{1w1DL1h6_1h3_b1h4Ry_5y513m}
flag{1w1DL1h6_1h3_b1h4Ry_5y513m}
flaa{1w1DL1h6_1n3_b1h4Ry_5y513m}
flag{1w1DL1h6_1n3_b1h4Ry_5y513m}
flaa{1w7DL1h6_1h3_b1h4Ry_5y513m}
flag{1w7DL1h6_1h3_b1h4Ry_5y513m}
flaa{1w7DL1h6_1n3_b1h4Ry_5y513m}
flag{1w7DL1h6_1n3_b1h4Ry_5y513m}
flaa{1w1DL1h6_1h3_b1h4Ry_5y573m}
flag{1w1DL1h6_1h3_b1h4Ry_5y573m}
...
```

Okay, here comes the moment of truth:
```
f004q67@babylon4:~/re/RE-basics-W22/gdb_tutorial$ ./twiddling 
Enter flag (e.g. flag{3x4mpl3_fl4g})
flaa{1w7DL1h6_1h3_b1h4Ry_5y513m}
You did it! What a good reverser you are ;)
```

Compile and run 're.c' to print out all the valid strings.
