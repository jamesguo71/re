/* Please use the H2HW.md doc in the same directory for explanation of the code */

#include <stdio.h>

typedef unsigned int uint;

int POS[] = {0x12,0x1A,0xC,0x1D,
0x6,0x19,0x1F,0x1B,
0x1E,0xB,0x10,0x3,
0xE,0x2,0x1,0x8,
0x7,0xF,0x16,0x15,
0x4,0x13,0x17,0x18,
0x11,0x9,0x5,0x1C,
0xD,0xA,0x0,0x14};

extern uint possible[2048][32];


int bit_parity(uint param_1)
{
  uint local_7c;
  uint local_6c;
  
  local_6c = 0;
  for (local_7c = param_1; local_7c != 0; local_7c = local_7c & local_7c - 1) {
    local_6c = local_6c ^ 1;
  }
  return local_6c;
}

void reverse_middle_bits(uint *param_1)

{
  uint local_c;
  
  local_c = 0;
  while (*param_1 != 0) {
    local_c = local_c << 1 | *param_1 & 1;
    *param_1 = (int)*param_1 >> 1;
  }
  *param_1 = local_c;
}

void swap(uint *x,uint *y)

{
  *x = *x ^ *y;
  *y = *y ^ *x;
  *x = *x ^ *y;
  return;
}


int num_bit1(uint param_1)

{
  uint local_1c;
  int ret;
  
  ret = 0;
  for (local_1c = param_1; local_1c != 0; local_1c = (int)local_1c >> 1) {
    ret = ret + (local_1c & 1);
  }
  return ret;
}


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

void print_one_to_many() {
    uint inp[32];

    for (int i = 32; i <= 127; i += 1) {
      for (int j = 0; j < 32; j++) {
        inp[j] = i;
      }      
      printf("PreImage:  ");      
      printf("%d; ", inp[0]);          

      this_is_where_the_fun_begins(inp); 

      printf("Image   : ");
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

void gen_assoc_array(uint original[96], uint transformed[96]) {

    uint inp[32];

    for (int i = 32; i <= 127; i++) original[i - 32] = i;

    for (int i = 32; i <= 127; i += 32) {

      for (int j = i; j < i + 32; j++) {
        inp[j%32] = j;
      }      

      only_translate(inp); 
      for (int j = i; j < i + 32; j++) {
        transformed[j- 32] = inp[j%32];        
      }      

    }
}

void print_assoc_array(uint original[96], uint transformed[96]) {
  for (int i = 0; i < 96; i++){
      printf("%d, ", original[i]);
  }
  printf("\n");
  for (int i = 0; i < 96; i++){
    printf("%d, ", transformed[i]);
  }
  printf("\n");
}

int check_equal(uint a[32], uint b[32]);

void cp_32(uint src[32], uint dest[32]){
  for (int i = 0; i < 32; i++)
    dest[i] = src[i];  
}

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

void print_rev_swapped(uint inp[32]) {
  uint cp[32];
  for (int i = 0; i < 32; i++)
    cp[i] = inp[i];

  reverse_swap(cp);

    for (int i = 0; i < 32; i++){
        printf("%d, ", cp[i]);
    }
    printf("\n");
}

void print_32_decimal(uint inp[32]) {
  for (int i = 0; i < 32; i++){
        printf("%d, ", inp[i]);
  }
  printf("\n");
}

void print_32_char(uint inp[32]) {
  for (int i = 0; i < 32; i++){
        printf("%c", inp[i]);
  }
  printf("\n");

}


int check_equal(uint encrypt[32], uint magic[32]) {
  int i;
  for (i = 0; i < 32; i++) {
    if (encrypt[i] != magic[i])
      break;
  }
  if (i == 32) {
    return 1;
  }
  return 0;
}

void meet_in_middle_test() {
  printf("Meet in middle...\n");
  uint magic[32] = {102, 108, 97, 103, 123, 49, 119, 49, 68, 76, 49, 104, 54, 95, 49, 104, 51, 95, 98, 49, 104, 52, 82, 121, 95, 53, 121, 53, 49, 51, 109, 125};
  uint encrypt[32] = {50, 51, 104, 107, 95, 95, 53, 55, 108, 50, 95, 98, 119, 107, 68, 50, 50, 50, 51, 50, 102, 107, 123, 81, 124, 97, 53, 125, 79, 124, 98, 54};
  reverse_swap(encrypt);
  only_translate(magic);

  if (check_equal(encrypt, magic)) {
      printf("Met in middle!\n");
  } else {
      printf("Comparison failed.\n")  ;
  }
  return;
}



int main()
{
    // uint inp[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    // uint ori_inp[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    // uint inp[32] = {102, 108, 97, 103, 123, 49, 119, 49, 68, 76, 49, 104, 54, 95, 49, 104, 51, 95, 98, 49, 104, 52, 82, 121, 95, 53, 121, 53, 49, 51, 109, 125};

    // print_map();

    // uint original[96];
    // uint transformed[96];
    // gen_assoc_array(original, transformed);
    // print_assoc_array(original, transformed);


    // print_one_to_many();

    // this_is_where_the_fun_begins(inp); 
    
    // meet_in_middle_test();
    try_possible();

    // uint encrypt[32] = {50, 51, 104, 107, 95, 95, 53, 55, 108, 50, 95, 98, 119, 107, 68, 50, 50, 50, 51, 50, 102, 107, 123, 81, 124, 97, 53, 125, 79, 124, 98, 54};
    // // print_rev_swapped(encrypt);


    // uint magic[32] = {102, 108, 97, 103, 123, 49, 119, 49, 68, 76, 49, 104, 54, 95, 49, 104, 51, 95, 98, 49, 104, 52, 82, 121, 95, 53, 121, 53, 49, 51, 109, 125};
    // print_32_decimal(magic);
    // forward_swap(magic);
    // print_32_decimal(magic);
    // reverse_swap(magic);
    // print_32_decimal(magic);
    // this_is_where_the_fun_begins(magic);
    // print_32_decimal(magic);
    // print_32_decimal(encrypt);

    // // print_32_char(magic);
    
    // // forward_swap(magic);
    // // print_32_char(magic);

    // // reverse_swap(magic);
    // // print_32_char(magic);

    // // this_is_where_the_fun_begins(magic);
    // // print_32_char(magic);

    // // print_32_char(encrypt);

    // printf("equal? %d\n", check_equal(magic, encrypt));



    // uint inp[32] = {55,51,109,110,95,95,53,52,123,55,95,103,119,110,68,55,55,55,51,55,108,110,102,93,121,98,53,114,91,121,103,54,};
    

    return 0;
}
