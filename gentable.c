#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "aes.h"

#define SIZE_128 16
#define SIZE_32 4				
#define CHAIN 100				//number of times a chain repeats

//Bit manioulation macros. CHAR_BIT = 8
#define CLEAR_BIT(array, n) (array[n/CHAR_BIT] &= ~(1 << (n%CHAR_BIT)) )
#define SET_BIT(array, n)   (array[n/CHAR_BIT] |=  (1 << (n%CHAR_BIT)) )
#define TEST_BIT(array, n)  (array[n/CHAR_BIT] &   (1 << (n%CHAR_BIT)) )
#define NUMBER_BYTES(bits_number) ((bits_number + CHAR_BIT - 1) / CHAR_BIT)

//Define struct used to write on the binary file rainbow
struct rainbow_data{  
    unsigned int key;
	unsigned char aes[SIZE_128];
};

//Get the maximum number of entries("lines") on rainbow file, so it satisfies the size restriction 2^s
unsigned long int maxNumLines(unsigned int, unsigned int);
//Pick the lowest-value key that haven't seen before
unsigned int getNextAvailableKey(char*, unsigned int, unsigned int);
//Receives a 32-bit key and return a 128-bit key left-padding from n to 128 bit
void getKey_128(unsigned char*, unsigned int, unsigned int);
//clear the whole 128 bits
void resetKey(unsigned char*);
//Reduce function: Reduce 128_bit key to n_bit key
unsigned int reduceKey(unsigned char*, unsigned int, unsigned int);


int main(int argc, char **argv)
{ 
	unsigned int n = 0;
	unsigned int s = 0;	
	
	//Check the info entered as arguments
	if ((argc != 0) && (argc != 3)) { printf("./gentable n <paswword length in bits> s <bound on thie size of rainbow>\n"); exit(1); }
	else if(argc == 3) {
		if((sscanf (argv[1], "%i", &n)!=1) || (n<0 || n>32)) { printf("Invalid value of n\n"); exit(1); }
		if((sscanf (argv[2], "%i", &s)!=1) || (s<0 || s>32)) { printf("Invalid value of s\n"); exit(1); }
		if((n-s) > 10) { printf("n-s > 10 or s>n\n"); exit(1); }	
	}

	/********CREATE FILE rainbow****/
	FILE *file_rainbow; 
	file_rainbow=fopen("rainbow","w");  
	if(file_rainbow  == NULL) {
 		perror("Writting error");
        exit(1);
	}  
	struct rainbow_data my_rainbow;						//Use to acced the binary file rainbow
 		
	/********CREATE KEYS BITMAP ****/
	//Calculate size of bitmap
	unsigned int max = (1<<n);							//max = 2^n
	char *key_bitmap = (char*) calloc(max, 1);			//Keeps track of all generated keys to avoid collisions
	char *aes_key_bitmap = (char*) calloc(max, 1);		//Keeps track only of first keys on a chain

	/********Data for AES*******/
	aes_context _aes;
	unsigned char plaintext[SIZE_128] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char key_128[SIZE_128] =   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	
	unsigned char ciphertext[16];   	
   	
	//********Data for main loop*******/
	unsigned int key_32 = 0;							//key generated on a chain
	unsigned int first_key_32 = 0;						//first key of the chain
	unsigned int count_keys=0;							//keeps track of the number of all keys generated
	unsigned int count_keys_aes = 0;					//keeps track of the number of first key of the chain
	
	/********MAIN LOOP: calculate and store Key=H(Key) on rainbow file*******/
	//Get the maximum number of times AES is procesed to satisfies the size restriction	2^s. If the space on rainbow is filled, then the loop ends
	unsigned long int num_lines = (unsigned long int) maxNumLines(n, s);
	unsigned long int count_lines;	
	for(count_lines=0; count_lines<num_lines; count_lines++) {
		//If the number of "first keys on a chain" reach the maximum number of password allowed (2^n - 1), break the loop, even before fullfill the maximum size on rainbow
		if(count_keys_aes==max)
			break;
			
		//each time the key_bitmap is full, check if theres is still space on the file rainbow.
		//if there is space, copy the bitmap aes_key_bitmap into key_bitmap. 
		//This mechanism allowed me, to star a new round looking fullfill the maximum number of password allowed (2^n - 1). If the space on rainbow is filled first, 
		//then the loop ends
		if(count_keys==max) {
			int i;	
			for(i=0; i<NUMBER_BYTES(max); i++)	
				key_bitmap[i] = aes_key_bitmap[i];
			
			//reset variables
			key_32 = 0;
			first_key_32 = 0;		
			count_keys = 0;
		}
			
		//get the first key on the chain
		first_key_32 = getNextAvailableKey(key_bitmap, first_key_32, max);
		
		//key_32 keep track of keys on the chain
		key_32 = first_key_32;
		count_keys++;

		/*********AES - REDUCTION CHAIN********/
		unsigned int i;
		for(i=0; i<CHAIN; i++) {
			//left-padd the key to use aes
			getKey_128(key_128, key_32, n);
   			
			//AES - Encrypt  
			memset(ciphertext, 0, 16);   	
   			aes_setkey_enc(&_aes, key_128, 128);
   			aes_crypt_ecb(&_aes, AES_ENCRYPT, plaintext, ciphertext);
   			
   			//******REDUCE
   			key_32 = reduceKey(ciphertext, n, i);
   			
   			///*****CHECK IF KEY IS ALREADY TAKEN
   			//If key_32 has NOT been taken, then take it
			if(!TEST_BIT(key_bitmap, key_32)) {
				SET_BIT(key_bitmap, key_32);
				count_keys++;
			}
			else  //If key_32 is already on the key_bitmap, then break the chain
				break;
   		}
   		
		//After chain finishes, store first key in the aes_keys_bitmap
		if(!TEST_BIT(aes_key_bitmap, first_key_32)) {
			//Update aes_key_bitmap with the new first key in the chain and counter of first keys
			SET_BIT(aes_key_bitmap, first_key_32);
			count_keys_aes++;
			
			/*******RAINBOW FILE*******/
			//Store the value in the data structure prior to store the info on the binary file rainbow
			my_rainbow.key=first_key_32;
			int j;
       		for(j=0; j<SIZE_128; j++)
				my_rainbow.aes[j] = ciphertext[j];
			
			//write Data on the rainbow document
			fwrite(&my_rainbow, sizeof(struct rainbow_data), 1, file_rainbow); 	
		}
	}
	
	fclose(file_rainbow); 	
	free(key_bitmap);
	printf("\n");	
	return 0;
}


//Get the maximum number of times AES is procesed to satisfies the size restriction	
unsigned long int maxNumLines(unsigned int n, unsigned int s) {	
	unsigned long int s2 = (1<<s);	
	unsigned long int num_lines = ((s2)*3*16)/(SIZE_32+SIZE_128);
	
	//printf("\nsize= %lu\n", s2*3*16);
	return(num_lines);
}

//Pick the lowest-value key that haven't seen before
unsigned int getNextAvailableKey(char *key_bitmap, unsigned int counter, unsigned int size) {	
   	while((TEST_BIT(key_bitmap, counter)) && counter<size-1)
   		counter++;

	//add key to the key_bitmap to keep track of the new key
   	if(!TEST_BIT(key_bitmap, counter))
		SET_BIT(key_bitmap, counter);
	
	return counter;
}

//Receives a 32-bit key and return a 128-bit key left-padding from n to 128 bit
void getKey_128(unsigned char *key_128, unsigned int key, unsigned int n) {    	
	unsigned char byte;
	
	//Put zeros in key_128 for the next key. Must do it. cause getKey_128 method only change first 32bits
	resetKey(key_128); 
	
	//Converts the integer key(32 bit long) to an array of unsigned char because aes requires it. 
	int cont = SIZE_128-1;
	while (key > 0) {
		byte = key & 0xFF;
		key_128[cont] = byte;
		cont--;
		key = key >> 8;
	}        
}

//clear the whole 128 bits
void resetKey(unsigned char *key_128) {
	int i;
	for(i=0; i<SIZE_128; i++)
		key_128[i] = 0x00;
}

//Reduce function: Reduce 128_bit key to n_bit key
unsigned int reduceKey(unsigned char *key_128, unsigned int n, unsigned int position) {
	int i, j;
	unsigned int k = 3;								//use to compute R(key_128, position) = (key_128 + (position % k)) % (2^n)
	unsigned char str_32[SIZE_32];
	
	//Get the first 32 bits of kye_128
	for(i=SIZE_128-SIZE_32, j=0; i<SIZE_128; i++, j++)
		str_32[j] = key_128[i];

	//Convert each hexadecimal value on the char array to character ASCII and concatenate all in a single string call str
	unsigned char str[SIZE_32+1];
	strcpy (str, "");
	char character[2];
	strcpy (character, "");
	
	for(i=0; i<SIZE_32; i++) {
		sprintf(character,"%X", str_32[i]);
		strcat(str, character);	
	}
	
	//Convert the string str to unsigned int number
	char *ptr;
	unsigned int key_32 = strtoul(str, &ptr, 16L);
	
	/******R(key_128, position) = (key_128 + (position % k)) % (2^n)***/
	key_32 = key_32 + (position % k);
	//At this point key_32 = (key_128 + (position % k)), so we need to key_32 = key_32  % (2^n)
	
	//key_32 % 2^n --> Lef-padd bits from 32bit to nbit
	for(i=n; i<SIZE_32*8; i++)
		key_32 &= ~(1 << i);
		
	return key_32;
}
