#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "aes.h" 

#define SIZE_128 16
#define SIZE_32 4 

//Bit manioulation macros. CHAR_BIT = 8
#define CLEAR_BIT(array, n) (array[n/CHAR_BIT] &= ~(1 << (n%CHAR_BIT)) )
#define SET_BIT(array, n)   (array[n/CHAR_BIT] |=  (1 << (n%CHAR_BIT)) )
#define TEST_BIT(array, n)  (array[n/CHAR_BIT] &   (1 << (n%CHAR_BIT)) )
#define NUMBER_BITS(number) ((number + CHAR_BIT - 1) / CHAR_BIT)

//Define boolean type
typedef int bool;
enum { false, true };

//Define struct used to write on the binary file rainbow
struct rainbow_data{  
    unsigned int key;
	unsigned char aes[SIZE_128];
};

//Traverse rainbow file looking for a match on the Ciphertext. Return true if there is a match, false otherwise
bool check_rainbow(char*, unsigned char*, unsigned int*, unsigned int);
//Receives a char array (string enter in arguments 0x...) and return an unsigend char array with the Ciphertext value
void getCiphertext(unsigned char*, unsigned char*);
//Compare two Ciphertext.. If both are equals return true, otherwise false
bool compareCiphertext(unsigned char*, unsigned char*);

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
	unsigned char plaintext[SIZE_128] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char key_128[SIZE_128] =   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};			
	unsigned char ciphertext[16];
	memset(ciphertext, 0, 16);
	unsigned char output[16];
	aes_context _aes;
	
	if ((argc != 0) && (argc != 4)) { printf("./crack n <paswword length in bits> s <bound on thie size of rainbow> ciphertext <ciphertext value>\n"); exit(1); }	
	else if(argc == 4) {
		if ((sscanf (argv[1], "%i", &n)!=1) || (n<0 || n>=32)) { printf("Invalid value of n\n"); exit(1); }
		if ((sscanf (argv[2], "%i", &s)!=1) || (s<0 || s>=32)) { printf("Invalid value of s\n"); exit(1); }
		
		unsigned char* input = argv[3];
		//converts input to a unsigned char array
		getCiphertext(input, ciphertext);	
	}

	/********CREATE KEYS BITMAP ****/
	//Calculate size of bitmap
	unsigned int max = (1<<n);							//max = 2^n
	char *key_bitmap = (char*) calloc(max, 1);			//Keeps track of all generated keys to avoid collisions

	//********Data for main loop*******/
	unsigned int key_32 = 0;							//key generated on a chain
	unsigned int count_keys=0;							//keeps track of the number of all keys generated
    unsigned int key[1];								//represent the key value if there is a match on the rainbow file
    
	//IF Password was Found on the rainbow			
    if(check_rainbow(key_bitmap, ciphertext, key, n)==true) {
    	//printf("\nFound in rainbow\n");
    	
    	/*********AES - SECTION********/
		//Perform aes - reduce chain until reach the hash entered as input and count the times it takes to reach that hash. 
		//You know the ciphertext is at some point on this chain
    	bool match=false;
    	key_32 = key[0];								//key[0] is the value of the key that matches the ciphertext entered in argv[3]
		int i = 0;
    	while(match==false) {
    		
    		//******AES
			//left-padd the key to use aes
			getKey_128(key_128, key_32, n);
   			
			//AES - Encrypt  
			memset(output, 0, 16);   	
   			aes_setkey_enc(&_aes, key_128, 128);
   			aes_crypt_ecb(&_aes, AES_ENCRYPT, plaintext, output);

   			if(compareCiphertext(ciphertext, output) == true)
   				match=true;
   			else
   				key_32 = reduceKey(output, n, count_keys);		//Reduce

			count_keys++;   			
   		}
	
    	printf("\nPassword is 0x%X. AES was evaluated %u times.\n", key_32, count_keys);
    }
    //Password NOT Found on the rainbow
    else {	
		//printf("\nNOT Found in rainbow\n");
	
    	/*********AES - SECTION********/
    	//Perform aes until reach a hash that math the hash entered as input and count the times it takes to reach that hash.
    	bool match=false;
    	key_32 = 0;
    	while(match==false) {
    		key_32 = getNextAvailableKey(key_bitmap, key_32, max);
    		
    		//******AES
			//left-padd the key to use aes
			getKey_128(key_128, key_32, n);
   			
			//AES - Encrypt  
			memset(output, 0, 16);   	
   			aes_setkey_enc(&_aes, key_128, 128);
   			aes_crypt_ecb(&_aes, AES_ENCRYPT, plaintext, output);
   			
   			if(compareCiphertext(ciphertext, output) == true)
   				match=true;
   			
			count_keys++;
    	}
    	printf("\nPassword is 0x%X. AES was evaluated %u times.\n", key_32, count_keys);
    }
    free(key_bitmap);
} 


//Receives a char array (string enter in arguments 0x...) and return an unsigend char array with the Ciphertext value
void getCiphertext(unsigned char *input, unsigned char *ciphertext) {
	int value;
	unsigned char buff[2];
	strcpy (buff, "");
	unsigned char character1, character2;
	int i,j;
	for(i=2, j=0; i<strlen(input); i+=2, j++) {
		sprintf(buff,"%c", input[i]);
		sscanf(buff, "%X", &value);
		character1 = (char) value;
		character1 <<= 4;
			
		sprintf(buff,"%c", input[i+1]);
		sscanf(buff, "%X", &value);
		character2 = (char) value;
			
		character1 |= character2;
		ciphertext[j] = character1;	
	}	
}

//Compare two Ciphertext.. If both are equals return true, otherwise false
bool compareCiphertext(unsigned char *cipher1, unsigned char *cipher2) {
	bool result = true;
	int i;
	for(i=0; i<SIZE_128; i++)
		if(cipher1[i]!=cipher2[i])
			result = false;
	return result;
}

//Traverse rainbow file looking for a match on the Ciphertext. Return true if there is a match, false otherwise
//While is traversing rainbow file adds the keys to key_bitmap to keep track of the known keys on crack.c
//The value of the key that matches the ciphertext is returned on the position zero of array "key" --> key[0]
bool check_rainbow(char *key_bitmap, unsigned char *ciphertext, unsigned int *key, unsigned int n) {	
	bool found = false;  

	//Create file rainbow
	FILE *file_rainbow; 
	file_rainbow=fopen("rainbow","r");  
	struct rainbow_data my_rainbow;	
	unsigned int key_32;
	
	if(file_rainbow != NULL) { 		
		int fcheck;
		int nmemb = 1;

 		//read binary file struct size at a time
 		while(nmemb == (fcheck = fread(&my_rainbow, sizeof(struct rainbow_data), nmemb, file_rainbow))) {
 			if(ferror(file_rainbow)) {
       	 		perror("Read error");
       	 		break;
   			}
   			
			if(compareCiphertext(ciphertext, my_rainbow.aes)==true) {
				found = true;		
				key[0] = my_rainbow.key;
			}
			else {
				key_32 = (unsigned int) my_rainbow.key;
				//Lef-padd bits from 32bit to nbit
				int i;
				for(i=n; i<SIZE_32*8; i++)
					key_32 &= ~(1 << i);
				
				if(!TEST_BIT(key_bitmap, key_32))
					SET_BIT(key_bitmap, key_32);
			}
 		}
 	}
 	fclose (file_rainbow);	
 	return found;
 }
 

//Pick the lowest-value key that haven't seen before
unsigned int getNextAvailableKey(char *key_bitmap, unsigned int counter, unsigned int size) {	
   	while((TEST_BIT(key_bitmap, counter)) && counter<size-1)
   		counter++;

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
