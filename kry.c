#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "freq.h"

#define ALPHABET_SIZE 26

char *encode(int a, int b, char *text) {
    printf("Encoding with a=%d and b=%d, with text %s\n", a, b, text);
    int x = 0;
    char *encoded = malloc(strlen(text) * sizeof(char));

    for(unsigned i = 0; i < strlen(text); i++){ //ignore spaces in text
        if (text[i] >= 'A' && text[i] <= 'Z') {
            x = text[i] - 'A';
        } else if (text[i] >= 'a' && text[i] <= 'z') {
            x = text[i] - 'a';
        }
        char encoded_char = (a * x + b) % ALPHABET_SIZE + 'A';
        if(text[i] == ' '){
            encoded[i] = ' ';
            continue;
        }
        encoded[i] = encoded_char;
    }
    free(encoded);
    return encoded;
}

char *decode(int a, int b, char *text) {
    printf("Decoding with a=%d and b=%d, with text %s\n", a, b, text);
    int x = 0;
    char *decoded = malloc(strlen(text) * sizeof(char));

    int MI = 0; //multiplicative inverse
    for(int i= 0; i < a; i++){
        MI=((i*ALPHABET_SIZE)+1);
        if(MI % a == 0){
            break;
        }
    }
    MI=MI/a;
    for(unsigned i = 0; i < strlen(text); i++){ //ignore spaces in text
        if (text[i] >= 'A' && text[i] <= 'Z') {
            x = text[i] - 'A';
        } else if (text[i] >= 'a' && text[i] <= 'z') {
            x = text[i] - 'a';
        }else if (text[i] == ' '){
            decoded[i] = ' ';
            continue;
        }


        // printf("%c:%d ", text[i],x);
        char decoded_char = (MI * (x - b) % ALPHABET_SIZE);
        if (decoded_char < 0){
            decoded_char = decoded_char + ALPHABET_SIZE;
        }
        decoded_char = decoded_char + 'A'; 
        if(text[i] == ' '){
            decoded[i] = ' ';
            continue;
        }
        decoded[i] = decoded_char;
    }
    return decoded;
}



//function for frequency analysis, prints out the frequency of each character in the text
float *frequency(char *s){
    float *freq = malloc(ALPHABET_SIZE * sizeof(float));
    int i = 0;
    int j = 0;
    int count = 0;
    int len = strlen(s);
    for(i = 0; i < ALPHABET_SIZE; i++){
        for(j = 0; j < len; j++){
            if(s[j] == 'a' + i || s[j] == 'A' + i){
                count++;
            }
        }
        freq[i] = (float)count / len;
        count = 0;
    }
    return freq;
}


//function to make a substitution between 

char *nokey_decode(char *input, char *output) {
    FILE *input_fp, *output_fp;
    char encoded_text[255];
    char *decoded_text = NULL;

    input_fp = fopen(input, "r");
    output_fp = fopen(output, "w");

    if(input_fp == NULL) {
        printf("Error opening file %s\n", input);
        return NULL;
    }
    if (output_fp == NULL) {
        printf("Error creating output file.");
        return NULL;
    }

    while (fgets(encoded_text, sizeof(encoded_text), input_fp)) {
        
    }
    // fgets(encoded_text, 255, input_fp);
    fprintf(output_fp, "%s", encoded_text);
    printf("%s", encoded_text);

    int a_key[12] = {1,3,5,7,9,11,15,17,19,21,23,25};
    int b_key[25] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25};
    float min_error = 100;
    float error = 0.0;
    int right_a;
    int right_b;

    float czech_freq[] = {
    0.115,
    0.0187,  // b
    0.0187,  // c
    0.0125,  // d
    0.1975,  // e - 4
    0.0094,  // f
    0.0242,  // g
    0.0242,  // h
    0.0911,  // i - 8
    0.0019,  // j
    0.0405,  // k
    0.0361,  // l
    0.0345,  // m
    0.1045,  // n - 13
    0.0582,  // o
    0.0405,  // p
    0.0002,  // q
    0.0563,  // r
    0.0497,  // s
    0.0626,  // t
    0.0304,  // u
    0.013,   // v
    0.0006,  // w
    0.0193,  // x
    0.0016,  // y
    0.0214,  // z
};

  
    float *decoded_freq = malloc(ALPHABET_SIZE * sizeof(float));
    for(int i = 0; i < 12; i++){
        for(int j = 0; j < 25; j++){
            char *decoded_text = decode(a_key[i], b_key[j], encoded_text);

            printf("Decoded text: %s\n", decoded_text);
            decoded_freq = frequency(decoded_text);
       
            //calculate error as substraction of frequency analysis of input and frequency analysis of decoded_text and their sum
            error = 0;
            for(int k = 0; k < ALPHABET_SIZE; k++){
                error += fabs(czech_freq[k] - decoded_freq[k]);
                printf("Error: %f\n", error);
            }
            
            if(error < min_error){
                min_error = error;
                right_a = a_key[i];
                right_b = b_key[j];
            }
        }
    }
    printf("Min error: %f\n", min_error);
    printf("--Right a: %d\n", right_a);
    printf("--Right b: %d\n", right_b);

    fclose(input_fp);
    fclose(output_fp);

    decoded_text = decode(right_a, right_b, encoded_text);
    return decoded_text;
}


int main(int argc, char *argv[]){

    if(argc < 1){ 
        fprintf(stderr, "error: Wrong amount of arguments\n");
        return 0;
   }
    char *mode = argv[1];
    int a = 0;
    int b = 0;
    char *input_file = NULL;
    char *output_file = NULL;
    char *text_to_encode = "TOTO JE TAJNA ZPRAVA";//argv[6];
    char *text_to_decode = "MXMX IT MHIUH EAGHSH";//argv[6];
  

    for (int i = 2; i < argc; i += 2) {
        if (strcmp(argv[i], "-a") == 0) {
            a = atoi(argv[i+1]);
        } else if (strcmp(argv[i], "-b") == 0) {
            b = atoi(argv[i+1]);
        } else if (strcmp(argv[i], "-f") == 0){
            input_file = argv[i+1];
        } else if (strcmp(argv[i], "-o") == 0){
            output_file = argv[i+1];
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            return 1;
        }
    }
    char *encoded = NULL;
    char *decoded = NULL;

    if (strcmp(mode, "-e") == 0) {
        encoded = encode(a, b, text_to_encode);
        printf("Encoded text: %s\n", encoded);
    } else if (strcmp(mode, "-d") == 0) {
        decoded = decode(a, b, text_to_decode);
        printf("Decoded text: %s\n", decoded);
    } else if (strcmp(mode, "-c") == 0) {
        decoded = nokey_decode(input_file, output_file);
        printf("Decoded text: %s\n", decoded);
        return 1;
    } else {
        printf("Unknown mode: %s\n", mode);
        return 1;
    }
    return 0;
}