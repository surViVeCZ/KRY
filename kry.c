//Date: 3.9.2023
//Author: Bc. Petr Pouček
//FIT VUT Brno
//KRY - 1. projekt

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "freq.h"

#define ALPHABET_SIZE 26
#define A_KEYS 12
#define B_KEYS 25

//encoding with key
char *encode(int a, int b, char *text) {
    int x = 0;
    char *encoded = malloc(strlen(text) * sizeof(char));

    for(unsigned i = 0; i < strlen(text); i++){ 
        if (text[i] >= 'A' && text[i] <= 'Z') {
            x = text[i] - 'A';
        }
        //using equation for affine cipher encoding
        char encoded_char = (a * x + b) % 26 + 'A';

        //ignoring spaces in text
        if(text[i] == ' '){
            encoded[i] = ' ';
            continue;
        }
        encoded[i] = encoded_char;
    }
    return encoded;
}

//decoding with key
char *decode(int a, int b, char *text) {
    int x = 0;
    char *decoded = malloc(strlen(text) * sizeof(char));

    //multiplicative inverse
    int MI = 0; 
    for(unsigned i = 0; i < a; i++){
        MI = ((i * ALPHABET_SIZE) + 1);
        if (MI % a == 0){
            break;
        }
    }

    MI=MI/a;
    for(unsigned i = 0; i < strlen(text); i++){
        if (text[i] >= 'A' && text[i] <= 'Z') {
            x = text[i] - 'A';
        }else if(text[i] >= 'a' && text[i] <= 'z'){
            x = text[i] - 'a';
        }
        //ignoring spaces in text
        if (text[i] == ' '){
            decoded[i] = ' ';
            continue;
        }
        //using equation for affine cipher decoding
        char decoded_char = (MI * (x - b) % ALPHABET_SIZE);
        if (decoded_char < 0){
            decoded_char = decoded_char + ALPHABET_SIZE;
        }
        decoded_char = decoded_char + 'A'; 

        //ignoring spaces in text
        if(text[i] == ' '){
            decoded[i] = ' ';
            continue;
        }
        decoded[i] = decoded_char;
    }
    return decoded;
}

//calculates frequency of each character in given string
float *frequency(char *s){
    float *freq = malloc(ALPHABET_SIZE * sizeof(float));
    int count = 0;
    for(unsigned i = 0; i < ALPHABET_SIZE; i++){
        for(unsigned j = 0; j < strlen(s); j++){
            if(s[j] == 'A' + i || s[j] == 'a' + i){
                count++;
            }
        }
        freq[i] = (float)count / strlen(s);
        count = 0;
    }
    return freq;
}

//decoding without key using frequency analysis
char *nokey_decode(char *input, char *output) {
    FILE *input_fp, *output_fp;
    char encoded_text[255];
    char *decoded_text = NULL;

    input_fp = fopen(input, "r");
    output_fp = fopen(output, "w");

    if(input_fp == NULL) {
        fprintf(stderr, "Error opening file %s\n", input);
        return NULL;
    }
    if (output_fp == NULL) {
        fprintf(stderr, "Error creating output file.");
        return NULL;
    }
    
    char* content = fgets(encoded_text, 255, input_fp);
    if(content == NULL){
        fprintf(stderr, "Error reading file %s\n", input);
        return NULL;
    }

    int a_key[A_KEYS] = {1,3,5,7,9,11,15,17,19,21,23,25};
    int b_key[B_KEYS] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25};
    float min_error = 100;
    float error = 0.0;
    int right_a = 0, right_b = 0;

    float *decoded_freq = NULL;
    for(int i = 0; i < A_KEYS; i++){
        for(int j = 0; j < B_KEYS; j++){
            char *decoded_text = decode(a_key[i], b_key[j], encoded_text);
            decoded_freq = frequency(decoded_text);

            error = 0;
            for(int k = 0; k < ALPHABET_SIZE; k++){
                error += fabs(czech_freq[k] - decoded_freq[k]);
            }
            free(decoded_text);
            free(decoded_freq);
            
            if(error < min_error){
                min_error = error;
                right_a = a_key[i];
                right_b = b_key[j];
            }
        }
    }
    //right keys
    printf("a=%d,b=%d", right_a, right_b);
 
    decoded_text = decode(right_a, right_b, encoded_text);
    output_fp = fopen(output, "w");
    fprintf(output_fp, "%s", decoded_text);

    fclose(input_fp);
    fclose(output_fp);
    return decoded_text;
}

int main(int argc, char *argv[]){
    if(argc < 1){ 
        fprintf(stderr, "error: Wrong amount of arguments\n");
        return 0;
   }
    char *mode = argv[1];
    int a = 0, b = 0;
    char *input_file, *output_file, *text_to_encode, *text_to_decode, *encoded, *decoded;
    input_file = output_file = text_to_encode = text_to_decode = encoded = decoded = NULL;
  

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
            if(argv[6] != NULL && i == 6){
                text_to_encode = argv[6];
                text_to_decode = argv[6];
            }
            else{
                fprintf(stderr, "Wrong argument\n");
                return 1;
            }
        }
    }
    if(strcmp(mode, "-e") == 0 || strcmp(mode, "-d") == 0){
        if(argc != 7){
            fprintf(stderr, "Wrong amount of arguments\n");
            return 1;
        }
        else{
            if (strcmp(mode, "-e") == 0) {
                encoded = encode(a, b, text_to_encode);
                printf("%s", encoded);
                free(encoded);
            } else if (strcmp(mode, "-d") == 0) {
                decoded = decode(a, b, text_to_decode);
                printf("%s", decoded);
                free(decoded);
            }
        }
    }else if(strcmp(mode, "-c") == 0) {
        if(argc != 6){
            fprintf(stderr, "Wrong amount of arguments\n");
            return 1;
        }
        else if (strcmp(mode, "-c") == 0) {
            decoded = nokey_decode(input_file, output_file);
            free(decoded);
        }
    } else {
        fprintf(stderr, "Unknown combination of arguments: %s\n", mode);
        return 1;
    }
    return 0;
}