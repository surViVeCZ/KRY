#include <stdio.h>
#include <string.h>
#include <stdlib.h>


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
        char encoded_char = (a * x + b) % 26 + 'A';
        if(text[i] == ' '){
            encoded[i] = ' ';
            continue;
        }
        encoded[i] = encoded_char;
    }
    return encoded;
}

char *decode(int a, int b, char *text) {
    printf("Decoding with a=%d and b=%d, with text %s\n", a, b, text);
    int x = 0;
    char *decoded = malloc(strlen(text) * sizeof(char));

    int MI = 0; //multiplicative inverse
    for(int i= 0; i < a; i++){
        MI=((i*26)+1);
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
        }
        char decoded_char = (MI * (x - b)) % 26 + 'A';
        if(text[i] == ' '){
            decoded[i] = ' ';
            continue;
        }
        decoded[i] = decoded_char;
    }
    return decoded;
}


char *nokey_decode(int a, int b, char *text) {
    printf("Decoding without key with a=%d and b=%d, with text %s\n", a, b, text);
    return text;
}


int main(int argc, char *argv[]){


    if(argc < 1){ 
        fprintf(stderr, "error: Wrong amount of arguments\n");
        return 0;
   }
    char *mode = argv[1];
    int a = 0;
    int b = 0;
    char *text_to_encode = "TOTO JE TAJNA ZPRAVA";//argv[6];
    char *text_to_decode = "MXMX IT MHIUH EAGHSH";//argv[6];
  

    for (int i = 2; i < argc; i += 2) {
        if (strcmp(argv[i], "-a") == 0) {
            a = atoi(argv[i+1]);
        } else if (strcmp(argv[i], "-b") == 0) {
            b = atoi(argv[i+1]);
        } else {
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
        decoded = nokey_decode(a, b, text_to_decode);
        printf("Decoded text: %s\n", decoded);
        return 1;
    } else {
        printf("Unknown mode: %s\n", mode);
        return 1;
    }
    return 0;
}