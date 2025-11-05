#pragma clang diagnostic push
#pragma ide diagnostic ignored "readability-non-const-parameter"
#include <stdio.h>

#define BUFFER_SIZE 0xf00000  // Files over 15MB are not supported

typedef unsigned char byte;
typedef byte* buffer_t;

void clearBuffer(buffer_t buffer) {
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = 0;
    }
}

size_t bufferLen(buffer_t buffer) {
    for (size_t len = BUFFER_SIZE; len > 0; len--) {
        if (buffer[len - 1] != 0) return len;
    }
    return 0;
}

size_t fillBufferTillDivisible(buffer_t buffer, int divisibleBy) {
    size_t len = bufferLen(buffer);
    while (len % divisibleBy != 0 && len < BUFFER_SIZE) {
        buffer[len] = 0;
        len++;
    }
    return len;
}

size_t trimOrPad(buffer_t buffer, size_t exactLen) {
    size_t len = bufferLen(buffer);
    if (len > exactLen) {
        for (size_t i = len - 1; i > exactLen; i--) {
            buffer[i] = 0;
        }
    }
    return exactLen;
}

size_t readFromfile(const char* fileName, buffer_t buffer) {
    FILE* inputFile = fopen(fileName, "rb");
    if (!inputFile) {
        printf("Reading file failed to open\n");
        return 0;
    }
    size_t bytesRead = fread(buffer, 1, BUFFER_SIZE, inputFile);
    if (bytesRead < BUFFER_SIZE) buffer[bytesRead] = 0;
    if (bytesRead == 0) {
        if (ferror(inputFile)) {
            perror("Error during reading the file");
        } else if (feof(inputFile)) {
            printf("End of file reached\n");
        } else printf("Unknown file read error\n");
    }
    fclose(inputFile);
    return bytesRead;
}

int writeToFile(const char* fileName, buffer_t buffer) {
    size_t size = bufferLen(buffer);
    FILE* outputFile = fopen(fileName, "wb");
    if (!outputFile) return 2;
    size_t bytesWritten = fwrite(buffer, 1, size, outputFile);
    fclose(outputFile);
    if (bytesWritten > 0) return 0;
    else return 5;
}

void copyBuffer(buffer_t from, buffer_t to) {
    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        to[i] = from[i];
    }
}

#pragma clang diagnostic pop