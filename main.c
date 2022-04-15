#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <unistd.h>


#define PATH_SEPARATOR "/"

#define MALWARE_DATA_FILENAME "malware.data"
#define MALWARE_DATA_COUNT 3

#define QUARANTINE_DIR "/var/tmp/tulus-quarantine"

#define DEBUG 1
#define VERBOSE 1

#define RED_ANSI "\033[0;31m"
#define GREEN_ANSI "\033[0;32m"
#define DEFAULT_COLOR_ANSI "\033[0m"

uint8_t malwareHashes[MALWARE_DATA_COUNT][SHA256_DIGEST_LENGTH];

void printHelp() {
    printf("tulware scanner.\n"
           "\n"
           "Usage:\n"
           "  tulware-scanner -d <directory> [-f <file>]\n"
           "  tulware-scanner -h\n"
           "\n"
           "Options:\n"
           "  -h                Show this screen.\n"
           "  -d <directory>    Directory path to scan. [default=\"./\"]\n"
           "  -f <file>         File to scan\n");
}

void readMalwareHashes() __attribute__((constructor));

void setupQuarantineDirectory() __attribute__((constructor));

void signatureBasedTraversePathScan(char *path);

int isRelevantFileName(char *fileName);

void pathConcat(char *path1, char *path2, char *outputPath);

void verifyFile(char *directoryPath, char *fileName);

void calculateFileHash(uint8_t *hash, char *filepath);

int isKnownMalwareHash(uint8_t *fileHash);

void quarantineFile(char *filePath, char *fileName);

void buildQuarantineFilePath(char *outputPath, char *fileName);

void scanDebugLog(uint8_t *hash, int isKnownHash, char *filePath);

void printHash(unsigned char *hash);

void readMalwareHashes() {
    FILE *file = fopen(MALWARE_DATA_FILENAME, "rb");

    if (!file) {
        printf("Error while reading file content: %s", MALWARE_DATA_FILENAME);
        exit(EXIT_FAILURE);
    }

    fread(&malwareHashes, sizeof(uint8_t) * SHA256_DIGEST_LENGTH, MALWARE_DATA_COUNT, file);
    fclose(file);
}

void setupQuarantineDirectory() {
    struct stat st = {0};
    if (stat(QUARANTINE_DIR, &st) != -1) {
        return;
    }
    if (mkdir(QUARANTINE_DIR, S_IRWXG | S_IROTH | S_IXOTH | S_IRWXU) != 0) {
        printf("Error occurred while creating quarantine directory");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    char *directory = "./";
    char *file = NULL;
    int c;

    while ((c = getopt(argc, argv, "hd:f:")) != -1) {
        switch (c) {
            case 'h':
                printHelp();
                exit(EXIT_SUCCESS);
            case 'd':
                directory = malloc(strlen(optarg) + 1);
                strncpy(directory, optarg, strlen(optarg) + 1);
                break;
            case 'f':
                file = malloc(strlen(optarg) + 1);
                strncpy(file, optarg, strlen(optarg) + 1);
                break;
            case ':':
                printf("Option needs a value\n");
                break;
            case '?':
                printf("Unknown option: %c\n"
                       "See available options in help (-h) menu.", optopt);
                break;
            default:
                printHelp();
                exit(EXIT_FAILURE);
        }
    }

    if (directory && file) {
        verifyFile(directory, file);
    }
    if (directory) {
        signatureBasedTraversePathScan(directory);
    }

    return EXIT_SUCCESS;
}

void signatureBasedTraversePathScan(char *basePath) {
    char path[__DARWIN_MAXPATHLEN];
    struct dirent *nextDirectory;
    DIR *directory = opendir(basePath);

    if (!directory) {
        return;
    }

    while ((nextDirectory = readdir(directory)) != NULL) {
        if (isRelevantFileName(nextDirectory->d_name)) {
            if (nextDirectory->d_type == DT_REG) {
                verifyFile(basePath, nextDirectory->d_name);
            }

            pathConcat(path, basePath, nextDirectory->d_name);
            signatureBasedTraversePathScan(path);
        }
    }

    closedir(directory);
}

int isRelevantFileName(char *filename) {
    if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
        return 0;
    }
    return 1;
}

void pathConcat(char *outputPath, char *path1, char *path2) {
    strcpy(outputPath, path1);
    strcat(outputPath, PATH_SEPARATOR);
    strcat(outputPath, path2);
}

void verifyFile(char *directoryPath, char *fileName) {
    char filePath[__DARWIN_MAXPATHLEN];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    pathConcat(filePath, directoryPath, fileName);
    calculateFileHash(hash, filePath);

    int isKnownHash = isKnownMalwareHash(hash);

    if (isKnownHash) {
        quarantineFile(filePath, fileName);
    }

    if (DEBUG && (VERBOSE || isKnownHash)) {
        scanDebugLog(hash, isKnownHash, filePath);
    }
}

void calculateFileHash(uint8_t *hash, char *filepath) {
    unsigned char chunk[1024];
    SHA256_CTX hashContext;
    size_t bytes;

    FILE *file = fopen(filepath, "rb");

    if (!file) {
        printf("Error while reading file content: %s", filepath);
        exit(EXIT_FAILURE);
    }

    SHA256_Init(&hashContext);
    while ((bytes = fread(chunk, 1, sizeof chunk, file)) != 0) {
        SHA256_Update(&hashContext, chunk, bytes);
    }
    SHA256_Final(hash, &hashContext);

    fclose(file);
}

int isKnownMalwareHash(uint8_t *fileHash) {
    for (int i = 0; i < MALWARE_DATA_COUNT; i++) {
        if (memcmp(fileHash, malwareHashes[i], SHA256_DIGEST_LENGTH) == 0) {
            return 1;
        }
    }
    return 0;
}

void quarantineFile(char *filePath, char *fileName) {
    char destinationFilePath[__DARWIN_MAXPATHLEN];
    buildQuarantineFilePath(destinationFilePath, fileName);

    if (rename(filePath, destinationFilePath)) {
        printf("Error occurred while moving file to quarantine.");
        exit(EXIT_FAILURE);
    }

    if (chmod(destinationFilePath, 0) != 0) {
        printf("Error occurred while changing quarantined file mode");
        exit(EXIT_FAILURE);
    }

    if (symlink(destinationFilePath, filePath) < 0) {
        printf("Error occurred while creating symlink to quarantined file");
        exit(EXIT_FAILURE);
    }
}

void buildQuarantineFilePath(char *outputPath, char *fileName) {
    char quarantineFileName[__DARWIN_MAXNAMLEN];
    snprintf(quarantineFileName, sizeof quarantineFileName, "%ld_%s", (long) time(NULL), fileName);
    pathConcat(outputPath, QUARANTINE_DIR, quarantineFileName);
}

void scanDebugLog(uint8_t *hash, int isKnownHash, char *filePath) {
    if (isKnownHash) {
        printf(RED_ANSI);
        printf(" SIGNATURE RECOGNIZED | ");
    } else {
        printf(GREEN_ANSI);
        printf(" -------------------- | ");
    }
    printHash(hash);
    printf(" | %s\n", filePath);
    printf(DEFAULT_COLOR_ANSI);
}

void printHash(unsigned char *hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
}
