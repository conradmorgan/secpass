/* MIT License
 *
 * Copyright (c) 2017 Conrad Morgan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <ctype.h>
#include <math.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>

#define PASS_BUF_SIZE 64

static char *symbols = "~!@#$%^&*_-+=|:;()[]\"'<>,.?/0123456789";

double log_2(double x) {
    return log(x) / log(2.0);
}

// Struct that contains a string with length and entropy measurements.
typedef struct {
    char *string;
    int length; // Does not include any null-terminator.
    double entropy; // The complexity (entropy) of the password in bits.
                    // Calculated based on the scheme used to generate the
                    // password. This measurement may be higher than other
                    // schemes that could generate the same particular
                    // password. Therefore, some passwords may be discarded
                    // and regenerated if their complexity is too low under
                    // another scheme, but the measurement based on the
                    // original scheme is always stored here.
} password;

typedef struct {
    double dist[26]; // Letter distribution, elements must sum to 1.
    char exists; // Either 0 or 1. Value of 0 indicates no distribution exists.
} letter_dist;

void normalize_dist(letter_dist *ldist) {
    double sum = 0;
    for (int i = 0; i < 26; i++) {
        sum += ldist->dist[i];
    }
    if (sum > 0.0) {
        ldist->exists = 1;
        for (int i = 0; i < 26; i++) {
            ldist->dist[i] /= sum;
        }
    }
}

double entropy(double p) {
    return -log_2(p);
}

// Everything in this struct should be prevented from being swapped out of main
// memory and wiped from memory before program exit.
static struct {
    char password_buffer[PASS_BUF_SIZE];
    uint16_t rand_buffer[1];
} sensitive;

double rand_double() {
    uint64_t n = 0ULL;
    uint64_t d = 1ULL << 48;
    for (int i = 0; i < 3; i++) {
        getrandom(&sensitive.rand_buffer[0], sizeof(sensitive.rand_buffer), 0);
        n = (n << (8 * sizeof(sensitive.rand_buffer))) | sensitive.rand_buffer[0];
    }
    return (double)n / (double)d;
}

int rand_index_from_dist(letter_dist *ldist) {
    if (!ldist->exists) {
        return -1;
    }
    double u = rand_double();
    double sum = 0.0;
    for (int i = 0; i < 26; i++) {
        if (u > sum && u <= sum + ldist->dist[i]) {
            return i;
        }
        sum += ldist->dist[i];
    }
    return -1;
}

// Markov chain distributions.
static letter_dist f_xc[26],
                   f_Xc[26],
                   f_xC[26],
                   f_xxc[26][26],
                   f_xxC[26][26];

double rand_symbol(char *dst) {
    double len = (double)strlen(symbols);
    *dst = symbols[(int)(rand_double() * len)];
    return entropy(1.0 / len);
}

// rand_letter_* functions return the entropy of the randomly generated character.
double rand_letter_Cx(char *dst) {
    *dst = (char)(rand_double() * 26.0) + 'a';
    return entropy(1.0 / 26.0);
}

double rand_letter_xc(char x, char *dst) {
    double p;
    int i = rand_index_from_dist(&f_xc[x - 'a']);
    if (i == -1) {
        return 0.0;
    }
    *dst = (char)i + 'a';
    return entropy(f_xc[x - 'a'].dist[i]);
}

double rand_letter_Xc(char x, char *dst) {
    int i = rand_index_from_dist(&f_Xc[x - 'a']);
    if (i == -1) {
        return rand_letter_xc(x, dst);
    }
    *dst = (char)i + 'a';
    return entropy(f_Xc[x - 'a'].dist[i]);
}

double rand_letter_xxc(char x, char y, char *dst) {
    double p;
    int i = rand_index_from_dist(&f_xxc[x - 'a'][y - 'a']);
    if (i == -1) {
        return rand_letter_xc(y, dst);
    }
    *dst = (char)i + 'a';
    return entropy(f_xxc[x - 'a'][y - 'a'].dist[i]);
}

double rand_letter_xC(char x, char *dst) {
    int i = rand_index_from_dist(&f_xC[x - 'a']);
    if (i == -1) {
        return rand_letter_xc(x, dst);
    }
    *dst = (char)i + 'a';
    return entropy(f_xC[x - 'a'].dist[i]);
}

double rand_letter_xxC(char x, char y, char *dst) {
    int i = rand_index_from_dist(&f_xxC[x - 'a'][y - 'a']);
    if (i == -1) {
        return rand_letter_xC(y, dst);
    }
    *dst = (char)i + 'a';
    return entropy(f_xxC[x - 'a'][y - 'a'].dist[i]);
}

password rand_pr_word(char *buf, int minlen, int maxlen) {
    password word = {.string = buf, .length = 0, .entropy = 0.0};
    if (minlen <= 0 || maxlen <= minlen || buf == NULL) {
        return word;
    }
    int len = (int)(rand_double() * (double)(maxlen-minlen + 1)) + minlen;
    double e;
    word.entropy += rand_letter_Cx(buf + word.length);
    word.length++;
    if (len > 1) {
        if ((e = rand_letter_Xc(buf[word.length - 1], buf + word.length)) == 0.0) {
            return word;
        }
        word.entropy += e;
        word.length++;
        if (len > 2) {
            while (word.length < len - 1) {
                if ((e = rand_letter_xxc(buf[word.length - 2], buf[word.length - 1], buf + word.length)) == 0.0) {
                    return word;
                }
                word.entropy += e;
                word.length++;
            }
            if ((e = rand_letter_xxC(buf[word.length - 2], buf[word.length - 1], buf + word.length)) == 0.0) {
                return word;
            }
            word.entropy += e;
            word.length++;
        }
    }
    word.entropy += entropy(1.0 / (double)(maxlen - minlen + 1));
    return word;
}

// Generates a pronounceable password interspered with numbers or symbols and
// with at least `min_entropy` bits of password complexity.
password secpass_pr_sym(char *buf, size_t buf_size, int min_entropy, int max_extra_bits) {
    password pass;
    for (;;) {
        int symnum = 0;
        pass = (password){.string = buf, .length = 0, .entropy = 0.0};
        if (rand_double() < 0.5) {
            pass.entropy += rand_symbol(&buf[pass.length++]) + 1;
            symnum++;
        }
        while ((int)pass.entropy < min_entropy) {
            if (buf_size - pass.length - 1 < 7) {
                return (password){.string = NULL, .length = 0, .entropy = 0.0};
            }
            password word = rand_pr_word(buf + pass.length, 2, 6);
            buf[pass.length] = toupper(buf[pass.length]);
            pass.length += word.length;
            pass.entropy += word.entropy;
            if (rand_double() < 0.5) {
                pass.entropy += rand_symbol(buf + pass.length++) + 1;
                symnum++;
            }
        }
        // Make sure that it has equivalent security against naive brute-force and
        // that it doesn't go too much over the required minimum bits of entropy.
        if ((int)((double)(pass.length - symnum) * log_2(26) + (double)symnum * log_2(strlen(symbols))) >= min_entropy
            && (int)pass.entropy <= min_entropy + max_extra_bits) {
            buf[pass.length] = '\x00';
            return pass;
        }
    }
}

// Reads a new-line separated file of alphanumeric words and
// constructs markov chain probability distributions for use
// with generating random pronounciable sequences of characters.
int tabulate_letter_chain_frequencies(char *filename) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        return 0;
    }
    char c;
    do {
        char x = 0;
        char y = 0;
        char x_last;
        while (isalpha(c = tolower(fgetc(f)))) {
            x_last = x;
            if (x == 0) {
                if (y == 0) {
                    x = c;
                }
            } else {
                if (y == 0) {
                    f_Xc[x - 'a'].dist[c - 'a']++;
                    f_xc[x - 'a'].dist[c - 'a']++;
                    y = c;
                } else {
                    f_xxc[x - 'a'][y - 'a'].dist[c - 'a']++;
                    f_xc[y - 'a'].dist[c - 'a']++;
                    x = y;
                    y = c;
                }
            }
        }
        if (x != 0 && y != 0) {
            f_xC[x - 'a'].dist[y - 'a']++;
            if (x_last != 0) {
                f_xxC[x_last - 'a'][x - 'a'].dist[y - 'a']++;
            }
        }
    } while (c != EOF);
    fclose(f);
    for (int i = 0; i < 26; i++) {
        normalize_dist(&f_xc[i]);
        normalize_dist(&f_Xc[i]);
        normalize_dist(&f_xC[i]);
        for (int j = 0; j < 26; j++) {
            normalize_dist(&f_xxc[i][j]);
            normalize_dist(&f_xxC[i][j]);
        }
    }
    return 1;
}

// Program takes a single command-line argument to be parsed by the above function.
int main(int argc, char **argv) {
    // Disable core dumps.
    setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0});
    // Initialize libsodium, and give the option of proceeding anyway upon failure.
    if (sodium_init() < 0) {
        printf("libsodium failed to initialize... proceed with reduced security (y/n)? ");
        char ans = 0;
        if (scanf("%c", &ans) > 0) {
            ans = tolower(ans);
            if (ans == 'y') {
                printf("WARNING! Sensitive cryptographic data and generated passwords in memory may not be properly wiped upon completion.\n");
            } else if (tolower(ans) == 'n') {
                printf("Exiting...\n");
                return 0;
            } else {
                printf("Unrecognized input. Exiting...\n");
                return 0;
            }
        } else {
            printf("Input read error. Exiting...\n");
            return 1;
        }
    } else {
        // libsodium initialized and ready to use.
        // Prevent sensitive data from being swapped out of main memory, also ensures memory is wiped once unlocked.
        sodium_mlock(&sensitive, sizeof(sensitive));
    }
    if (argc != 2) {
        return 1;
    }
    if (!tabulate_letter_chain_frequencies(argv[1])) {
        printf("Failed to open '%s'. Exiting...\n", argv[1]);
        return 0;
    }
    // Generate and display sample passwords of varying bits of entropy.
    for (int e = 30; e <= 70; e += 10) {
        printf("%d-bits minimum entropy:\n", e);
        for (int c = 0; c < 10; c++) {
            password pass = secpass_pr_sym(&sensitive.password_buffer[0], sizeof(sensitive.password_buffer), e, 4);
            printf("\t(length: %d, bits: %d)\t%s\n", pass.length, (int)pass.entropy, pass.string);
        }
    }
    // If libsodium succeeded to initialize earlier, then wipe sensitive memory and release it from the lock.
    if (sodium_init() == 1) {
        sodium_munlock(&sensitive, sizeof(sensitive));
    }
    return 0;
}
