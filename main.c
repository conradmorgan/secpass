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
#include <sys/resource.h>

#define PASS_BUF_SIZE 64
#define ALPH 26

static char all_symbols[32]           = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
// '`| excluded.
static char distinguished_symbols[29] = "!\"#$%&()*+,-./:;<=>?@[\\]^_{}~";

double log_2(double x) {
    return log(x) / log(2.0);
}

double entropy(double p) {
    return -log_2(p);
}

// Struct that contains a string with length and entropy measurements.
typedef struct {
    char *string;
    int length; // Does not include any null-terminator.
    double entropy; // The estimated complexity (entropy) of the password in bits.
} password;

typedef struct {
    double dist[ALPH];  // Letter frequency distribution. Should sum to 1.
    char exists;        // Either 0 or 1. Value of 0 indicates no distribution exists.
} letter_dist;

// Everything in this struct is to be prevented from being swapped out of main
// memory, and is to be wiped before program exit.
static struct {
    char password_buffer[PASS_BUF_SIZE];
    // For storing a single cryptographically random byte.
    uint8_t crypt_byte;
    // For sensitive parameters and results that would otherwise get leaked on the stack.
    letter_dist *arg_ldist;
    double ret_double;
    int ret_int;
    // For sensitive intermediate calculations.
    double tmp_double;
    uint64_t tmp_uint64;
    int tmp_int;
} sensitive;

// Generate a cryptographically secure uniform random double in [0.0, 1.0).
// Result stored in `sensitive.ret_double`.
void gen_rand_double() {
    sensitive.tmp_uint64 = 0ull;
    // Generate 56 random bits.
    for (int i = 0; i < 7; i++) {
        randombytes_buf(&sensitive.crypt_byte, 1);
        sensitive.tmp_uint64 = (sensitive.tmp_uint64 << 8) | sensitive.crypt_byte;
    }
    // Leave only the least-significant 52 bits (size of explicit double-precision mantissa).
    sensitive.tmp_uint64 &= 0x000fffffffffffffull;
    sensitive.ret_double = (double)sensitive.tmp_uint64 / (double)0x0010000000000000ull;
}

// Result stored in `sensitive.ret_int`.
void gen_rand_index_from_dist() {
    if (!sensitive.arg_ldist->exists) {
        sensitive.ret_int = -1;
        return;
    }
    gen_rand_double();
    sensitive.tmp_double = 0.0;
    for (sensitive.ret_int = 0; sensitive.ret_int < ALPH; sensitive.ret_int++) {
        if (sensitive.tmp_double < sensitive.ret_double &&
            sensitive.tmp_double + sensitive.arg_ldist->dist[sensitive.ret_int] >= sensitive.ret_double) {
            return;
        }
        sensitive.tmp_double += sensitive.arg_ldist->dist[sensitive.ret_int];
    }
    sensitive.ret_int = -1;
}

// Markov chain distributions.
static letter_dist f_xc[ALPH],
                   f_Xc[ALPH],
                   f_xC[ALPH],
                   f_xxc[ALPH][ALPH],
                   f_xxC[ALPH][ALPH];

void normalize_dist(letter_dist *ldist) {
    double sum = 0;
    for (int i = 0; i < ALPH; i++) {
        sum += ldist->dist[i];
    }
    if (sum > 0.0) {
        ldist->exists = 1;
        for (int i = 0; i < ALPH; i++) {
            ldist->dist[i] /= sum;
        }
    }
}

static inline int sym_num_space() {
    return 10 + sizeof(distinguished_symbols)/sizeof(char);
}

double rand_sym_num(char *dst) {
    double space = (double)sym_num_space();
    gen_rand_double();
    sensitive.tmp_int = (int)(space * sensitive.ret_double);
    *dst = (sensitive.tmp_int < 10) ? (sensitive.tmp_int + '0') : distinguished_symbols[sensitive.tmp_int - 10];
    return entropy(1.0 / space);
}

// rand_letter_* functions return the entropy of the randomly generated character.
double rand_letter_Cx(char *dst) {
    gen_rand_double();
    *dst = (char)((double)ALPH * sensitive.ret_double) + 'a';
    return entropy(1.0 / (double)ALPH);
}

double rand_letter_xc(char *dst) {
    sensitive.arg_ldist = &f_xc[dst[-1] - 'a'];
    gen_rand_index_from_dist();
    if (sensitive.ret_int == -1) {
        return 0.0;
    }
    *dst = (char)sensitive.ret_int + 'a';
    return entropy(sensitive.arg_ldist->dist[sensitive.ret_int]);
}

double rand_letter_Xc(char *dst) {
    sensitive.arg_ldist = &f_Xc[dst[-1] - 'a'];
    gen_rand_index_from_dist();
    if (sensitive.ret_int == -1) {
        return rand_letter_xc(dst);
    }
    *dst = (char)sensitive.ret_int + 'a';
    return entropy(sensitive.arg_ldist->dist[sensitive.ret_int]);
}

double rand_letter_xxc(char *dst) {
    sensitive.arg_ldist = &f_xxc[dst[-2] - 'a'][dst[-1] - 'a'];
    gen_rand_index_from_dist();
    if (sensitive.ret_int == -1) {
        return rand_letter_xc(dst);
    }
    *dst = (char)sensitive.ret_int + 'a';
    return entropy(sensitive.arg_ldist->dist[sensitive.ret_int]);
}

double rand_letter_xC(char *dst) {
    sensitive.arg_ldist = &f_xC[dst[-1] - 'a'];
    gen_rand_index_from_dist();
    if (sensitive.ret_int == -1) {
        return rand_letter_xc(dst);
    }
    *dst = (char)sensitive.ret_int + 'a';
    return entropy(sensitive.arg_ldist->dist[sensitive.ret_int]);
}

double rand_letter_xxC(char *dst) {
    sensitive.arg_ldist = &f_xxC[dst[-2] - 'a'][dst[-1] - 'a'];
    gen_rand_index_from_dist();
    if (sensitive.ret_int == -1) {
        return rand_letter_xC(dst);
    }
    *dst = (char)sensitive.ret_int + 'a';
    return entropy(sensitive.arg_ldist->dist[sensitive.ret_int]);
}

password rand_pr_word(char *buf, int minlen, int maxlen) {
    password word = {.string = buf, .length = 0, .entropy = 0.0};
    if (minlen <= 0 || maxlen <= minlen || buf == NULL) {
        return word;
    }
    gen_rand_double();
    // Get a random length between `minlen` and `maxlen`.
    sensitive.tmp_int = (int)(sensitive.ret_double * (double)(maxlen-minlen + 1)) + minlen;
    double e;
    word.entropy += rand_letter_Cx(buf + word.length);
    word.length++;
    if (sensitive.tmp_int > 1) {
        if ((e = rand_letter_Xc(buf + word.length)) == 0.0) {
            return (password){NULL, 0, 0.0};
        }
        word.entropy += e;
        word.length++;
        if (sensitive.tmp_int > 2) {
            while (word.length < sensitive.tmp_int - 1) {
                if ((e = rand_letter_xxc(buf + word.length)) == 0.0) {
                    return (password){NULL, 0, 0.0};
                }
                word.entropy += e;
                word.length++;
            }
            if ((e = rand_letter_xxC(buf + word.length)) == 0.0) {
                return (password){NULL, 0, 0.0};
            }
            word.entropy += e;
            word.length++;
        }
    }
    word.entropy += entropy(1.0 / (double)(maxlen - minlen + 1));
    return word;
}

// Generates a pronounceable password interspered with numbers and symbols and
// with at least `min_entropy` bits of password complexity.
password secpass_pr_sym(char *buf, size_t buf_size, int min_entropy, int max_extra_bits) {
    password pass;
    int max_word_len = 6;
    int min_word_len = 2;
    for (;;) {
        int symbols = 0;
        int words = 0;
        pass = (password){.string = buf, .length = 0, .entropy = 0.0};
        gen_rand_double();
        if (sensitive.ret_double < 0.5) {
            pass.entropy += rand_sym_num(&buf[pass.length++]) + 1;
            symbols++;
        }
        while ((int)pass.entropy < min_entropy) {
            if (buf_size - pass.length - 1 < 7) {
                return (password){NULL, 0, 0.0};
            }
            password word = rand_pr_word(buf + pass.length, min_word_len, max_word_len);
            if (word.length == 0) {
                continue;
            }
            buf[pass.length] = toupper(buf[pass.length]);
            pass.length += word.length;
            pass.entropy += word.entropy;
            words++;
            gen_rand_double();
            if (sensitive.ret_double < 0.5) {
                pass.entropy += rand_sym_num(buf + pass.length++) + 1;
                symbols++;
            }
        }
        // Make sure it doesn't go too much over the required minimum bits of entropy.
        if ((int)pass.entropy <= min_entropy + max_extra_bits) {
            // Make sure that it has equivalent security against naive brute-force.
            double naive_entropy = (double)(pass.length - symbols) * log_2(ALPH) +
                (double)symbols * log_2((double)sym_num_space()) +
                (double)words * log_2((double)(max_word_len - min_word_len + 1));
            if ((int)naive_entropy >= min_entropy) {
                pass.entropy = fmin(pass.entropy, naive_entropy);
                buf[pass.length] = '\0';
                return pass;
            }
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
            c -= 'a';
            x_last = x;
            if (x == 0) {
                if (y == 0) {
                    x = c;
                }
            } else {
                if (y == 0) {
                    f_Xc[x].dist[c]++;
                    f_xc[x].dist[c]++;
                    y = c;
                } else {
                    f_xxc[x][y].dist[c]++;
                    f_xc[y].dist[c]++;
                    x = y;
                    y = c;
                }
            }
        }
        if (x != 0 && y != 0) {
            f_xC[x].dist[y]++;
            if (x_last != 0) {
                f_xxC[x_last][x].dist[y]++;
            }
        }
    } while (!feof(f));
    fclose(f);
    for (int i = 0; i < ALPH; i++) {
        normalize_dist(&f_xc[i]);
        normalize_dist(&f_Xc[i]);
        normalize_dist(&f_xC[i]);
        for (int j = 0; j < ALPH; j++) {
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
    if (sodium_init() < 0) {
        printf("libsodium failed to initialize. Exiting...\n");
        return 1;
    }
    // Prevent sensitive data from being swapped out of main memory, also ensures memory is wiped once unlocked.
    sodium_mlock(&sensitive, sizeof(sensitive));
    if (argc < 2) {
        printf("Not enough arguments, requires a filename to a wordlist.\n");
        return 0;
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
    // Wipe sensitive memory and release it from the swap lock.
    sodium_munlock(&sensitive, sizeof(sensitive));
    return 0;
}
