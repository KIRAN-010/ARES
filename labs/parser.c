/* Educational length-prefixed parser. Compile with -DFIXED to enforce bounds.
 * Known fixture only. Never run unknown samples/code on the MJ controller.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    unsigned char input[256];
    size_t n = fread(input, 1, sizeof(input), stdin);
    if (n == 0) return 0;
    size_t declared = input[0];
#ifdef FIXED
    if (declared > n - 1) return 2;
#endif
    unsigned char *payload = malloc(n - 1 ? n - 1 : 1);
    if (!payload) return 3;
    for (size_t i = 1; i < n; ++i) payload[i - 1] = input[i];
    volatile uint32_t sum = 0;
    for (size_t i = 0; i < declared; ++i) sum += payload[i];
    free(payload);
    return sum == 0xFFFFFFFF ? 1 : 0;
}
