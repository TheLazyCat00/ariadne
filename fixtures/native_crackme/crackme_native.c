/* Tiny native license-gate crackme for exercising the native angr backend:
 *   fgets   -> stdin source
 *   strcmp  -> the gate comparison against a constant key
 *   printf  -> win/lose outcome strings the sink classifier anchors on
 * Build: gcc crackme_native.c -o crackme_native.exe
 */
#include <stdio.h>
#include <string.h>

static int check_license(const char *key) {
    if (strcmp(key, "NATIVE-KEY-9000") == 0)
        return 1;
    return 0;
}

int main(void) {
    char buf[128];
    printf("Enter license key: ");
    if (!fgets(buf, sizeof buf, stdin))
        return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (check_license(buf)) {
        printf("License accepted. Welcome!\n");
        return 0;
    }
    printf("License invalid. Access denied.\n");
    return 1;
}
