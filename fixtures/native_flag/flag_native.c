/* License-gate crackme variant that gates on a boolean *variable* (isUnlocked)
 * instead of a check_license() return value, for exercising taint-based branch
 * discovery in the native angr backend:
 *   getenv     -> external SOURCE (license state almost always comes from outside)
 *   strcmp     -> the comparison that produces the gate boolean
 *   isUnlocked -> one bool that gatekeeps MULTIPLE branches (same expression)
 *   printf     -> win/lose outcome strings the sink classifier anchors on
 *
 * Research note: the next analysis step does not look for a check_license()
 * function. It finds the branches that gatekeep on the same expression
 * (isUnlocked), confirms that expression is tainted by an external source, and
 * patches only the boolean sub-expression that is shared across those branches.
 * Build: gcc flag_native.c -o flag_native.exe
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    /* External license state: an env var here, but it could equally be a file
     * or registry value -- all are recognized sources. */
    const char *license = getenv("ARIADNE_LICENSE");
    int isUnlocked = (license != NULL && strcmp(license, "NATIVE-KEY-9000") == 0);

    /* The same boolean variable gatekeeps several branches. None of these is a
     * function call -- the gate lives entirely in `isUnlocked`. */
    if (isUnlocked) {
        printf("License accepted. Welcome!\n");
    } else {
        printf("License invalid. Access denied.\n");
    }

    if (isUnlocked) {
        printf("Premium features unlocked.\n");
    }

    return isUnlocked ? 0 : 1;
}
