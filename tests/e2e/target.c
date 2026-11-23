#include <stdio.h>
#include <string.h>
struct point { int x; int y; };
volatile unsigned int g_counter = 0x11223344;
volatile struct point g_origin = { 3, 4 };
const char g_banner[] = "mcp-e2e-banner";
__attribute__((noinline)) int add_numbers(int a, int b) { return a + b + (int)g_counter; }
__attribute__((noinline)) int checksum(const char *s) { int c = 0; while (*s) c = c * 31 + *s++; return c; }
__attribute__((noinline)) int distance2(int x, int y) { return (x - g_origin.x) * (x - g_origin.x) + (y - g_origin.y) * (y - g_origin.y); }
int main(int argc, char **argv) {
    printf("%s %d\n", g_banner, add_numbers(argc, 2));
    printf("%d %d\n", checksum(argc > 1 ? argv[1] : "hello"), distance2(argc, 7));
    return 0;
}
