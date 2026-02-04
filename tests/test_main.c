#include <stdio.h>

void run_packet_parse_tests(void);
void run_rule_tests(void);
void run_engine_tests(void);

int main(void)
{
    printf("[lfw] running tests\n");

    run_packet_parse_tests();
    run_rule_tests();
    run_engine_tests();

    printf("[lfw] all tests passed\n");
    return 0;
}
