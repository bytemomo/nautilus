#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include "ecrt.h"

extern "C" {
#include "master.h"
#include "domain.h"
#include "slave_config.h"
}

extern "C" int ioctl(int fd, unsigned long request, ...) {
    (void)fd; (void)request;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;

    ec_master_t master;
    ec_domain_t *domain = NULL;
    ec_slave_config_t *sc = NULL;

    memset(&master, 0, sizeof(ec_master_t));
    master.fd = 1;

    uint16_t alias = *((uint16_t *)(data));
    uint16_t pos   = *((uint16_t *)(data + 2));
    uint32_t vend  = *((uint32_t *)(data + 4));
    uint32_t prod  = *((uint32_t *)(data + 8));

    size_t cursor = 12;

    domain = ecrt_master_create_domain(&master);
    if (!domain) goto cleanup;

    sc = ecrt_master_slave_config(&master, alias, pos, vend, prod);
    if (!sc) goto cleanup;

    while (cursor + 4 < size) {
        uint16_t index = *((uint16_t *)(data + cursor));
        uint8_t  sub   = data[cursor + 2];
        uint8_t  val   = data[cursor + 3];
        cursor += 4;

        ecrt_slave_config_sdo8(sc, index, sub, val);

        if (cursor % 8 == 0 && cursor + 2 < size) {
            ecrt_slave_config_pdo_assign_add(sc, 2, index);
        }
    }

    static const ec_pdo_entry_reg_t domain_regs[] = {
        {0,0,0,0,0,0,NULL},
    };
    ecrt_domain_reg_pdo_entry_list(domain, domain_regs);

cleanup:
    ec_master_clear(&master);

    return 0;
}
