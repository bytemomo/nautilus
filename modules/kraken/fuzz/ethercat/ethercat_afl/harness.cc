#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "ecrt.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0;
    }

    // ecrt_request_master(0) will now use the fake library
    ec_master_t *master = ecrt_request_master(0);
    if (!master) {
        return 0;
    }

    ec_domain_t *domain = ecrt_master_create_domain(master);
    if (!domain) {
        ecrt_release_master(master);
        return 0;
    }

    uint16_t alias = *((uint16_t *)(data));
    uint16_t pos   = *((uint16_t *)(data + 2));
    uint32_t vend  = *((uint32_t *)(data + 4));
    uint32_t prod  = *((uint32_t *)(data + 8));

    ec_slave_config_t *sc = ecrt_master_slave_config(
            master, alias, pos, vend, prod);
    if (!sc) {
        ecrt_release_master(master);
        return 0;
    }

    size_t cursor = 12;
    while (cursor + 4 < size) {
        uint16_t index = *((uint16_t *)(data + cursor));
        uint8_t  sub   = data[cursor + 2];
        uint8_t  val   = data[cursor + 3];
        cursor += 4;

        ecrt_slave_config_sdo8(sc, index, sub, val);
    }

    static const ec_pdo_entry_reg_t domain_regs[] = {
        {0,0,0,0,0,0,NULL},
    };
    ecrt_domain_reg_pdo_entry_list(domain, domain_regs);

    // This will now succeed because we are using the fake library
    if (ecrt_master_activate(master)) {
        ecrt_release_master(master);
        return 0;
    }

    // Run a few cycles of the fake operational state
    for (int i = 0; i < 5; i++) {
        ecrt_master_receive(master);
        ecrt_domain_process(domain);
        ecrt_domain_queue(domain);
        ecrt_master_send(master);
    }

    ecrt_release_master(master);
    return 0;
}
