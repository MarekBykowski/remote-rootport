/*
 * simics_transaction.h
 *
 * The single, shared definition of simics_transaction_t -- the fixed-layout
 * record exchanged across the cosim named pipes and (via dpi_cosim.c) the
 * DPI-C boundary into simv. Previously every tool (thin-server-enum.c,
 * emu-enum.c, dpi_cosim.c, doe-emu.c, thin-server.c) carried its own private
 * copy; include this header instead of redefining it.
 *
 * The layout MUST stay byte-compatible with the SV typedef in
 * EipPcieTBSeqPkg.sv and cxl_relay's cxl_tlp_fifo.h.
 *
 * cfg_type is a dead field (never read), retained on purpose: it fills the
 * 4 bytes the compiler would otherwise pad before the u64 physical_address,
 * so the struct size and every used field's offset match the SV / cxl_relay
 * layout with or without it.
 */
#ifndef SIMICS_TRANSACTION_H
#define SIMICS_TRANSACTION_H

#include <stdint.h>

/* Max config/mem payload carried in one transaction. */
#define MAX_PAYLOAD 256

typedef struct {
    uint32_t packet_number;
    uint32_t packet_type;
    uint32_t sim_type;
    uint32_t bus_no;
    uint32_t dev_no;
    uint32_t fun_no;
    uint32_t cfg_type;
    uint32_t control_status;
    uint64_t physical_address;
    uint32_t r0w1;
    uint32_t data_size;
    uint8_t  data[MAX_PAYLOAD];
    uint32_t reg_value;
    uint32_t fixed_first_size;
    uint32_t unaligned_value;
    uint32_t fbe;
    uint32_t fixed_last_size;
    uint32_t lbe;
    uint32_t cmp_status;
    uint32_t response1;
    uint32_t response2;
} simics_transaction_t;

#endif /* SIMICS_TRANSACTION_H */
