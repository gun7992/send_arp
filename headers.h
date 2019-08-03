#pragma once
#include <stdint.h>
#define ETHER_MAC_SIZE		0x06
#define ETHER_HDR_SIZE		0x0e
#define ETHER_PROTO_SIZE	0X04






struct ethernet_hdr
{
    uint8_t ether_dmac[ETHER_MAC_SIZE];
    uint8_t ether_smac[ETHER_MAC_SIZE];
    uint16_t ether_type;
};


struct arp_hdr
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t H_add_len;
    uint8_t P_add_len;
    uint16_t Opcode;
    uint8_t S_hardware_addr[ETHER_MAC_SIZE];
    uint8_t S_protocol_addr[ETHER_PROTO_SIZE];
    uint8_t T_hardware_addr[ETHER_MAC_SIZE];
    uint8_t T_protocol_addr[ETHER_PROTO_SIZE];
};



