#ifndef FORMAT_H
#define FORMAT_H

#include <QObject>
/*
   @ This head file is used to define format of packages
   @ auther DJH-sudo
   @ if you have any question,pls contact me at djh113@126.com
*/

// define some types and macro defination
//typedef unsigned char uchar;     // 1 byte
//typedef unsigned short ushort;   // 2 byte
//typedef unsigned int uint;       // 4 byte
//typedef unsigned long ulong;     // 4 byte

#define ARP  "ARP"                 //
#define TCP  "TCP"                 //
#define UDP  "UDP"                 //
#define ICMP "ICMP"                //
#define DNS  "DNS"                 //
#define TLS  "TLS"                 //
#define SSL  "SSL"                 //
// Ethernet protocol format
/*
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/
typedef struct ether_header{   // 14 byte
    uchar ether_des_host[6];  // destination addr [6 byte]
    uchar ether_src_host[6];  // source addr [6 byte]
    ushort ether_type;        // type [2 byte]
}ETHER_HEADER;


// Ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           |R|D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocol  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct ip_header{           // 20 byte
    uchar versiosn_head_length;    // version [4 bit] and length of header [4 bit]
    uchar TOS;                     // TOS/DS_byte [1 byte]
    ushort total_length;           // ip package total length [2 byte]
    ushort identification;         // identification [2 byte]
    ushort flag_offset;            // flag [3 bit] and offset [13 bit]
    uchar ttl;                     // TTL [1 byte]
    uchar protocol;                // protocal [1 byte]
    ushort checksum;               // checksum [2 byte]
    uint src_addr;                 // source address [4 byte]
    uint des_addr;                 // destination address [4 byte]
}IP_HEADER;
// Tcp header
/*
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct tcp_header{    // 20 byte
    ushort src_port;         // source port [2 byte]
    ushort des_port;         // destination [2 byte]
    uint sequence;           // sequence number [4 byte]
    uint ack;                // Confirm serial number [4 byte]
    uchar header_length;     // header length [4 bit]
    uchar flags;             // flags [6 bit]
    ushort window_size;      // size of window [2 byte]
    ushort checksum;         // checksum [2 byte]
    ushort urgent;           // urgent pointer [2 byte]
}TCP_HEADER;

// Udp header
/*
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct udp_header{ // 8 byte
    ushort src_port;      // source port [2 byte]
    ushort des_port;      // destination port [2 byte]
    ushort data_length;   // data length [2 byte]
    ushort checksum;      // checksum [2 byte]

}UDP_HEADER;
// Icmp header
/*
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct icmp_header{         // at least 8 byte
    uchar type;                    // type [1 byte]
    uchar code;                    // code [1 byte]
    ushort checksum;               // checksum [2 byte]
    ushort identification;         // identification [2 byte]
    ushort sequence;               // sequence [2 byte]
}ICMP_HEADER;

//Arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct arp_header{   // 28 byte
    ushort hardware_type;   // hardware type [2 byte]
    ushort protocol_type;   // protocol [2 byte]
    uchar mac_length;       // MAC address length [1 byte]
    uchar ip_length;        // IP address length [1 byte]
    ushort op_code;         // operation code [2 byte]

    uchar src_eth_addr[6];  // source ether address [6 byte]
    uchar src_ip_addr[4];   // source ip address [4 byte]
    uchar des_eth_addr[6];  // destination ether address [6 byte]
    uchar des_ip_addr[4];   // destination ip address [4 byte]

}ARP_HEADER;
// dns
/*
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
|                       Queries                        |
+------------------------------------------------------+
|                       Answers                        |
+------------------------------------------------------+
|                Authoritative nameservers             |
+------------------------------------------------------+
|                  Additional records                  |
+------------------------------------------------------+
*/
typedef struct dns_header{  // 12 byte
    ushort identification; // Identification [2 byte]
    ushort flags;          // Flags [total 2 byte]
    ushort question;       // Question Number [2 byte]
    ushort answer;         // Answer RRs [2 byte]
    ushort authority;      // Authority RRs [2 byte]
    ushort additional;     // Additional RRs [2 byte]
}DNS_HEADER;

// dns question
typedef struct dns_question{
    // char* name;          // Non-fixed
    ushort query_type;     // 2 byte
    ushort query_class;    // 2 byte
}DNS_QUESITON;

typedef struct dns_answer{
    // char* name          // Non-fixed
    ushort answer_type;   // 2 byte
    ushort answer_class;  // 2 byte
    uint TTL;             // 4 byte
    ushort dataLength;    // 2 byte
    //char* name           // Non-fixed
}DNS_ANSWER;

#endif // FORMAT_H


