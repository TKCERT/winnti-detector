//******************************************************************************
//
// *** WINNTI session setup detector ***
//
// This program detects initial connection attempts from WINNTI malware.
//
// AUTHOR: Stefan Ruester
// DATE:   2016-07-05
// TLP:    WHITE
// 
//******************************************************************************

/* #############################################################################
   ### INCLUDES
   ########################################################################## */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include "nids.h"

/* #############################################################################
   ### MACROS
   ########################################################################## */

#define WINTIDECT_VERISON   "1.6"
#define int_ntoa(x)         inet_ntoa(*((struct in_addr *)&x))

/* #############################################################################
   ### ENUMS
   ########################################################################## */

enum OP_MODE {
    MODE_UNDEFINED,
    MODE_READ_PCAP,
    MODE_LIVE_INTERFACE
};

/* #############################################################################
   ### GLOBALS
   ########################################################################## */

int opt_SYSLOG = 0;
const char * PRGNAME = "";
enum OP_MODE mode = MODE_UNDEFINED;

/* #############################################################################
   ### FUNCTIONS
   ########################################################################## */

void fill_adr_strings (struct tuple4 addr, char src_ip[46], char dst_ip[46], int *sport, int *dport)
{
    strncpy(src_ip, int_ntoa(addr.saddr), 46); src_ip[45] = '\0';
    strncpy(dst_ip, int_ntoa(addr.daddr), 46); dst_ip[45] = '\0';
    *sport = addr.source;
    *dport = addr.dest;
}


/* Returns 0 if winnti signature matches. Returns != 0 otherwise */
uint16_t check_for_winnti(char *data, size_t len)
{
    if(len < 16)
        return 1;

    uint16_t *w = (uint16_t *)data;
    uint32_t *l = (uint32_t *)data;

    // Three conditions hold for the first 8 words of winnti traffic:
    //   w[0] ^ w[4] ^ w[7] = 0x0000
    //   w[1] ^ w[5] ^ w[6] = 0x0000
    //   w[x] != 0
    //   l[2] usually contains a timestamp
    if(!l[0] || !l[1] || !l[2] || !l[3])
        return 1;

    return (w[0] ^ w[4] ^ w[7]) | (w[1] ^ w[5] ^ w[6]);

}


void tcp_callback (struct tcp_stream *tcp, void **param)
{
    struct half_stream *hlf;
    char src_ip[46], dst_ip[46];
    int  sport, dport;
    static char sbuf[1000];


    switch(tcp->nids_state)
    {
        // Connection has just been established
        case NIDS_JUST_EST:
            tcp->server.collect++;  // Collect data that is sent to server
            break;

        // Received some data
        case NIDS_DATA:
            hlf = &tcp->server;

            // Stop collecting packets
            tcp->server.collect = 0;

            // We are only interested in the first bytes of a connection
            if(tcp->server.offset != 0)
                break;

            // Check for signs of a winnti connection
            if(check_for_winnti(hlf->data, tcp->server.count_new) != 0)
                break;

            // Get IP addresses and ports
            fill_adr_strings(tcp->addr, src_ip, dst_ip, &sport, &dport);

            // Build alert message
            snprintf(sbuf, sizeof(sbuf), "Found WINNTI session setup: (TCP) %s:%i -> %s:%i",
                      src_ip, sport, dst_ip, dport);
            
            // Make UTC timestamp of last PCAP packet
            struct tm tm;
            struct timeval *tv = &nids_last_pcap_header->ts;
            gmtime_r(&tv->tv_sec, &tm);
            
            // Get timestamp
            char tstamp[64];
            strftime(tstamp, 64, "%Y-%m-%d %H:%M:%S", &tm);
            
            // Print alert to stdout
            printf("[!] %s.%06ldZ %s\n", tstamp, tv->tv_usec, sbuf);
            fflush(stdout);

            // Write syslog entry if required
            if(opt_SYSLOG)
            {
                syslog(LOG_LOCAL7 | LOG_ALERT, "%s", sbuf);
            }

        case NIDS_CLOSE:
        case NIDS_RESET:
        case NIDS_TIMED_OUT:
            // Connection terminated
            break;

        default:
            break;
    }
}

void udp_callback (struct tuple4 *addr, char *buf, int len, struct ip *iph)
{
    char src_ip[46], dst_ip[46];
    int  sport, dport;
    static char sbuf[1000];

    // Check for signs of a winnti connection
    if(check_for_winnti(buf, len) != 0)
        return;

    // Get IP addresses and ports
    fill_adr_strings(*addr, src_ip, dst_ip, &sport, &dport);

    // Build alert message
    snprintf(sbuf, sizeof(sbuf), "Found WINNTI session setup: (UDP) %s:%i -> %s:%i",
          src_ip, sport, dst_ip, dport);
            
    // Make UTC timestamp of last PCAP packet
    struct tm tm;
    struct timeval *tv = &nids_last_pcap_header->ts;
    gmtime_r(&tv->tv_sec, &tm);
            
    // Get timestamp
    char tstamp[64];
    strftime(tstamp, 64, "%Y-%m-%d %H:%M:%S", &tm);
            
    // Print alert to stdout
    printf("[!] %s.%06ldZ %s\n", tstamp, tv->tv_usec, sbuf);
    fflush(stdout);

    // Write syslog entry if required
    if(opt_SYSLOG)
    {
        syslog(LOG_LOCAL7 | LOG_ALERT, "%s", sbuf);
    }
}


void nids_syslog(int type, int err, struct ip *iph, void *data)
{
    return;
}

void usage()
{
    printf(
        "Usage: %s <-i device|-f pcapfile> [-l]\n"
        "  -l  Log to syslog (local7.alert 'nsm')\n",
        PRGNAME);
    exit(1);
}

int main(int argc, char * const *argv)
{

    PRGNAME = argv[0];

    fprintf(stderr, "wntidect version %s using libnids %i.%i -- Stefan Ruester\n", WINTIDECT_VERISON, NIDS_MAJOR, NIDS_MINOR);

    // Enable TCP workarounds
    nids_params.tcp_workarounds = 1;

    // Disable portscan detection
    nids_params.scan_num_hosts = 0;

    // Disable logging by libnids
    nids_params.syslog = &nids_syslog;

    // Disable checksum checks
    struct nids_chksum_ctl cksum_ctl = {
        .netaddr = 0,
        .mask    = 0,
        .action  = NIDS_DONT_CHKSUM
    };
    nids_register_chksum_ctl(&cksum_ctl, 1);

    // Read command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "i:f:l")) != -1)
    {
        switch(opt)
        {
        case 'f':
            if(mode != MODE_UNDEFINED)
                usage();
            mode  = MODE_READ_PCAP;
            nids_params.filename = optarg;
            fprintf(stderr, "[i] Reading PCAP file %s\n", argv[2]);
            break;

        case 'i':
            if(mode != MODE_UNDEFINED)
                usage();
            mode = MODE_LIVE_INTERFACE;
            nids_params.device = optarg;
            fprintf(stderr, "[i] Reading from device %s\n", argv[2]);
            break;

        case 'l':
            opt_SYSLOG = 1;
            openlog("nsm", 0, LOG_LOCAL7);
            break;            

        default:
            usage();
        }
    }

    if(mode == MODE_UNDEFINED)
    {
        usage();
    }

    // Initialize NDIS library
    if(!nids_init())
    {
        fprintf(stderr,"%s\n", nids_errbuf);
        exit(1);
    }

    fflush(stdout);

    // Register callback functions
    nids_register_tcp (tcp_callback);
    nids_register_udp (udp_callback);

    // Start capture
    nids_run ();

    return 0;
}


