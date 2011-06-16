/**
 * MO639 - Segurança de Redes
 * lab03 - DNS spoof
 * dns-spoof.c
 *
 * Gabriel Lorencetti Prado - 060999
 * Mauro Tardivo Filho      - 063140
 * Rodrigo Shizuo Yasuda    - 074358
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>


#define IP_SIZE 16
#define REQUEST_SIZE 100
#define PCAP_INTERFACENAME_SIZE 16
#define FILTER_SIZE 200
#define ETHER_ADDR_LEN  6

typedef struct _SpoofParams_ {
  char ip[IP_SIZE];                        /* ip address (xxx.xxx.xxx.xxx) */
  char request[REQUEST_SIZE];              /* request address (www.example.com) */
  char interface[PCAP_INTERFACENAME_SIZE]; /* interface name */
} SpoofParams;

/* ethernet header definition */
struct etherhdr{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* dst address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* src address */
  u_short ether_type; /* network protocol */
};

/* DNS header */
struct dnshdr {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};

/* Estrutura para uma pergunta DNS */
struct dns_query {
  char *qname;
  char qtype[2];
  char qclass[2];
};

/* Estrutura para uma resposta DNS */
struct dns_reply {
  char *name;
  char atype[2];
  char aclass[2];
  char ttl[4];
  char RdataLen[2];
  char *Rdata;
};

/**
 * Program usage
 */
void usage(char *prog_name){
  fprintf(stderr, "Usage:%s --interface <interface> --request <request> --ip <ip>\n", prog_name);
  exit(-1);
}

void parse_args(int argc, char *argv[], SpoofParams *spoof_params){
  
  unsigned int i; /* iterator */
  
  /* invalid parameters count */
  if(argc != 7){
    fprintf(stderr, "Too few parameters found.\n");
    usage(argv[0]);
  }
  
  for(i = 1; i < argc ; i++){
    if(!strcmp(argv[i], "--interface")){
      strncpy(spoof_params->interface, argv[++i], PCAP_INTERFACENAME_SIZE-1);
      spoof_params->interface[PCAP_INTERFACENAME_SIZE-1] = '\0';
    }
    
    if(!strcmp(argv[i], "--request")){
      strncpy(spoof_params->request, argv[++i], REQUEST_SIZE-1);
      spoof_params->request[REQUEST_SIZE-1] = '\0';
    }
    
    if(!strcmp(argv[i], "--ip")){
      strncpy(spoof_params->ip, argv[++i], IP_SIZE-1);
      spoof_params->ip[IP_SIZE-1] = '\0';
    }
  }
}

/**
 * Extracts the src ip from a ip header
 */
void extract_ip_from_iphdr(struct iphdr* ip, char* request_ip){
  
  int i;
  int aux[4];
  u_int32_t raw_ip;
  
  raw_ip = ip->saddr;
  for(i=0;i<4;i++){
    aux[i] = (raw_ip >> (i*8)) & 0xff;
  }
  
  sprintf(request_ip, "%d.%d.%d.%d",aux[0], aux[1], aux[2], aux[3]);
  
}

/**
 * Extracts DNS query and ip from packet
 */
void extract_dns_data(const u_char *packet, struct dns_query *dns, char* request_ip){
  struct etherhdr *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  struct dnshdr *dns_hdr;
  unsigned int ip_header_size;
  
  /* ethernet header */
  ether = (struct etherhdr*)(packet);

  /* ip header */
  ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
  extract_ip_from_iphdr(ip, request_ip);

  /* udp header */
  ip_header_size = ip->ihl*4;
  udp = (struct udphdr *)(((char*) ip) + ip_header_size);

  /* dns header */
  dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));

  dns->qname = ((char*) dns_hdr) + sizeof(struct dnshdr);
  
}

/**
 * Extracts the request from a dns query
 */
void extract_dns_request(struct dns_query *dns, char *request){
  unsigned int i, j, k;
  char *curr = dns->qname;
  unsigned int size;
  
  size = curr[0];

  /* monta nome da pergunta */
  j=0;
  i=1;
  while(size > 0){
    for(k=0; k<size; k++){
      request[j++] = curr[i+k];
    }
    request[j++]='.';
    i+=size; /* reposiciona indice */
    size = curr[i++];
  }
  request[--j] = '\0';
}

/**
 * Prints a terminal message with host IP and request
 */
void print_message(char* request, char* ip){
  printf("O host %s fez uma requisição a %s\n", ip, request);
}

/**
 * Callback function to handle packets
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  SpoofParams *spoof_params;
  struct dns_query dns;
  char request[REQUEST_SIZE];
  char ip[IP_SIZE];
  
  spoof_params = (SpoofParams*)args;
  
  extract_dns_data(packet, &dns, ip);
  extract_dns_request(&dns, request);
  
  if(!strcmp(request, spoof_params->request)){
    //build_dns_answer(spoof_params, mais parametros aqui - ip );
    print_message(request, ip);
  }
}

/**
 * Runs the filter
 */
void run_filter(SpoofParams *spoof_params){

  char filter[FILTER_SIZE];      /* filter expression */
  char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error messages buffer */
  struct bpf_program fp;         /* compiled filter */
  pcap_t *handle;

  handle = pcap_open_live(spoof_params->interface, /* device to sniff on */
                          1500,                    /* maximum number of bytes to capture per packet */
                          1,                       /* promisc - 1 to set card in promiscuous mode, 0 to not */
                          0,                       /* to_ms - amount of time to perform packet capture in milliseconds */
                                                   /* 0 = sniff until error */
                          errbuf);                 /* error message buffer if something goes wrong */

  if (handle == NULL)   /* there was an error */
  {
    fprintf (stderr, "%s", errbuf);
    exit (1);
  }

  if (strlen(errbuf) > 0)
  {
    fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
    errbuf[0] = 0;    /* reset error buffer */
  }
  
  /* only DNS */
  sprintf(filter, "udp and dst port domain");
  
  /* compiles the filter expression */
  if(pcap_compile(handle, &fp, filter, 0, 0) == -1){
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    exit(-1);
  }
  
  /* applies the filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
    exit(-1);
  }
  
  /* loops through the packages */
  pcap_loop(handle, -1, handle_packet, (u_char*)spoof_params);
  
  /* frees the compiled filter */
  pcap_freecode(&fp);
  
  /* closes the handler */
  pcap_close(handle);
}

int main(int argc, char **argv){
  SpoofParams spoof_params; /* arguments */
  
  parse_args(argc, argv, &spoof_params);
  
  run_filter(&spoof_params);
  
  return 0;
}