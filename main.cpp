#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

int main()
{
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   struct pcap_pkthdr header;	/* The header that pcap gives us */
   //const u_char *packet;		/* The actual packet */

   /* Define the device */
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }
   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   /* Grab a packet */
   while(1)
   {
       struct pcap_pkthdr * header;
       const u_char * packet;
       const int res = pcap_next_ex(handle, &header, &packet);
       if(res < 0)
       {
           break;
       }
       if(res == 0)
       {
           continue;
       }
       unsigned short L3_type = ntohs(*((unsigned short*)&(packet[12])));

       if(L3_type != 0x800)
       {
           continue;
       }
       unsigned char L4_type = *((unsigned char*)&(packet[23]));

       if(L4_type != 0x06)
       {
           continue;
       }
       unsigned char ip_hdrlen = (*((unsigned char*)&(packet[14])) << 4);
       ip_hdrlen = (ip_hdrlen >> 4) * 4;

       printf("------------------------------------------------------\n");
       printf("sm : %02x:%02x:%02x:%02x:%02x:%02x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
       printf("dm : %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
       printf("sip : %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
       printf("dip : %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
       printf("sport : %d\n", ntohs(*((unsigned short*)&(packet[ip_hdrlen+14]))));
       printf("dport : %d\n", ntohs(*((unsigned short*)&(packet[ip_hdrlen+16]))));
   }
   /* Print its length */
   printf("Jacked a packet with length of [%d]\n", header.len);
   /* And close the session */
   pcap_close(handle);
   return(0);
}
