#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include "UDPRedistributeModule.h"

static struct nf_hook_ops nfho; 
static int verbose = DEFAULT_VERBOSE_LEVEL;
static int hook_port = DEFAULT_HOOK_PORT;
static int number_redirect_ports = DEFAULT_NUMBER_REDIRECT_PORTS;
static int start_redirect_port = DEFAULT_START_REDIRECT_PORT;

  /*  Get params from insmod  */
module_param(hook_port, int, 0);
module_param(verbose, int, 0);
module_param(number_redirect_ports, int, 0);
module_param(start_redirect_port, int, 0);

int init_module(){
        nfho.hook     = hook_func;
        nfho.hooknum  = NF_INET_PRE_ROUTING;                                           
        nfho.pf       = PF_INET;                                                            
        nfho.priority = NF_IP_PRI_FIRST;                                              
 
        nf_register_hook(&nfho);                                                     
        printk(KERN_INFO "%s: Activated\n", MODULE_NAME);
        printOptions();
        return 0;
}

void cleanup_module()
{
        nf_unregister_hook(&nfho);     
        printk(KERN_INFO "%s: Removed \n", MODULE_NAME);
}

void printOptions(void){
        int i;
        printk(KERN_INFO "%s: Options:\n", MODULE_NAME);
        printk(KERN_INFO "\tVerbosity Level:\t %d\n", verbose);
        printk(KERN_INFO "\tHooking Port:\t %d\n", hook_port);
        printk(KERN_INFO "\tRedirect to %d Ports\n", number_redirect_ports);
        for (i = 0; i < number_redirect_ports; i++) {
                printk(KERN_INFO "\t\t%d\n", (start_redirect_port+i));
        }
}

static unsigned int hook_func(
                unsigned int hooknum,
                struct sk_buff *skb, 
                const struct net_device *in, 
                const struct net_device *out, 
                int (*okfn)(struct sk_buff *)
                ){

  struct iphdr *iph;
  struct udphdr *udph;

  if (!skb)
    return NF_ACCEPT;

  if (skb->pkt_type != PACKET_HOST)
    return NF_ACCEPT;

  iph = ip_hdr(skb);
  if (!iph)
    return NF_ACCEPT;

  if (iph->protocol == IPPROTO_UDP){

    if(verbose > 2)
      printk("%s: skb %p len %u data_len %u\n", MODULE_NAME, skb, skb->len, skb->data_len);

    if(verbose > 2)
     printk("%s: IP at [%i] in %s out %s %pI4 -> %pI4 proto %hhu\n",
        MODULE_NAME,
        (int)((u8 *)iph - (u8 *)skb->data),
        in->name,
        out->name, 
        &(iph->saddr), 
        &(iph->daddr), 
        iph->protocol);    

    skb_set_transport_header(skb, iph->ihl * 4 + (char*) iph - (char*) skb->data);

    udph = udp_hdr(skb);

    if(verbose > 2)
      printk("%s: UDP at [%i]: %hu -> %hu len %hu\n",
        MODULE_NAME,
        (int)((char*) udph - (char*) iph),
        ntohs(udph->source),
        ntohs(udph->dest), 
        ntohs(udph->len));

    if(ntohs(udph->dest)==hook_port){
      unsigned int i;
      get_random_bytes(&i, sizeof(i));

      udph->dest=(unsigned short) htons(start_redirect_port+(i%number_redirect_ports));
      if(verbose > 1)
        printk("%s: Updated to %hu\n", MODULE_NAME, ntohs(udph->dest));
    }
  }

  return NF_ACCEPT;
}

MODULE_DESCRIPTION("Modulo de redistribución para paquetes UDP");
MODULE_AUTHOR("Sebastian Blasco");
MODULE_VERSION("0.1") ;
MODULE_LICENSE ("GPL");