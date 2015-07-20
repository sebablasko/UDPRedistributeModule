#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include "utilities.h"

        /* Especifico valor por defecto de parametros que configuran el modulo */
#define _target_hook_protocol_ IPPROTO_UDP              // Corresponde a 17 = UDP
static int _target_hook_port_ = 13131;
static int _redirect_ports_[1024];
static int _redirect_ports_argc_ = 0;
static int verbose = 2;

        /* Habilito opcion para modificar las varibales si me las pasan al instalar el modulo */
module_param(_target_hook_port_, int, 0);
module_param(verbose, int, 0);
module_param_array(_redirect_ports_, int, &_redirect_ports_argc_, 0);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Modulo de redistribución para paquetes UDP");
MODULE_AUTHOR("Sebastian Blasco");
 
static struct nf_hook_ops nfho;                          // Net filter hook option struct
struct udphdr *udp_header;                               // Transport Layer (UDP) header struct
struct iphdr *ip_header;                                 // Internet Layer (IP) header struct


__be16 udp_checksum(struct iphdr* iphdr, struct udphdr* udphdr, unsigned char* data){
        __be32 sum = 0;
        __be16 proto = 0x1100;                           // 17 udp
        __be16 data_length = (__be16) ntohs(udphdr->len) - sizeof(struct udphdr);
        __be16 src[2];
        __be16 dest[2];
        __be16 *padded_data;
        int padded_data_length, i;

        if(data_length % 2 != 0)
                padded_data_length = (int) data_length / 2 + 1;
        else
                padded_data_length = (int) data_length / 2;

        padded_data = alloc(padded_data_length, __be16);
        padded_data[padded_data_length - 1] = 0;
        memcpy(padded_data,data, data_length);

        src[0] = (__be16) (iphdr->saddr >> 16);
        src[1] = (__be16) (iphdr->saddr);
        dest[0] = (__be16) (iphdr->daddr >> 16);
        dest[1] = (__be16) (iphdr->daddr);

        data_length = (__be16) htons(data_length);

        sum = src[0] + src[1] + dest[0] + dest[1] + proto + udphdr->len + udphdr->source + udphdr->dest + udphdr->len;

        for(i = 0; i < padded_data_length; i++)
                sum += padded_data[i];

        while(sum >> 16)
                sum = (__be16) (sum & 0xFFFF) + (__be16) (sum >> 16);

        dealloc(padded_data);

        return (__be16) ~sum;
}


        /* Función que ejecutará el hook sobre cada paquete interceptado */
unsigned int hook_func(
                unsigned int hooknum,
                struct sk_buff *skb, 
                const struct net_device *in, 
                const struct net_device *out, 
                int (*okfn)(struct sk_buff *)
                ){

        unsigned int src_ip, dest_ip, src_port, dest_port;
        unsigned char* transport_data;

        /* Determino si el paquete es vacio, en caso contrario, lo proceso */
        if(!skb) {
                if(verbose > 0) printk(KERN_INFO "Es un paquete vacio \n");
                return NF_ACCEPT;
        }
 
        ip_header = (struct iphdr *)skb_network_header(skb);                            // Tomar el header de red

        /* Recuperar información del Header IP */
        src_ip = (unsigned int)ip_header->saddr;                                        // Source IP
        dest_ip = (unsigned int)ip_header->daddr;                                       // Dest IP
        src_port = 0;
        dest_port = 0;
 
        /* Verifico si es paquete del protocolo deseado */
        if (ip_header->protocol == _target_hook_protocol_) {                            // Revisar que sea protocolo UDP en el header de red

                //udp_header = (struct udphdr *)(skb_transport_header(skb)+20);         // El hack!!!!
                udp_header = (struct udphdr *)skb_transport_header(skb);                // Tomar el header de transporte

                /* Obtener datos de los puertos del header UDP */
                src_port = (unsigned int)ntohs(udp_header->source);                     // Source Port
                dest_port = (unsigned int)ntohs(udp_header->dest);                      // Dest Port

                transport_data = skb->data + sizeof(struct iphdr) + sizeof(struct udphdr);               

                /* Verifico si el puerto destino es el especificado */
                if(dest_port == _target_hook_port_){
                        
                        unsigned int i, updated_dest_port;

                        /* Determino a cual puerto será redirijido el paquete */
                        get_random_bytes(&i, sizeof(i));
                        //updated_dest_port = _redirect_ports_[i%(sizeof(_redirect_ports_)/sizeof(_redirect_ports_[0]))];
                        updated_dest_port = _redirect_ports_[i%_redirect_ports_argc_];

                        if(verbose > 0)
                                printk(KERN_INFO "UDPRedistributeModule: UPDATE DestPort: %u -> %u\n",
                                        ntohs(udp_header->dest),
                                        updated_dest_port);

                        if(verbose > 1)
                                printk(KERN_INFO "UDPRedistributeModule: UPDATE Checksum: %u -> %u\n",
                                        udp_header->check,
                                        udp_checksum(ip_header, udp_header, transport_data));

                        /* Realizo la mutacion del paquete */
                        udp_header->dest = (unsigned short) htons(updated_dest_port);
                        udp_header->check = udp_checksum(ip_header, udp_header, transport_data);

                        if(verbose > 1)
                                printk(KERN_INFO "UDPRedistributeModule: Final Package SOURCE: %pI4:%u; DEST: %pI4:%u; \tCS:%u\n",
                                                                &ip_header->saddr,
                                                                (unsigned int)ntohs(udp_header->source),
                                                                &ip_header->daddr,
                                                                (unsigned int)ntohs(udp_header->dest),
                                                                udp_header->check);

                }

                //return NF_DROP;                                                       //Descarta el paquete
                return NF_ACCEPT;                                                       //Deja pasar el paquete
        }
               
        return NF_ACCEPT;
}
 
int init_module()
{
        int i;

        nfho.hook = hook_func;                                                          //Funcion para interceptar los paquetes
        nfho.hooknum = NF_INET_PRE_ROUTING;                                             //Cuales paquetes (desde cuando) los intercepto
        nfho.pf = PF_INET;                                                              //lo mismo que AF-FAMILY (Protocol/Address family)
        nfho.priority = NF_IP_PRI_FIRST;                                                //Prioridad para mi filtro
 
        nf_register_hook(&nfho);                                                        //registra mi interceptor

        printk(KERN_INFO "UDPRedistributeModule: Activado con opciones:\n");
        printk(KERN_INFO "\tNivel de verbosidad %d\n", verbose);
        printk(KERN_INFO "\tPuerto a Interceptar %d\n", _target_hook_port_);
        printk(KERN_INFO "\tRedirigir a %d puertos \n", _redirect_ports_argc_);
        for (i = 0; i < _redirect_ports_argc_; i++) {
                printk(KERN_INFO "\t\t%d\n", _redirect_ports_[i]);
        }
       
        return 0;
}
 
void cleanup_module()
{
        nf_unregister_hook(&nfho);     
        printk(KERN_INFO "UDPRedistributeModule: Eliminado \n");
}