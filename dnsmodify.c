#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
struct iphdr *iph;
struct udphdr *udp_header;
struct sk_buff *sock_buff;
unsigned int sport, dport;

unsigned int hook_func(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
    //NOTE: Feel free to uncomment printks! If you are using Vagrant and SSH
     //      too many printk's will flood your logs.
    //printk(KERN_INFO "=== BEGIN HOOK ===\n");

    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (!iph) {
        //printk(KERN_INFO "no ip header\n");
        return NF_ACCEPT;
    }

    if(iph->protocol==IPPROTO_UDP) {
        udp_header = udp_hdr(sock_buff);
        dport = htons((unsigned short int) udp_header->dest);
	if (dport == 53) {
            sport = htons((unsigned short int) udp_header->source);
	    char hex[sock_buff->len*2];
	    bin2hex(hex, sock_buff->data, sock_buff->len);
            printk(KERN_INFO "UDP ports: source: %d, dest: %d \n", sport, dport);
            printk(KERN_INFO "UDP ports: data: %s\n", hex);
            //printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
	    
	    char* search = { 0x01, "t", 0x06, "danman", 0x02, "eu" };
	    int search_len = 12;
	    int j = 0;
	    int i = 0;

	    for (i = 0; i<sock_buff->len; i++) {
		if (sock_buff->data[i] == search[j]){
                    printk(KERN_INFO "match %x: %x %x\n",search[j], i, j);
		    j++;
		} else {
			if (j == 12) {
        	            printk(KERN_INFO "found\n");
			    return NF_ACCEPT;
			}
			if (j > 0) {
				i--;
				j = 0;
			}
		}
	    }
	}

	return NF_ACCEPT;
    }

    /*
    if(iph->protocol==IPPROTO_ICMP) {
        printk(KERN_INFO "=== BEGIN ICMP ===\n");
        printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        iph->saddr = iph->saddr ^ 0x10000000;
        printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
        printk(KERN_INFO "=== END ICMP ===\n");

    }
    */

    //if(in) { printk(KERN_INFO "in->name:  %s\n", in->name); }
    //if(out) { printk(KERN_INFO "out->name: %s\n", out->name); }
    //printk(KERN_INFO "=== END HOOK ===\n");
    return NF_ACCEPT;        

}

static int __init initialize(void) {
    nfho.hook = hook_func;
    //nfho.hooknum = NF_INET_PRE_ROUTING;
    //Interesting note: A pre-routing hook may not work here if our Vagrant
    //                  box does not know how to route to the modified source.
    //                  For the record, mine did not.
    nfho.hooknum = NF_INET_PRE_ROUTING;
    //nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    return 0;    
}

static void __exit teardown(void) {
    nf_unregister_hook(&nfho);
}

module_init(initialize);
module_exit(teardown);

