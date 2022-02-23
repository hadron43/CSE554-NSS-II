/*****************************************************
 * This code was compiled and tested on Artix Linux
 * with kernel version 5.16.1
 *****************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

static struct nf_hook_ops *nfho = NULL;

MODULE_LICENSE("GPL-2.0");
MODULE_DESCRIPTION("Netfilter kernel module");

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_TCP) {
		// TCP packet detected

		// extract tcp header
		tcph = (struct tcphdr *) skb_transport_header(skb);

		// NULL scan
		if (tcph -> syn == 0 && tcph -> ack == 0
				&& tcph -> fin == 0 && tcph -> urg == 0
				&& tcph -> rst == 0 && tcph -> psh == 0) {

			printk("NULL scan detected!");
			return NF_DROP;
		}

		// FIN Scan
		else if(tcph -> syn == 0 && tcph -> ack == 0
				&& tcph -> fin == 1 && tcph -> urg == 0
				&& tcph -> rst == 0 && tcph -> psh == 0) {

			printk("FIN scan detected!");
			return NF_DROP;
		}


		// XMAS Scan
		else if(tcph -> syn == 0 && tcph -> ack == 0
				&& tcph -> fin == 1 && tcph -> urg == 1
				&& tcph -> rst == 0 && tcph -> psh == 1) {

			printk("XMAS Scan detected!");
			return NF_DROP;
		}
	}

	// by default, accept
	return NF_ACCEPT;
}

static int __init LKM_init(void) {
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	nfho->priority 	= NF_IP_PRI_FIRST;
	nfho->hook 	= (nf_hookfn*)hfunc;
	nfho->pf 	= PF_INET;
	nfho->hooknum 	= NF_INET_PRE_ROUTING;

	nf_register_net_hook(&init_net, nfho);
	return 0;
}

static void __exit LKM_exit(void) {
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);
