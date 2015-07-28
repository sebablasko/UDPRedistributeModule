
#define MODULE_NAME "UDPRedistributeModule"

#define DEFAULT_HOOK_PORT 13131
#define DEFAULT_VERBOSE_LEVEL 2
#define DEFAULT_START_REDIRECT_PORT 1820
#define DEFAULT_NUMBER_REDIRECT_PORTS 1

static unsigned int hook_func(
                unsigned int hooknum,
                struct sk_buff *skb, 
                const struct net_device *in, 
                const struct net_device *out, 
                int (*okfn)(struct sk_buff *)
                );

void printOptions(void);