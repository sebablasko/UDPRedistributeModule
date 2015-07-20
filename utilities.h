#ifndef __UTILITIES_H__
#define __UTILITIES_H__

#include <linux/vmalloc.h>

#define alloc(TSIZE,TYPE)\
  (TYPE*) kmalloc(TSIZE * sizeof(TYPE), GFP_KERNEL);

#define dealloc(PTR)\
  kfree(PTR)

#define null NULL

#endif
