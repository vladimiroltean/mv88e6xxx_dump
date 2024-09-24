/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UTILS_H__
#define __UTILS_H__ 1

#include <sys/types.h>
#include <asm/types.h>
#include <resolv.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <time.h>

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef LIST_FOREACH_SAFE
#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#endif /* __UTILS_H__ */
