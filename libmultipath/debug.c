/*
 * Copyright (c) 2005 Christophe Varoqui
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "log_pthread.h"
#include <sys/types.h>
#include <time.h>
#include "../third-party/valgrind/drd.h"
#include "vector.h"
#include "config.h"
#include "defaults.h"
#include "debug.h"
#include "time-util.h"
#include "util.h"

void dlog (int sink, int prio, const char * fmt, ...)
{
	va_list ap;
	int thres;
	struct config *conf;

	va_start(ap, fmt);
	conf = get_multipath_config();
	ANNOTATE_IGNORE_READS_BEGIN();
	thres = (conf) ? conf->verbosity : DEFAULT_VERBOSITY;
	ANNOTATE_IGNORE_READS_END();
	put_multipath_config(conf);

	if (prio <= thres) {
		if (sink < 1) {
			if (sink == 0) {
				struct timespec ts;
				char buff[32];

				get_monotonic_time(&ts);
				safe_sprintf(buff, "%ld.%03ld",
					     (long)ts.tv_sec,
					     ts.tv_nsec/1000000);
				fprintf(stderr, "%s | ", buff);
			}
			vfprintf(stderr, fmt, ap);
		}
		else
			log_safe(prio + 3, fmt, ap);
	}
	va_end(ap);
}
