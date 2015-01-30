/*
   +----------------------------------------------------------------------+
   | Suhosin-Patch for PHP                                                |
   +----------------------------------------------------------------------+
   | Copyright (c) 2004-2009 Stefan Esser                                 |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.02 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available at through the world-wide-web at                           |
   | http://www.php.net/license/2_02.txt.                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Stefan Esser <stefan.esser@sektioneins.de>                   |
   +----------------------------------------------------------------------+
 */
/* $Id: zend_canary.c,v 1.1 2004/11/26 12:45:41 ionic Exp $ */

#include "zend.h"

#include <stdio.h>
#include <stdlib.h>


#if SUHOSIN_PATCH

static size_t last_canary = 0x73625123;

/* will be replaced later with more compatible method */
ZEND_API void zend_canary(void *buf, int len)
{
	time_t t;
	size_t canary;
	int fd;
	
#ifndef PHP_WIN32
	fd = open("/dev/urandom", 0);
	if (fd != -1) {
		int r = read(fd, buf, len);
		close(fd);
		if (r == len) {
			return;
		}
	}
#endif	
	/* not good but we never want to do this */
	time(&t);
	canary = *(unsigned int *)&t + getpid() << 16 + last_canary;
	last_canary ^= (canary << 5) | (canary >> (32-5));
	/* When we ensure full win32 compatibility in next version
	   we will replace this with the random number code from zend_alloc.c */
        memcpy(buf, &canary, len);
}

#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
