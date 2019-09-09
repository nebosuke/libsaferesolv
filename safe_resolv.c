// vim: noai:ts=4:sw=4: et
/*
The MIT License (MIT)

Copyright (c) 2019 @kensuke_ishida

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <dlfcn.h>
#include <pthread.h>

#define MAX_NUM_ENTRIES 100
#define CACHE_AGE_SECS (24 * 3600)

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void fini() __attribute__((destructor));

__attribute__((visibility("internal")))
void *__load_func(const char *symbol)
{
    char *error;
    void *ret = dlsym(RTLD_NEXT, symbol);
    if ((error = dlerror()) != NULL) {
        exit(EXIT_FAILURE);
    }
    return ret;
}

typedef struct resolved_addrinfo_entry
{
    struct resolved_addrinfo_entry *next;
    struct resolved_addrinfo_entry *prev;
    char *node;
    struct addrinfo *hints;
    struct addrinfo *res;
    time_t timestamp;
} resolved_addrinfo_entry;

static struct resolved_addrinfo_entry *first = NULL;
static struct resolved_addrinfo_entry *last = NULL;

static int num_entries = 0;

static struct resolved_addrinfo_entry *free_resolved_addrinfo_entry(struct resolved_addrinfo_entry *cur)
{
    static void (*libc_freeaddrinfo)(struct addrinfo *res) = NULL;
    if (!libc_freeaddrinfo) {
        libc_freeaddrinfo = __load_func("freeaddrinfo");
    }
    if (!cur) {
        return NULL;
    }

    free(cur->node);

    if (cur->hints) {
        free(cur->hints);
    }
    if (cur->res) {
        libc_freeaddrinfo(cur->res);
    }

    struct resolved_addrinfo_entry *next = cur->next;

    free(cur);

    return next;
}

static void append_resolved_addrinfo_entry(const char *node, const struct addrinfo *hints, struct addrinfo *res)
{
    resolved_addrinfo_entry *entry = (resolved_addrinfo_entry *) calloc(sizeof(resolved_addrinfo_entry), 1);

    entry->node = (char *) calloc(1, strlen(node) + 1);
    strcpy(entry->node, node);

    if (hints) {
        entry->hints = (struct addrinfo *) calloc(sizeof(struct addrinfo), 1);
        entry->hints->ai_flags = hints->ai_flags;
        entry->hints->ai_family = hints->ai_family;
        entry->hints->ai_socktype = hints->ai_socktype;
        entry->hints->ai_protocol = hints->ai_protocol;
    }

    entry->res = res;

    struct timeval now;
    gettimeofday(&now, NULL);
    entry->timestamp = now.tv_sec;

    pthread_mutex_lock(&lock);
    {
        if (first) {
            last->next = entry;
            entry->prev = last;
            last = entry;
        } else {
            first = last = entry;
        }

        num_entries++;

        while (num_entries > MAX_NUM_ENTRIES) {
            first = free_resolved_addrinfo_entry(first);
            first->prev = NULL;
            num_entries--;
        }
    }
    pthread_mutex_unlock(&lock);
}

static struct addrinfo * find_resolved_addrinfo(const char *node, const struct addrinfo *hints)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    time_t threshold = now.tv_sec - CACHE_AGE_SECS;

    pthread_mutex_lock(&lock);

    resolved_addrinfo_entry *cur = last;
    while (cur) {
        if (cur->timestamp > threshold) {
            if (0 == strcmp(node, cur->node)) {
                if (hints && hints->ai_flags == cur->hints->ai_flags
                          && hints->ai_family == cur->hints->ai_family
                          && hints->ai_socktype == cur->hints->ai_socktype
                          && hints->ai_protocol == cur->hints->ai_protocol) {
                    pthread_mutex_unlock(&lock);
                    return cur->res;
                } else if (cur->hints == NULL) {
                    pthread_mutex_unlock(&lock);
                    return cur->res;
                }
            }
        }
        cur = cur->prev;
    }

    pthread_mutex_unlock(&lock);

    return NULL;
}

__attribute__((visibility("default")))
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    static int (*libc_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
    static void (*libc_freeaddrinfo)(struct addrinfo *res) = NULL;

    int ret;

    if (!libc_getaddrinfo) {
        libc_getaddrinfo = __load_func("getaddrinfo");
    }
    if (!libc_freeaddrinfo) {
        libc_freeaddrinfo = __load_func("freeaddrinfo");
    }

    ret = libc_getaddrinfo(node, service, hints, res);
    if (ret != 0) {
        *res = find_resolved_addrinfo(node, hints);
        if (*res) {
            ret = 0;
        }
    } else {
        int i = 0;
        for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
            i += 1;
        }
        if (i > 0) {
            append_resolved_addrinfo_entry(node, hints, *res);
        } else {
            libc_freeaddrinfo(*res);
            *res = find_resolved_addrinfo(node, hints);
        }
    }
    return ret;
}

__attribute__((visibility("default")))
void freeaddrinfo(struct addrinfo *res)
{
    // overwrite freeaddrinfo as emtpy function
}

static void fini()
{
    pthread_mutex_lock(&lock);
    if (first) {
        struct resolved_addrinfo_entry *cur = first;
        while (cur) {
            cur = free_resolved_addrinfo_entry(cur);
        }
        first = last = NULL;
    }
    pthread_mutex_unlock(&lock);
}
