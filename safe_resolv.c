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
#include <arpa/inet.h>
#include <sys/time.h>
#include <dlfcn.h>
#include <pthread.h>

#define MAX_NUM_ENTRIES_PER_NODE 5
#define CACHE_AGE_SECS (24 * 3600)
#define LOG stderr

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static time_t last_dump_timestamp_sec = 0;

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

typedef struct per_node_root
{
    struct per_node_root *next;
    struct per_node_root *prev;
    char *node;
    struct resolved_addrinfo_entry *first;
    struct resolved_addrinfo_entry *last;
    int num_entries;
} per_node_root;

typedef struct resolved_addrinfo_entry
{
    struct resolved_addrinfo_entry *next;
    struct resolved_addrinfo_entry *prev;
    struct addrinfo *hints;
    struct addrinfo *res;
    time_t timestamp;
} resolved_addrinfo_entry;

static struct per_node_root *first = NULL;
static struct per_node_root *last = NULL;

static struct per_node_root *get_per_node_root(const char *node)
{
    per_node_root *cur = first;
    while (cur) {
        if (0 == strcmp(cur->node, node)) {
            return cur;
        }
        cur = cur->next;
    }

    cur = (per_node_root *) calloc(sizeof(per_node_root), 1);
    cur->node = (char *) calloc(1, strlen(node) + 1);
    strcpy(cur->node, node);

    if (first) {
        cur->prev = last;
        last->next = cur;
        last = cur;
    } else {
        first = last = cur;
    }

    return cur;
}

static struct resolved_addrinfo_entry *free_resolved_addrinfo_entry(resolved_addrinfo_entry *cur)
{
    static void (*libc_freeaddrinfo)(struct addrinfo *res) = NULL;
    if (!libc_freeaddrinfo) {
        libc_freeaddrinfo = __load_func("freeaddrinfo");
    }
    if (!cur) {
        return NULL;
    }

    if (cur->hints) {
        free(cur->hints);
    }
    if (cur->res) {
        libc_freeaddrinfo(cur->res);
    }

    resolved_addrinfo_entry *next = cur->next;

    free(cur);

    return next;
}

static struct per_node_root *free_per_node_root(per_node_root *cur)
{
    resolved_addrinfo_entry *cur_addrinfo_entry = cur->first;
    while (cur_addrinfo_entry) {
        cur_addrinfo_entry = free_resolved_addrinfo_entry(cur_addrinfo_entry);
        cur->num_entries -= 1;
    }
    per_node_root *next = cur->next;

    free(cur->node);
    free(cur);

    return next;
}

static void dump_all_entries()
{
    struct in_addr addr;

    time_t now = time(NULL);
    struct tm *ts;
    char sz_time[80];

    ts = localtime(&now);
    strftime(sz_time, sizeof(sz_time), "%Y-%m-%d %H:%M:%S", ts);

    per_node_root *cur = first;

    while (cur) {
        resolved_addrinfo_entry *resolved = cur->last;
        addr.s_addr= ((struct sockaddr_in *)(resolved->res->ai_addr))->sin_addr.s_addr;
        fprintf(LOG, "### dump cached resolved_addrinfo_entry: time=%s, node=%s, addr=%s\n", sz_time, cur->node, inet_ntoa(addr));
        cur = cur->next;
    }
}

static void append_resolved_addrinfo_entry(const char *node, const struct addrinfo *hints, struct addrinfo *res)
{
    resolved_addrinfo_entry *entry = (resolved_addrinfo_entry *) calloc(sizeof(resolved_addrinfo_entry), 1);

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
        per_node_root *root = get_per_node_root(node);

        if (root->first) {
            root->last->next = entry;
            entry->prev = root->last;
            root->last = entry;
        } else {
            root->first = root->last = entry;
        }

        root->num_entries += 1;

        while (root->num_entries > MAX_NUM_ENTRIES_PER_NODE) {
            root->first = free_resolved_addrinfo_entry(root->first);
            root->first->prev = NULL;
            root->num_entries -= 1;
        }

        if (last_dump_timestamp_sec < (now.tv_sec - 60)) {
            dump_all_entries();
            last_dump_timestamp_sec = now.tv_sec;
        }
    }
    pthread_mutex_unlock(&lock);
}

static struct addrinfo * find_resolved_addrinfo(const char *node, const struct addrinfo *hints)
{
    struct in_addr addr;
    struct timeval now;
    gettimeofday(&now, NULL);
    time_t threshold = now.tv_sec - CACHE_AGE_SECS;

    pthread_mutex_lock(&lock);
    {
        per_node_root *root = get_per_node_root(node);
        resolved_addrinfo_entry *cur = root->last;
        while (cur) {
            if (cur->timestamp > threshold) {
                if (hints && cur->hints
                          && hints->ai_flags == cur->hints->ai_flags
                          && hints->ai_family == cur->hints->ai_family
                          && hints->ai_socktype == cur->hints->ai_socktype
                          && hints->ai_protocol == cur->hints->ai_protocol) {
                    pthread_mutex_unlock(&lock);
                    addr.s_addr= ((struct sockaddr_in *)(cur->res->ai_addr))->sin_addr.s_addr;
                    fprintf(LOG, "### use cached resolved_addrinfo_entry: node=%s, addr=%s\n", node, inet_ntoa(addr));
                    return cur->res;
                } else if (cur->hints == NULL) {
                    pthread_mutex_unlock(&lock);
                    addr.s_addr= ((struct sockaddr_in *)(cur->res->ai_addr))->sin_addr.s_addr;
                    fprintf(LOG, "### use cached resolved_addrinfo_entry: node=%s, addr=%s\n", node, inet_ntoa(addr));
                    return cur->res;
                }
            }
            cur = cur->prev;
        }
    }
    pthread_mutex_unlock(&lock);

    return NULL;
}

__attribute__((visibility("default")))
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    static int (*libc_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
    static void (*libc_freeaddrinfo)(struct addrinfo *res) = NULL;

    struct in_addr addr;
    int ret;

    struct timeval begin, end;
    float diff_time;
    gettimeofday(&begin, NULL);

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

    gettimeofday(&end, NULL);
    diff_time = (end.tv_sec - begin.tv_sec +  (float)(end.tv_usec - begin.tv_usec) / 1000000) * 1000.0;

    struct addrinfo *addrinfo = *res;
    addr.s_addr= ((struct sockaddr_in *)(addrinfo->ai_addr))->sin_addr.s_addr;
    fprintf(LOG, "### getaddrinfo: node=%s, addr=%s, delta=%.3f[ms]\n", node, inet_ntoa(addr), diff_time);

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
    {
        per_node_root *cur = first;
        while (cur) {
            cur = free_per_node_root(cur);
        }
        first = last = NULL;
    }
    pthread_mutex_unlock(&lock);
}
