// vim: noai:ts=4:sw=4: et
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

typedef struct resolved_entry
{
    struct resolved_entry *next;
    struct resolved_entry *prev;
    char *node;
    struct addrinfo *hints;
    struct addrinfo *res;
    time_t timestamp;
} resolved_entry;

static struct resolved_entry *first = NULL;
static struct resolved_entry *last = NULL;

static int num_entries = 0;

static struct resolved_entry *free_resolved_entry(struct resolved_entry *cur)
{
    static void (*lib_freeaddrinfo)(struct addrinfo *res) = NULL;
    if (!lib_freeaddrinfo) {
        lib_freeaddrinfo = __load_func("freeaddrinfo");
    }
    if (!cur) {
        return NULL;
    }

    free(cur->node);

    if (cur->hints) {
        free(cur->hints);
    }
    if (cur->res) {
        lib_freeaddrinfo(cur->res);
    }

    struct resolved_entry *next = cur->next;

    free(cur);

    return next;
}

static void append_resolved_entry(const char *node, const struct addrinfo *hints, struct addrinfo *res)
{
    resolved_entry *entry = (resolved_entry *) calloc(sizeof(resolved_entry), 1);

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
            first = free_resolved_entry(first);
            first->prev = NULL;
            num_entries--;
        }
    }
    pthread_mutex_unlock(&lock);
}

static struct addrinfo * find_resolved_entry(const char *node, const struct addrinfo *hints)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    time_t threshold = now.tv_sec - CACHE_AGE_SECS;

    pthread_mutex_lock(&lock);

    resolved_entry *cur = last;
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
    static int (*lib_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
    static void (*lib_freeaddrinfo)(struct addrinfo *res) = NULL;

    int ret;

    if (!lib_getaddrinfo) {
        lib_getaddrinfo = __load_func("getaddrinfo");
    }
    if (!lib_freeaddrinfo) {
        lib_freeaddrinfo = __load_func("freeaddrinfo");
    }

    ret = lib_getaddrinfo(node, service, hints, res);
    if (ret != 0) {
        *res = find_resolved_entry(node, hints);
        if (*res) {
            ret = 0;
        }
    } else {
        int i = 0;
        for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
            i += 1;
        }
        if (i > 0) {
            append_resolved_entry(node, hints, *res);
        } else {
            lib_freeaddrinfo(*res);
            *res = find_resolved_entry(node, hints);
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
        struct resolved_entry *cur = first;
        while (cur) {
            cur = free_resolved_entry(cur);
        }
        first = last = NULL;
    }
    pthread_mutex_unlock(&lock);
}
