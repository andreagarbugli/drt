// clang-format off
#ifndef DRT_INCLUDE_H
#define DRT_INCLUDE_H

// check arch
#if defined(__x86_64__) || defined(_M_X64)
# ifndef ARCH_X64
#  define ARCH_X64 1
# endif
#elif defined(__i386__) || defined(_M_IX86)
# ifndef ARCH_X86
#  define ARCH_X86 1
# endif
#else
# error This architecture is NOT supported yet!
#endif

// endianness
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  ifndef ENDIAN_LITTLE
#   define ENDIAN_LITTLE 1
#  endif
# elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  ifndef ENDIAN_BIG
#   define ENDIAN_BIG 1
#  endif
# endif
#elif defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN)
# ifndef ENDIAN_LITTLE
#  define ENDIAN_LITTLE 1
# endif
#elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN)
# ifndef ENDIAN_BIG
#  define ENDIAN_BIG 1
# endif
#else
# error This endianness is NOT supported yet!
#endif

#if defined(_WIN32) || defined(_WIN64)
# ifndef OS_WINDOWS
#  define OS_WINDOWS 1
# endif
#elif defined(__unix__)
# ifndef OS_UNIX
#  define OS_UNIX 1
# endif
#if defined(__linux__)
# ifndef OS_LINUX
#  define OS_LINUX 1
# endif
#endif
#else
# error This operating system is NOT supported yet!
#endif

#if defined(_MSC_VER)
# ifndef COMPILER_MSVC
#  define COMPILER_MSVC 1
# endif
#elif defined(__GNUC__)
# ifndef COMPILER_GCC
#  define COMPILER_GCC 1
# endif
#elif defined(__clang__)
# ifndef COMPILER_CLANG
#  define COMPILER_CLANG 1
# endif
#endif

#if OS_WINDOWS
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <wingdi.h>
# pragma comment(lib, "kernel32")
# pragma comment(lib, "user32")
# pragma comment(lib, "gdi32.lib")
// # pragma comment(lib, "advapi32")
#elif OS_LINUX
# define _GNU_SOURCE
# ifndef __USE_MISC
#  define __USE_MISC
# endif
# include <errno.h>
# include <fcntl.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <unistd.h>
#endif

#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int8_t      i8;
typedef int16_t     i16;
typedef int32_t     i32;
typedef int64_t     i64;
typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

typedef size_t      usize;
typedef ptrdiff_t   isize;

typedef u8          byte;

typedef float       f32;
typedef double      f64;

////////////////////////////////////////////////////////////////////////////////
// Platform Defines
#if OS_WINDOWS

#elif OS_LINUX
# ifndef CLOCK_REALTIME
#  define CLOCK_REALTIME 0
# endif
# ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC 1
# endif
#endif

////////////////////////////////////////////////////////////////////////////////
// Common Defines

#define UNUSED(var)     ((void)(var))

// --- Flags
#define FLAG_BIT(x)         (1 << (x))
#define CHECK_FLAG(x, f)    ((x) & (f))

// --- Units (Bytes)
#define KB(x)      (((u64)x) << 10)
#define MB(x)      (((u64)x) << 20)
#define GB(x)      (((u64)x) << 30)
#define TB(x)      (((u64)x) << 40)

#define THOUSAND(x) ((x) * 1000)
#define MILLION(x)  ((x) * 1000000)
#define BILLION(x)  ((x) * 1000000000)

#if COMPILER_MSVC
# if __cplusplus
#  define type_of               decltype
# else
# define type_of                __typeof__
# endif
# define offset_of              offsetof
# define inline_fn              static __forceinline
# define struct_packed          __pragma(pack(push, 1)) struct
# define struct_packed_end      __pragma(pack(pop))
#elif COMPILER_GCC || COMPILER_CLANG
# define type_of                typeof
# define offset_of              __builtin_offsetof
# define inline_fn              static inline __attribute__((always_inline))
# define struct_packed          struct
# define struct_packed_end      __attribute__((packed))
#endif

#define local_variable      static
#define global_variable     static

#if OS_WINDOWS
# define trap()     __debugbreak()
#elif OS_LINUX
# define trap()     __builtin_trap()
#endif

#if OS_WINDOWS
# define GET_X_LPARAM(lp)       ((int)(short)LOWORD(lp))
# define GET_Y_LPARAM(lp)       ((int)(short)HIWORD(lp))
#endif

#define assert(x)  do { if (!(x)) { trap(); } } while (0)

// --- Array Utils
#define array_count(a) (sizeof((a)) / sizeof((a)[0]))

// --- Memory
#define memory_set              memset
#define memory_copy             memcpy
#define memory_zero(ptr, size)  memory_set(ptr, 0, size)
#define memory_zero_struct(s)   memory_zero(s, sizeof(*(s)))
#define memory_zero_array(a)    memory_zero(a, array_count(a))

#ifndef abs
# define abs(x)     ((x) < 0 ? -(x) : (x))
#endif
#ifndef min
# define min(a,b)   ((a) < (b) ? (a) : (b))
#endif
#ifndef max
# define max(a,b)   ((a) > (b) ? (a) : (b))
#endif

// --- Ascii Colors for Terminal
#define ANSI_COLOR_RED          "\x1b[31m"
#define ANSI_COLOR_GREEN        "\x1b[32m"
#define ANSI_COLOR_YELLOW       "\x1b[33m"
#define ANSI_COLOR_BLUE         "\x1b[34m"
#define ANSI_COLOR_MAGENTA      "\x1b[35m"
#define ANSI_COLOR_CYAN         "\x1b[36m"
#define ANSI_COLOR_RESET        "\x1b[0m"

////////////////////////////////////////////////////////////////////////////////
// Base Functions
inline_fn usize align_to        (usize value, usize alignment) { return (value + (alignment - 1)) & ~(alignment - 1); }
inline_fn usize align_down      (usize value, usize alignment) { return value & ~(alignment - 1); }
inline_fn bool  is_power_of_two (usize value)                  { return (value & (value - 1)) == 0; }

inline_fn u32 u32_swap_endian(u32 x) { return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24); }
inline_fn u16 u16_swap_endian(u16 x) { return ((x & 0xFF) << 8) | ((x & 0xFF00) >> 8); }

////////////////////////////////////////////////////////////////////////////////
//
// Base
//

////////////////////////////////////////////////////////////////////////////////
// Arena

typedef struct arena arena;
struct arena
{
    arena *base;
    usize size;
    usize pos;
    usize cmt_pos;
    usize align;
    usize __pad[3]; // TODO(garbu): use a compiler flag to cache align
};

typedef struct arena_params arena_params;
struct arena_params
{
    usize reserve_size;
    usize commit_size;
};

arena *arena_vm_alloc_params (arena_params *params);
void  *arena_push_no_zero    (arena *arena, usize size);
void  *arena_push            (arena *arena, usize size);

inline_fn void arena_pop   (arena *a, usize pos) { a->pos = pos; }
inline_fn void arena_clear (arena *a)            { a->pos = sizeof(arena); }

#define arena_vm_alloc(...)                     arena_vm_alloc_params(&(arena_params){.reserve_size=GB(1), .commit_size=KB(64), __VA_ARGS__})
#define arena_push_struct(arena, type)          (type *)arena_push(arena, sizeof(type))
#define arena_push_array(arena, type, count)    (type *)arena_push(arena, sizeof(type) * (count))

typedef struct temp_arena temp_arena;
struct temp_arena
{
    arena *arena;
    usize  pos;
};

temp_arena temp_arena_begin (arena *arena);
void       temp_arena_end   (temp_arena arena);

////////////////////////////////////////////////////////////////////////////////
// Characters ASCII
static inline bool is_whitespace   (char c) { return (c == ' ' || c == '\t' || c == '\n' || c == '\r'); }
static inline bool is_newline      (char c) { return (c == '\n' || c == '\r'); }
static inline bool is_digit        (char c) { return (c >= '0' && c <= '9'); }
static inline bool is_alpha        (char c) { return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')); }
static inline bool is_alphanumeric (char c) { return (is_alpha(c) || is_digit(c)); }
static inline bool is_hex          (char c) { return (is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')); }
static inline bool is_upper        (char c) { return (c >= 'A' && c <= 'Z'); }
static inline bool is_lower        (char c) { return (c >= 'a' && c <= 'z'); }
static inline bool is_ascii        (char c) { return (c >= 0 && c <= 127); }
static inline bool is_numeric      (char c) { return (is_digit(c) || c == '-' || c == '+' || c == 'e' || c == 'E' || c == '.'); }
static inline bool is_printable    (char c) { return (c >= 32 && c <= 126); }

static inline char to_upper (char c) { return (is_lower(c) ? c - 32 : c); }
static inline char to_lower (char c) { return (is_upper(c) ? c + 32 : c); }

////////////////////////////////////////////////////////////////////////////////
// Strings
typedef struct string string;
struct string
{
    u8 *data;
    usize len;
};

inline_fn string str          (u8 *s, usize len) { string res; res.data = s; res.len  = len; return res; }
inline_fn bool   string_empty (string s)         { return s.len == 0; }

#define SPRI            "%.*s"
#define from_cstr(s)    str((u8 *)s, cstring_len(s))
#define str_lit(s)      str((u8 *)(s), sizeof(s) - 1)
#define str_varg(s)     (int)((s).len), (char *)((s).data)
#define to_cstr(s)      (char *)s.data

// --- C-String
usize cstring_len  (char *s);
void  cstring_copy (char *dst, char *src, usize len);
bool  cstr_eq      (char *a, char *b);

string string_skip        (string s, usize el);
string string_trim_start  (string s);
string string_trim_end    (string s);
string string_trim        (string s);
bool   string_starts_with (string s, string pre);
bool   string_equal       (string a, string b);

// --- String Conversion
static inline f32 f32_from_str (string s) { return strtof(to_cstr(s), NULL); }
static inline i64 i64_from_str (string s) { return atoll(to_cstr(s)); }
static inline u8  u8_from_str  (string s) { return (u8)strtoul(to_cstr(s), NULL, 10); }

// --- String List
typedef struct string_node string_node;
struct string_node
{
    string       s;
    string_node *next;
};

typedef struct string_list string_list;
struct string_list
{
    string_node *head;
    string_node *tail;
    usize        count;
};

typedef struct string_array string_array;
struct string_array
{
    string *e;
    usize   len;
};

#define string_list_foreach(l, n)   \
    for ((n) = (l)->head; (n); (n) = (n)->next)

string_list  str_list();
void         string_list_push_node(string_list *list, string_node *node);
void         string_list_push(arena *arena, string_list *list, string str);
string      *string_list_to_array(arena *arena, string_list *list);

string       string_list_concat(arena *arena, string_list *list, string sep);

string_list  string_split(arena *arena, string s, char *delims, usize delim_count);
string_list *text_get_lines(arena *arena, string text);

////////////////////////////////////////////////////////////////////////////////
// Logging
typedef int (*log_write_fn)(const char *msg, usize len);

typedef enum {
    LOG_NONE,
    LOG_FATAL,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_TRACE,
    LOG_LEVEL_COUNT  // Total number of log levels
} log_level;

typedef struct log_level_fmt log_level_fmt;
struct log_level_fmt {
    char *level_str;   // Log level as a string
    char *color_str;   // Color string for the log level
};

static const log_level_fmt __drt_log_level_formats[LOG_LEVEL_COUNT] = {
    [LOG_NONE]  = {"NONE",  ""},
    [LOG_FATAL] = {"FATAL", ANSI_COLOR_RED},
    [LOG_ERROR] = {"ERROR", ANSI_COLOR_RED},
    [LOG_WARN]  = {"WARN",  ANSI_COLOR_YELLOW},
    [LOG_INFO]  = {"INFO",  ANSI_COLOR_GREEN},
    [LOG_DEBUG] = {"DEBUG", ANSI_COLOR_CYAN},
    [LOG_TRACE] = {"TRACE", ANSI_COLOR_MAGENTA},
};

static u32 logger_log_levelstr_to_enum(char *str)
{
    if (cstr_eq(str, "fatal"))   return LOG_FATAL;
    if (cstr_eq(str, "error"))   return LOG_ERROR;
    if (cstr_eq(str, "warn" ))   return LOG_WARN;
    if (cstr_eq(str, "info" ))   return LOG_INFO;
    if (cstr_eq(str, "debug"))   return LOG_DEBUG;
    if (cstr_eq(str, "trace"))   return LOG_TRACE;

    return LOG_NONE;
}

typedef struct logger logger;
struct logger
{
    log_level     level;
    bool          ts_on;
    bool          ctx_info_on; // line and file info
    log_write_fn  write;
    char         *title;
};

global_variable logger g_drt_logger = {
    LOG_INFO,
    false,
    false,
    NULL,
    "drt"
};

inline_fn void logger_log_set_level (logger *log, log_level level)    { log->level = level; }
inline_fn void logger_log_set_ts    (logger *log, bool enable_ts)     { log->ts_on = enable_ts; }
inline_fn void logger_log_set_write (logger *log, log_write_fn write) { log->write = write; }
inline_fn void logger_log_set_title (logger *log, char *title)        { log->title = title; }
inline_fn void logger_log_set_ctx   (logger *log, bool enable_ctx)    { log->ctx_info_on = enable_ctx; }

int
__drt_logger_log(u32 level, const char *sub, const char *fmt, ...)
{
    if (level > g_drt_logger.level || g_drt_logger.write == NULL) return 0;

    char buf[4096]; memory_zero_array(buf);
    size_t max_len = sizeof(buf);
    size_t n       = 0;

    n += snprintf(buf, max_len, "[");

    if (g_drt_logger.title)     n += snprintf(buf+n, max_len-n, "%s ", g_drt_logger.title);

    if (g_drt_logger.ts_on) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm *tm = localtime(&ts.tv_sec);

        n += strftime(buf+n, max_len-n, "%Y-%m-%d %H:%M:%S", tm);
        n += snprintf(buf+n, max_len-n, ".%09ld ", ts.tv_nsec);
    }

    log_level_fmt lvl_fmt = __drt_log_level_formats[level];
    if (sub) n += snprintf(buf+n, max_len-n, "%s%5s%s %s ", lvl_fmt.color_str, lvl_fmt.level_str, ANSI_COLOR_RESET, sub);
    else     n += snprintf(buf+n, max_len-n, "%s%5s%s ", lvl_fmt.color_str, lvl_fmt.level_str, ANSI_COLOR_RESET);

    n += snprintf(buf+n, max_len-n, "] ");

    va_list args;
    va_start(args, fmt);
    n += vsnprintf(buf+n, max_len-n, fmt, args);
    va_end(args);

    return g_drt_logger.write(buf, n);
}

#define logger_set_level(level)  logger_log_set_level(&g_drt_logger, level)
#define logger_set_ts(enable_ts) logger_log_set_ts(&g_drt_logger, enable_ts)
#define logger_set_write(write)  logger_log_set_write(&g_drt_logger, write)
#define logger_set_title(title)  logger_log_set_title(&g_drt_logger, title)
#define logger_set_ctx(enable)   logger_log_set_ctx(&g_drt_logger, enable)

#define debug(fmt, ...)     __drt_logger_log(LOG_DEBUG, NULL, fmt, ##__VA_ARGS__)
#define info(fmt, ...)      __drt_logger_log(LOG_INFO,  NULL, fmt, ##__VA_ARGS__)
#define warn(fmt, ...)      __drt_logger_log(LOG_WARN,  NULL, fmt, ##__VA_ARGS__)
#define error(fmt, ...)     __drt_logger_log(LOG_ERROR, NULL, fmt, ##__VA_ARGS__)

#define debug_ctx(fmt, ...)     __drt_logger_log(LOG_DEBUG, NULL, "(%s:%d)" # fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define debug_sys(sys, fmt, ...)     __drt_logger_log(LOG_DEBUG, sys, fmt, ##__VA_ARGS__)
#define info_sys(sys, fmt, ...)      __drt_logger_log(LOG_INFO,  sys, fmt, ##__VA_ARGS__)
#define warn_sys(sys, fmt, ...)      __drt_logger_log(LOG_WARN,  sys, fmt, ##__VA_ARGS__)
#define error_sys(sys, fmt, ...)     __drt_logger_log(LOG_ERROR, sys, fmt, ##__VA_ARGS__)

////////////////////////////////////////////////////////////////////////////////
//
// Platform
//

static i64 g_os_cpu_freq;
static i64 g_os_perf_freq;

void os_init();
void os_exit(int err);

// --- Time
i64 os_time_ns();

static inline i64 os_cpu_cycles()
{
    i64 res = 0;
#if OS_WINDOWS
    res = __rdtsc();
#elif OS_LINUX
    i64 lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    res = (hi << 32) | lo;
#endif
    return res;
}

////////////////////////////////////////////////////////////////////////////////
// Virtual Memory

#define DEFAULT_ALIGN_GRANILARITY GB(1)

void *os_vm_reserve  (usize size);
void  os_vm_commit   (void *addr, usize size);
void *os_vm_rsvcmt   (usize size);
void  os_vm_decommit (void *ptr, usize size);
void  os_vm_release  (void *ptr, usize size);

////////////////////////////////////////////////////////////////////////////////
// File System

#if OS_WINDOWS
    #define FILE_HANDLE_INVALID INVALID_HANDLE_VALUE
    typedef HANDLE  os_handle;
#elif OS_LINUX
    #define FILE_HANDLE_INVALID ((-1))
    typedef int     os_handle;
#endif

typedef enum {
    FILE_MODE_READ   = FLAG_BIT(0),
    FILE_MODE_WRITE  = FLAG_BIT(1),
    FILE_MODE_APPEND = FLAG_BIT(2),
    FILE_MODE_RW     = FLAG_BIT(3),

    FILE_MODE_MODES = FILE_MODE_READ | FILE_MODE_WRITE | FILE_MODE_APPEND | FILE_MODE_RW,
} fs_file_mode;

typedef enum {
    FILE_SEEK_OFFSET,
    FILE_SEEK_CURRENT,
    FILE_SEEK_END,
} fs_seek_type;

typedef enum {
    FILE_ERROR_NONE,
    FILE_ERROR_INVALID,
    FILE_ERROR_INVALID_NAME,
    FILE_ERROR_EXISTS,
    FILE_ERROR_NOT_EXISTS,
    FILE_ERROR_PERMISSION,
    FILE_ERROR_TRUNC_FAILURE,
} fs_file_error;

static const char *file_error_to_string[] = {
    "None",
    "Invalid",
    "InvalidName",
    "Exists",
    "NotExists",
    "Permission",
    "TruncateFailure",
};

typedef struct fs_file_result fs_file_result;
struct fs_file_result
{
    os_handle       hfile;
    fs_file_error   error;
};

#define FS_OPEN_PROC()      fs_file_result fs_open     (string filename, fs_file_mode mode)
#define FS_READ_AT_PROC()   int            fs_read_at  (os_handle h, void *buffer, usize size, usize offset)
#define FS_WRITE_AT_PROC()  int            fs_write_at (os_handle h, void *buffer, usize size, usize offset)
#define FS_SEEK_PROC()      int            fs_seek     (os_handle h, usize offset, fs_seek_type type)
#define FS_CLOSE_PROC()     void           fs_close    (os_handle h)

FS_OPEN_PROC();
FS_READ_AT_PROC();
FS_WRITE_AT_PROC();
FS_SEEK_PROC();
FS_CLOSE_PROC();

typedef struct fs_file fs_file;
struct fs_file
{
    os_handle hfile;
    string name;
};

fs_file_error fs_file_open  (fs_file *file, string filename);
int           fs_file_read  (fs_file *file, void *buffer, usize size);
int           fs_file_write (fs_file *file, void *buffer, usize size);
fs_file_error fs_file_close (fs_file *file);

string fs_read_entire_file(string filename);

////////////////////////////////////////////////////////////////////////////////
// Environment
string os_get_env(string name);

////////////////////////////////////////////////////////////////////////////////
//
// Core Functionalities
//

////////////////////////////////////////////////////////////////////////////////
// Allocators

#define ALLOCATOR_ALLOC_PROC(name)          void *(name)(void *data, usize size)
#define ALLOCATOR_ALLOC_ALIGNED_PROC(name)  void *(name)(void *data, usize size, usize align)
#define ALLOCATOR_FREE_PROC(name)           void  (name)(void *data, void *ptr, usize size)
#define ALLOCATOR_FREE_ALL_PROC(name)       void  (name)(void *data)
#define ALLOCATOR_REALLOC_PROC(name)        void *(name)(void *data, void *ptr, usize size)

typedef ALLOCATOR_ALLOC_PROC(allocator_alloc_proc);
typedef ALLOCATOR_ALLOC_ALIGNED_PROC(allocator_alloc_aligned_proc);
typedef ALLOCATOR_FREE_PROC(allocator_free_proc);
typedef ALLOCATOR_FREE_ALL_PROC(allocator_free_all_proc);
typedef ALLOCATOR_REALLOC_PROC(allocator_realloc_proc);

typedef struct allocator_ops allocator_ops;
struct allocator_ops
{
    allocator_alloc_proc         *alloc;
    allocator_alloc_aligned_proc *alloc_aligned;
    allocator_free_proc          *free;
    allocator_free_all_proc      *free_all;
    allocator_realloc_proc       *realloc;
};

typedef struct allocator allocator;
struct allocator
{
    void            *data;
    allocator_ops    ops;
};

// --- Heap Allocator
ALLOCATOR_ALLOC_PROC(heap_allocator_alloc_proc);
ALLOCATOR_ALLOC_ALIGNED_PROC(heap_allocator_alloc_aligned_proc);
ALLOCATOR_FREE_PROC(heap_allocator_free_proc);
ALLOCATOR_FREE_ALL_PROC(heap_allocator_free_all_proc);
ALLOCATOR_REALLOC_PROC(heap_allocator_realloc_proc);

static inline allocator *
mem_heap_allocator()
{
    static allocator *a = NULL;
    if (!a) {
        a = (allocator *)os_vm_rsvcmt(sizeof(allocator));
        a->ops.alloc         = heap_allocator_alloc_proc;
        a->ops.alloc_aligned = heap_allocator_alloc_aligned_proc;
        a->ops.free          = heap_allocator_free_proc;
        a->ops.free_all      = heap_allocator_free_all_proc;
        a->ops.realloc       = heap_allocator_realloc_proc;
    }

    return a;
}

// --- Generic Allocation Functions
static inline void *mem_alloc   (allocator *a, usize size)                { return a->ops.alloc(a->data, size); }
static inline void *mem_realloc (allocator *a, void *ptr, usize new_size) { return a->ops.realloc(a->data, ptr, new_size); }
static inline void  mem_free    (allocator *a, void *ptr)                 { a->ops.free(a->data, ptr, 0); }

////////////////////////////////////////////////////////////////////////////////
// Dynamic Array
#ifndef DRT_DARRAY_DEFAULT_CAP
# define DRT_DARRAY_DEFAULT_CAP 12
#endif
#ifndef DRT_DARRAY_GROWTH_FACTOR
# define DRT_DARRAY_GROWTH_FACTOR 2
#endif

typedef struct darray_params darray_params;
struct darray_params
{
    usize      cap;
    allocator *a;
};

typedef struct darray_header darray_header;
struct darray_header
{
    allocator *a;
    usize      size;
    usize      cap;
};

#define darray_get_header(arr)      (((darray_header *)(arr)) - 1)
#define darray_cap(arr)             (darray_get_header((arr)))->cap
#define darray_size(arr)            (darray_get_header((arr)))->size
#define darray_empty(arr)           (darray_size((arr)) == 0)

#define darray_init_params(arr, p)                                                                           \
    do {                                                                                                     \
        darray_params __darray_params = p;                                                                   \
        usize __darray_elems_size     = (__darray_params.cap) * sizeof(*(arr));                              \
        usize __darray_total_size     = __darray_elems_size + sizeof(darray_header);                         \
        darray_header *__darray_hdr   = (darray_header *)mem_alloc(__darray_params.a, __darray_total_size);  \
        __darray_hdr->a               = (__darray_params.a);                                                 \
        __darray_hdr->cap             = (__darray_params.cap);                                               \
        __darray_hdr->size            = 0;                                                                   \
        (arr)                         = (void *)(__darray_hdr + 1);                                          \
    } while (0)

#define DARRAY_DEFAULT_PARAMS(...)  (darray_params){.cap=DRT_DARRAY_DEFAULT_CAP, .a=mem_heap_allocator(), __VA_ARGS__ }
#define darray_init(arr, ...)       darray_init_params(arr, DARRAY_DEFAULT_PARAMS(__VA_ARGS__))

#define darray_push(arr, value)                                                                                         \
    do {                                                                                                                \
        darray_header *__darray_hdr = darray_get_header(arr);                                                           \
        if (__darray_hdr->size >= __darray_hdr->cap) {                                                                  \
            usize __darray_new_cap          = __darray_hdr->cap * DRT_DARRAY_GROWTH_FACTOR;                             \
            usize __darray_elems_size       = __darray_new_cap * sizeof(*(arr));                                        \
            usize __darray_total_size       = __darray_elems_size + sizeof(darray_header);                              \
            darray_header *__darray_new_hdr = (darray_header *)mem_alloc(__darray_hdr->a, __darray_total_size);         \
            memory_copy(__darray_new_hdr, __darray_hdr, sizeof(darray_header) + (__darray_hdr->cap * sizeof(*(arr))));  \
            __darray_new_hdr->cap = __darray_new_cap;                                                                   \
            mem_free(__darray_hdr->a, __darray_hdr);                                                                    \
            __darray_hdr = __darray_new_hdr;                                                                            \
            (arr)        = (void *)(__darray_hdr + 1);                                                                  \
        }                                                                                                               \
        (arr)[__darray_hdr->size++] = value;                                                                            \
    } while (0)

#define darray_pop(arr)                                       \
    do {                                                      \
        darray_header *__darray_hdr = darray_get_header(arr); \
        if (__darray_hdr->size > 0) __darray_hdr->size--;     \
    } while (0)

#endif // DRT_INCLUDE_H

////////////////////////////////////////////////////////////////////////////////
//
//
//
//
// IMPLEMENTATION
//
//
//
//

#ifdef DRT_IMPLEMENTATION

////////////////////////////////////////////////////////////////////////////////
//
// Base
//

// --- Heap Allocator
#if OS_WINDOWS
ALLOCATOR_ALLOC_PROC(heap_allocator_alloc_proc)                 { UNUSED(data); return _malloc_base(size); }
ALLOCATOR_ALLOC_ALIGNED_PROC(heap_allocator_alloc_aligned_proc) { UNUSED(data); return _aligned_malloc(size, align); }
ALLOCATOR_REALLOC_PROC(heap_allocator_realloc_proc)             { UNUSED(data); return _realloc_base(ptr, size); }
ALLOCATOR_FREE_PROC(heap_allocator_free_proc)                   { UNUSED(data); UNUSED(size); _free_base(ptr); }
ALLOCATOR_FREE_ALL_PROC(heap_allocator_free_all_proc)           { UNUSED(data); }

// ALLOCATOR_ALLOC_ALIGNED_PROC(pool_allocator_alloc_aligned_proc) { return pool_allocator_get_el(data, size); }
#elif OS_LINUX
ALLOCATOR_ALLOC_PROC(heap_allocator_alloc_proc)                    { UNUSED(data); return malloc(size); }
ALLOCATOR_ALLOC_ALIGNED_PROC(heap_allocator_alloc_aligned_proc)    { UNUSED(data); void *ptr; (void)posix_memalign(&ptr, align, size); return ptr; }
ALLOCATOR_REALLOC_PROC(heap_allocator_realloc_proc)                { UNUSED(data); return realloc(ptr, size); }
ALLOCATOR_FREE_PROC(heap_allocator_free_proc)                      { UNUSED(data); UNUSED(size); free(ptr); }
ALLOCATOR_FREE_ALL_PROC(heap_allocator_free_all_proc)              { UNUSED(data); }
#endif

// --- Pool Allocator

arena *
arena_vm_alloc_params(arena_params *params)
{
    usize aligned_size = align_to(params->reserve_size, GB(1));
    void *base         = os_vm_reserve(aligned_size);

    usize init_commit_size = params->commit_size;
    os_vm_commit(base, init_commit_size);

    arena *a = (arena *)base;
    a->base    = a;
    a->size    = params->reserve_size;
    a->pos     = sizeof(arena);
    a->cmt_pos = init_commit_size;
    a->align   = 8;

    return a;
}

void *
arena_push_no_zero(arena *arena, usize size)
{
    void *ptr         = NULL;
    byte *base        = (byte *)arena->base;
    usize aligned_pos = align_to(arena->pos, arena->align);

    if (aligned_pos + size <= arena->size - sizeof(arena))
    {
        ptr        = base + arena->pos;
        arena->pos = aligned_pos + size;
        if (arena->pos > arena->cmt_pos)
        {
            usize commit_size = arena->pos - arena->cmt_pos;
            commit_size       = align_to(commit_size, KB(64));
            os_vm_commit(base + arena->cmt_pos, commit_size);
            arena->cmt_pos += commit_size;
        }
    }

    return ptr;
}

void *
arena_push(arena *arena, usize size)
{
    void *ptr = arena_push_no_zero(arena, size);
    memory_zero(ptr, size);
    return ptr;
}



temp_arena
temp_arena_begin(arena *arena)
{
    temp_arena tmp;
    tmp.arena = arena;
    tmp.pos   = arena->pos;
    return tmp;
}

void
temp_arena_end(temp_arena tmp_arena)
{
    tmp_arena.arena->pos = tmp_arena.pos;
}

////////////////////////////////////////////////////////////////////////////////
// Strings
usize
cstring_len(char *s)
{
    usize len = 0;
    while (*s++ != '\0')    ++len;
    return len;
}

void
cstring_copy(char *dst, char *src, usize len)
{
    while (len--)    *dst++ = *src++;
}

bool
cstr_eq(char *a, char *b)
{
    usize a_len = cstring_len(a);
    usize b_len = cstring_len(b);
    if (a_len != b_len)    return false;

    for (usize i = 0; i < a_len; i++) {
        if (a[i] != b[i])    return false;
    }

    return true;
}

string
string_skip(string s, usize el)
{
    el = min(el, (s.len-1));
    return str(s.data + el, s.len - el);
}

string
string_trim_start(string s)
{
    usize start = 0;
    while (start < s.len && is_whitespace(s.data[start]))    start++;
    return str(s.data + start, s.len - start);
}

string
string_trim_end(string s)
{
    usize end = s.len;
    while (end > 0 && is_whitespace(s.data[end-1]))    end--;
    return str(s.data, end);
}

string
string_trim(string s)
{
    return string_trim_end(string_trim_start(s));
}

bool
string_starts_with(string s, string pre)
{
    if (s.len < pre.len)    return false;
    for (usize i = 0; i < pre.len; i++) {
        if (s.data[i] != pre.data[i])   return false;
    }

    return true;
}

bool
string_equal(string a, string b)
{
    return string_starts_with(a, b) && a.len == b.len;
}

string_list
str_list()
{
    string_list list;
    memory_zero_struct(&list);
    return list;
}

void
string_list_push_node(string_list *list, string_node *node)
{
    node->next = NULL;
    if (list->head == NULL) {
        list->head = list->tail = node;
    } else {
        list->tail->next = node;
        list->tail       = node;
    }

    list->count += 1;
}

void
string_list_push(arena *arena, string_list *list, string str)
{
    string_node *node = arena_push_struct(arena, string_node);
    node->s = str;
    string_list_push_node(list, node);
}

string
string_list_concat(arena *arena, string_list *list, string sep)
{
    usize total_len = 0;
    string_node *n;
    string_list_foreach(list, n) {
        total_len += n->s.len + sep.len;
    }

    total_len -= sep.len;

    u8 *data  = arena_push(arena, total_len);
    usize pos = 0;
    string_list_foreach(list, n) {
        memory_copy(data + pos, n->s.data, n->s.len);
        pos += n->s.len;
        memory_copy(data + pos, sep.data, sep.len);
        pos += sep.len;
    }

    return str(data, total_len);
}

string_list
string_split(arena *arena, string s, char *delims, usize delim_count)
{
    string_list result = str_list();
    usize start = 0;
    for (usize i = 0; i < s.len; ++i) {
        for (usize d = 0; d < delim_count; ++d) {
            if (s.data[i] == delims[d]) {
                string part = str(s.data + start, i - start);
                string_list_push(arena, &result, part);
                start = i + 1;
                break;
            }
        }
    }

    string part = str(s.data + start, s.len - start);
    string_list_push(arena, &result, part);

    return result;
}

string *
string_list_to_array(arena *arena, string_list *list)
{
    string *result = arena_push_array(arena, string, list->count);
    usize i = 0;
    string_node *n;
    string_list_foreach(list, n) {
        result[i] = n->s;
        i++;
    }

    return result;
}

string_list *
text_get_lines(arena *arena, string text)
{
    usize start_idx = 0;

    string_list *list = arena_push_struct(arena, string_list);

    for (usize i = 0; i < text.len; i++) {
        if (text.data[i] == '\n') {
            string substr = str(text.data + start_idx, i - start_idx);
            string_list_push(arena, list, substr);
            start_idx = i + 1;
        };
    }

    string substr = str(text.data + start_idx, text.len - start_idx);
    string_list_push(arena, list, substr);

    return list;
}

////////////////////////////////////////////////////////////////////////////////
//
// Platform
//

void
os_init()
{
#if OS_WINDOWS
    LARGE_INTEGER perf_freq;
    QueryPerformanceFrequency(&perf_freq);
    g_os_perf_freq = perf_freq.QuadPart;

    // DWORD cpu_freq_mhz;
    // HKEY key;
    // LONG ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    // "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &key);
    // if (ret == ERROR_SUCCESS) {
    //     DWORD data_size = sizeof(DWORD);
    //     RegQueryValueExA(key, "~MHz", NULL, NULL, (LPBYTE)&cpu_freq_mhz,
    //     &data_size); g_os_cpu_freq = cpu_freq_mhz * 1000000;
    // }
#elif OS_LINUX
#endif
}

void
os_exit(int ecode)
{
#if OS_WINDOWS
    ExitProcess(ecode);
#elif OS_LINUX
    _exit(ecode); // NOTE(gax): Should I use the classic `exit()`?
#endif
}

i64
os_time_ns()
{
    i64 res;
#if OS_WINDOWS
    LARGE_INTEGER perf_counter;
    QueryPerformanceCounter(&perf_counter);
    res = (perf_counter.QuadPart * BILLION(1)  / g_os_perf_freq);
#elif OS_LINUX
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    res = ts.tv_sec * BILLION(1) + ts.tv_nsec;
#endif
    return res;
}

////////////////////////////////////////////////////////////////////////////////
// Virtual Memory

void *os_vm_rsvcmt(usize size)
{
    void *ptr = os_vm_reserve(size);
    os_vm_commit(ptr, size);
    return ptr;
}

#if OS_WINDOWS
void *os_vm_reserve  (usize size)             { void *ptr; ptr = VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_READWRITE); return ptr; }
void  os_vm_commit   (void *addr, usize size) { VirtualAlloc(addr, size, MEM_COMMIT, PAGE_READWRITE); }
void  os_vm_decommit (void *ptr, usize size)  { VirtualFree(ptr, size, MEM_DECOMMIT); }
void  os_vm_release  (void *ptr, usize size)  { UNUSED(size); VirtualFree(ptr, 0, MEM_RELEASE); }
#elif OS_LINUX
void *os_vm_reserve  (usize size)             { void *ptr; ptr = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); return ptr; }
void  os_vm_commit   (void *addr, usize size) { mprotect(addr, size, PROT_READ | PROT_WRITE); }
void  os_vm_decommit (void *ptr, usize size)  { madvise(ptr, size, MADV_DONTNEED); }
void  os_vm_release  (void *ptr, usize size)  { munmap(ptr, size); }
#endif

////////////////////////////////////////////////////////////////////////////////
// File System

#if OS_WINDOWS
FS_OPEN_PROC()
{
    fs_file_result result = {0};
    int error             = FILE_ERROR_NONE;

    DWORD os_mode    = 0;
    DWORD os_creation = 0;
    switch (mode & FILE_MODE_MODES) {
    case FILE_MODE_READ:    os_mode = GENERIC_READ;  os_creation = OPEN_EXISTING; break;
    case FILE_MODE_WRITE:   os_mode = GENERIC_WRITE; os_creation = CREATE_ALWAYS; break;
    case FILE_MODE_APPEND:  os_mode = GENERIC_WRITE; os_creation = OPEN_ALWAYS;   break;

    case FILE_MODE_READ   | FILE_MODE_RW: os_mode = GENERIC_READ | GENERIC_WRITE; os_creation = OPEN_EXISTING; break;
    case FILE_MODE_WRITE  | FILE_MODE_RW: os_mode = GENERIC_READ | GENERIC_WRITE; os_creation = CREATE_ALWAYS; break;
    case FILE_MODE_APPEND | FILE_MODE_RW: os_mode = GENERIC_READ | GENERIC_WRITE; os_creation = OPEN_ALWAYS; break;
    default: break;
    }

    os_handle hfile = CreateFileA(to_cstr(filename), os_mode, FILE_SHARE_READ,
                                  NULL, os_creation, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
    {
        DWORD os_err = GetLastError();
        switch (os_err) {
        case ERROR_FILE_NOT_FOUND: error = FILE_ERROR_NOT_EXISTS; break;
        case ERROR_FILE_EXISTS:    error = FILE_ERROR_EXISTS; break;
        case ERROR_ALREADY_EXISTS: error = FILE_ERROR_EXISTS; break;
        case ERROR_ACCESS_DENIED:  error = FILE_ERROR_PERMISSION; break;
        default:                   error = FILE_ERROR_INVALID; break;
        }
    }

    result.hfile = hfile;

    if (CHECK_FLAG(mode, FILE_MODE_APPEND)) {
        if (fs_seek(hfile, 0, FILE_SEEK_END)) {
            CloseHandle(hfile);
            error = FILE_ERROR_INVALID;
        }
    }

    result.error = (fs_file_error)error;
    return result;
}

FS_READ_AT_PROC()
{
    fs_seek(h, offset, FILE_SEEK_OFFSET);
    int bytes_read = 0;
    if (!ReadFile(h, buffer, (DWORD)size, (DWORD *)&bytes_read, NULL))
        bytes_read = -1;

    return bytes_read;
}

FS_WRITE_AT_PROC()
{
    fs_seek(h, offset, FILE_SEEK_OFFSET);
    int bytes_written = 0;
    if (!WriteFile(h, buffer, (DWORD)size, (DWORD *)&bytes_written, NULL))
        bytes_written = -1;

    return bytes_written;
}

FS_SEEK_PROC()
{
    // NOTE(gax): the move_method in Windows correspond to our enum.
    DWORD move_method = type;
    LARGE_INTEGER li_offset;
    li_offset.QuadPart = offset;
    if (!SetFilePointerEx(h, li_offset, &li_offset, move_method))
        return -1;

    return (int)li_offset.QuadPart;
}

FS_CLOSE_PROC() { CloseHandle(h); }

#elif OS_LINUX
FS_OPEN_PROC()
{
    fs_file_result result; memory_zero_struct(&result);

    int os_mode = 0;
    switch (mode & FILE_MODE_MODES) {
    case FILE_MODE_READ:    os_mode = O_RDONLY; break;
    case FILE_MODE_WRITE:   os_mode = O_WRONLY | O_CREAT | O_TRUNC; break;
    case FILE_MODE_APPEND:  os_mode = O_WRONLY | O_CREAT | O_APPEND; break;

    case FILE_MODE_READ   | FILE_MODE_RW: os_mode = O_RDWR; break;
    case FILE_MODE_WRITE  | FILE_MODE_RW: os_mode = O_RDWR | O_CREAT | O_TRUNC; break;
    case FILE_MODE_APPEND | FILE_MODE_RW: os_mode = O_RDWR | O_CREAT | O_APPEND; break;
    default: break;
    }

    os_handle hfile = open(to_cstr(filename), os_mode);
    if (hfile < 0) {
        int os_err = errno;
        switch (os_err) {
        case ENOENT: result.error = FILE_ERROR_NOT_EXISTS; break;
        case EEXIST: result.error = FILE_ERROR_EXISTS; break;
        case EACCES: result.error = FILE_ERROR_PERMISSION; break;
        default:     result.error = FILE_ERROR_INVALID; break;
        }
    }

    result.hfile = hfile;
    return result;
}

FS_READ_AT_PROC()
{
    lseek(h, offset, SEEK_SET);
    return read(h, buffer, size);
}

FS_WRITE_AT_PROC()
{
    lseek(h, offset, SEEK_SET);
    return write(h, buffer, size);
}

FS_SEEK_PROC()
{
    int whence = 0;
    switch (type) {
    case FILE_SEEK_OFFSET:  whence = SEEK_SET; break;
    case FILE_SEEK_CURRENT: whence = SEEK_CUR; break;
    case FILE_SEEK_END:     whence = SEEK_END; break;
    }

    return lseek(h, offset, whence);
}

FS_CLOSE_PROC() { close(h); }

#endif

fs_file_error
fs_file_open(fs_file *file, string filename)
{
    fs_file_result res = fs_open(filename, FILE_MODE_READ);
    if (res.error != FILE_ERROR_NONE)
        return res.error;

    file->hfile = res.hfile;
    file->name  = filename;
    return FILE_ERROR_NONE;
}

int           fs_file_tell  (fs_file *file)                           { return fs_seek(file->hfile, 0, FILE_SEEK_CURRENT); }
int           fs_file_read  (fs_file *file, void *buffer, usize size) { return fs_read_at(file->hfile, buffer, size, fs_file_tell(file)); }
int           fs_file_write (fs_file *file, void *buffer, usize size) { return fs_write_at(file->hfile, buffer, size, fs_file_tell(file)); }
fs_file_error fs_file_close (fs_file *file)                           { fs_close(file->hfile); return FILE_ERROR_NONE; }

string
fs_read_entire_file_alloc(string filename, allocator *a)
{
    string result   = {0};
    os_handle hfile = FILE_HANDLE_INVALID;
#if OS_WINDOWS
    hfile = CreateFileA(to_cstr(filename), GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile != INVALID_HANDLE_VALUE)
    {
        LARGE_INTEGER file_size;
        GetFileSizeEx(hfile, &file_size);

        i64 size     = file_size.QuadPart;
        void *buffer = mem_alloc(a, size);
        if (ReadFile(hfile, buffer,(DWORD)size, NULL, NULL) != FALSE) {
            result.data = (u8 *)buffer;
            result.len  = size;
        } else {
            mem_free(a, buffer);
        }
    }

    CloseHandle(hfile);
#elif OS_LINUX
    hfile = open(to_cstr(filename), O_RDONLY);
    if (hfile != FILE_HANDLE_INVALID)
    {
        struct stat st;
        fstat(hfile, &st);

        i64 size     = st.st_size;
        void *buffer = mem_alloc(a, size);
        if (read(hfile, buffer, size) != -1) {
            result.data = (u8 *)buffer;
            result.len  = size;
        } else {
            mem_free(a, buffer);
        }
    }
#endif
    return result;
}

////////////////////////////////////////////////////////////////////////////////
// Environment
string
os_get_env(string name)
{
    string result; memory_zero_struct(&result);
    char *value = getenv(to_cstr(name));
    if (value) {
        result.data = (u8 *)value;
        result.len  = strlen(value);
    }
    return result;
}

#endif // DRT_IMPLEMENTATION
// clang-format on
