#define DRT_IMPLEMENTATION
#include "drt.h"

////////////////////////////////////////
// Structs
typedef struct input_buffer input_buffer;
struct input_buffer
{
    arena *arena;
    arena *tmp_arena;   // TODO: Remove this and use scratch arena

    string  buffer;
    ssize_t input_length;
};

////////////////////////////////////////
// Functions
static void print_prompt(void) { printf("udb> "); fflush(stdout); }

static void
read_input(input_buffer *ibuffer)
{
    ibuffer->input_length = 0;
    arena_clear(ibuffer->arena);

    string_list input_list = str_list();
    string current; memory_zero_struct(&current);
    bool done = false;
    while (!done) {
        current.len  = 1024;
        current.data = arena_push_array(ibuffer->tmp_arena, u8, current.len);

        ssize_t bytes_read = read(STDIN_FILENO, current.data, current.len);
        if (bytes_read <= 0) {
            error_sys("in-buffer", "Error reading input\n");
            exit(1);
        } else {
            current.len = bytes_read;
            if (current.data[bytes_read - 1] == '\n') {
                current.len -= 1;
                done         = true;
            }
            string_list_push(ibuffer->tmp_arena, &input_list, current);
            ibuffer->input_length += current.len;
        }
    }

    debug_sys("in-buffer", "Read %d bytes\n", ibuffer->input_length);

    // Concatenate the input list into a single string
    ibuffer->buffer = string_list_concat(ibuffer->arena, &input_list, str_lit(""));
    arena_clear(ibuffer->tmp_arena);
}

////////////////////////////////////////
global_variable arena *main_arena;

////////////////////////////////////////
int
log_write(const char *msg, usize len)
{
    return fprintf(stderr, "%.*s", (int)len, msg);
}

////////////////////////////////////////
int
main(int argc, char *argv[])
{
    UNUSED(argc);
    UNUSED(argv);

    u32 log_level = LOG_INFO;
    string env_log_level = os_get_env(str_lit("LOG_LEVEL"));
    if (!string_empty(env_log_level))
        log_level = logger_log_levelstr_to_enum(to_cstr(env_log_level));

    logger_log_set_level(&g_drt_logger, log_level);
    logger_log_set_write(&g_drt_logger, log_write);
    logger_log_set_title(&g_drt_logger, "udb");
    logger_log_set_ts(&g_drt_logger, true);
    logger_log_set_ctx(&g_drt_logger, true);

    main_arena = arena_vm_alloc();

    input_buffer *ibuffer = arena_push_struct(main_arena, input_buffer);
    ibuffer->arena        = arena_vm_alloc(.reserve_size=MB(64));
    ibuffer->tmp_arena    = arena_vm_alloc(.reserve_size=MB(64));

    printf("Welcome to uDB: a minimal database\n");
    while (true) {
        print_prompt();
        read_input(ibuffer);

        debug_ctx("Entered command: " SPRI "\n", str_varg(ibuffer->buffer));
        if (string_equal(ibuffer->buffer, str_lit(".exit"))) {
            break;
        } else if (string_equal(ibuffer->buffer, str_lit("clear"))) {
            // Clear the screen
            printf("\033[H\033[J");
            fflush(stdout);
        } else if (string_equal(ibuffer->buffer, str_lit(".help"))) {
            printf("Commands:\n");
            printf("  .exit - Exit uDB\n");
            printf("  .help - Display this help message\n");
        } else {
            error("Unrecognized command \"" SPRI "\".\n", str_varg(ibuffer->buffer));
        }
    }

    info("Exiting uDB\n");

    return 0;
}
