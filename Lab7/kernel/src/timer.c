#include "timer.h"
#include "def.h"
#include "list.h"
#include "memory.h"
#include "mini_uart.h"
#include "sched.h"
#include "slab.h"
#include "string.h"

#define MSG_SIZE        32
#define alloc_timer()   (timeout_event_t*)kmem_cache_alloc(timer, 0)
#define free_timer(ptr) kmem_cache_free(timer, (ptr))

static LIST_HEAD(timeout_event_head);
static struct kmem_cache* timer;


typedef struct timeout_event {
    unsigned long reg_time;   // register time, represent by ticks
    unsigned long duration;   // duration time, represent by ticks
    timer_callback callback;  // callback fucntion
    char* msg;                // callback fucntion argument
    bool is_periodic;         // is_preiodic
    struct list_head list;    // list node
} timeout_event_t;

int timer_init(void)
{
    timer = kmem_cache_create("timer", sizeof(timeout_event_t), -1);
    if (!timer)
        return 0;

    uint64_t tmp;
    asm volatile("mrs %0, cntkctl_el1" : "=r"(tmp));
    tmp |= 1;
    asm volatile("msr cntkctl_el1, %0" : : "r"(tmp));

    return 1;
}

static timeout_event_t* create_timeout_event(timer_callback cb,
                                             char* msg,
                                             unsigned long duration,
                                             bool is_periodic)
{
    timeout_event_t* new_timeout_event = alloc_timer();
    if (!new_timeout_event)
        return NULL;

    INIT_LIST_HEAD(&new_timeout_event->list);
    new_timeout_event->reg_time = get_current_ticks();
    new_timeout_event->duration = duration;
    new_timeout_event->callback = cb;
    new_timeout_event->is_periodic = is_periodic;

    new_timeout_event->msg = NULL;

    if (msg) {
        new_timeout_event->msg = kzmalloc(sizeof(char) * MSG_SIZE, 0);
        str_n_cpy(new_timeout_event->msg, msg, MSG_SIZE);
    }

    return new_timeout_event;
}

static void insert_timeout_event(timeout_event_t* new_event)
{
    if (!new_event)
        return;

    unsigned long invoke_time = new_event->reg_time + new_event->duration;
    // unsigned long current_time = get_current_ticks();

    timeout_event_t* node = NULL;
    list_for_each_entry (node, &timeout_event_head, list) {
        unsigned long node_time = node->reg_time + node->duration;
        if (node_time > invoke_time)
            break;
    }

    list_add_tail(&new_event->list, &node->list);

    // if the new event is the first event in the list, set the core timer
    if (list_first_entry(&timeout_event_head, timeout_event_t, list) ==
        new_event) {
        set_core_timer_timeout_ticks(new_event->duration);
        enable_core0_timer();
    }
}

void add_timer(timer_callback cb,
               char* msg,
               unsigned long duration,
               bool is_periodic)
{
    timeout_event_t* new_timeout_event =
        create_timeout_event(cb, msg, duration, is_periodic);
    insert_timeout_event(new_timeout_event);
}


void core_timer_handle_irq(void)
{
    // uart_printf("timer_handler\n");
    // unsigned long current_ticks = get_current_ticks();
    // unsigned long freq = get_freq();

    timeout_event_t* first_event =
        list_first_entry(&timeout_event_head, timeout_event_t, list);

    list_del_init(&first_event->list);

    if (first_event->is_periodic)
        add_timer(first_event->callback, first_event->msg,
                  first_event->duration, true);
    // uart_send_string("\nmessage: ");
    first_event->callback(first_event->msg);

    // uart_send_string("\ncurrent time: ");
    // uart_send_dec(current_ticks / freq);

    // uart_send_string("\ncommand execute time: ");
    // uart_send_dec(first_event->reg_time / freq);

    // uart_send_string("\ncommand duration time: ");
    // uart_send_dec(first_event->duration / freq);
    // uart_send_string("\n");

    if (first_event->msg)
        kfree(first_event->msg);

    free_timer(first_event);

    if (!list_empty(&timeout_event_head)) {
        timeout_event_t* next =
            list_first_entry(&timeout_event_head, timeout_event_t, list);

        set_core_timer_timeout_ticks(next->reg_time + next->duration -
                                     get_current_ticks());
        enable_core0_timer();
    }

    // uart_printf("timer_handler end\n");
}

void print_msg(char* msg)
{
    uart_send_string(msg);
}
