#include "config.h"

#include <dnsjit/core/assert.h>
#include <dnsjit/core/log.h>
#include <dnsjit/core/receiver.h>
#include <dnsjit/core/producer.h>

typedef struct output_null {
    core_log_t      _log;
    core_producer_t prod;
    void*           ctx;
    size_t          pkts;
} output_null_t;

static core_log_t    _log      = LOG_T_INIT("example.output.null");
static output_null_t _defaults = {
    LOG_T_INIT_OBJ("example.output.null"),
    0, 0, 0
};

core_log_t* output_null_log()
{
    return &_log;
}

void output_null_init(output_null_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void output_null_destroy(output_null_t* self)
{
    mlassert_self();
}

static void _receive(output_null_t* self, const core_object_t* obj)
{
    mlassert_self();

    self->pkts++;
}

core_receiver_t output_null_receiver()
{
    return (core_receiver_t)_receive;
}

void output_null_run(output_null_t* self, int64_t num)
{
    mlassert_self();

    if (!self->prod) {
        lfatal("no producer set");
    }

    if (num > 0) {
        while (num--) {
            const core_object_t* obj = self->prod(self->ctx);
            if (!obj)
                break;

            self->pkts++;
        }
    } else {
        for (;;) {
            const core_object_t* obj = self->prod(self->ctx);
            if (!obj)
                break;

            self->pkts++;
        }
    }
}
