#include "config.h"

#include <dnsjit/core/assert.h>
#include <dnsjit/core/object/null.h>
#include <dnsjit/core/log.h>
#include <dnsjit/core/receiver.h>
#include <dnsjit/core/producer.h>

typedef struct input_zero {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;
} input_zero_t;

static core_log_t   _log      = LOG_T_INIT("input.zero");
static input_zero_t _defaults = {
    LOG_T_INIT_OBJ("input.zero"),
    0,
    0,
};

static core_object_null_t _null = CORE_OBJECT_NULL_INIT(0);

core_log_t* input_zero_log()
{
    return &_log;
}

void input_zero_init(input_zero_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void input_zero_destroy(input_zero_t* self)
{
    mlassert_self();
}

void input_zero_run(input_zero_t* self, uint64_t num)
{
    mlassert_self();
    if (!self->recv) {
        lfatal("no receiver set");
    }

    while (num--) {
        self->recv(self->ctx, (core_object_t*)&_null);
    }
}

static const core_object_t* _produce(void* ctx)
{
    return (core_object_t*)&_null;
}

core_producer_t input_zero_producer()
{
    return _produce;
}
