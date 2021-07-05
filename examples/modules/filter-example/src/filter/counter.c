#include "config.h"

#include <dnsjit/core/assert.h>
#include <dnsjit/core/log.h>
#include <dnsjit/core/receiver.h>
#include <dnsjit/core/producer.h>

typedef struct filter_counter {
    core_log_t _log;

    core_receiver_t recv;
    void*           ctx;

    core_producer_t prod;
    void*           prod_ctx;

    size_t count;
} filter_counter_t;

static core_log_t       _log      = LOG_T_INIT("example.filter.counter");
static filter_counter_t _defaults = {
    LOG_T_INIT_OBJ("example.filter.counter"),
    0, 0,
    0, 0,
    0
};

core_log_t* filter_counter_log()
{
    return &_log;
}

void filter_counter_init(filter_counter_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void filter_counter_destroy(filter_counter_t* self)
{
    mlassert_self();
}

static void _receive(filter_counter_t* self, const core_object_t* obj)
{
    mlassert_self();
    lassert(obj, "obj is nil");

    if (!self->recv) {
        lfatal("no receiver set");
    }
    self->count++;
    self->recv(self->ctx, obj);
}

core_receiver_t filter_counter_receiver()
{
    return (core_receiver_t)_receive;
}

static const core_object_t* _produce(filter_counter_t* self)
{
    const core_object_t* obj;
    mlassert_self();

    obj = self->prod(self->prod_ctx);
    if (obj) {
        self->count++;
    }

    return obj;
}

core_producer_t filter_counter_producer(filter_counter_t* self)
{
    mlassert_self();

    if (!self->prod) {
        lfatal("no producer set");
    }

    return (core_producer_t)_produce;
}
