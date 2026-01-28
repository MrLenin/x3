/*
 * x3_kc_adapter.h - Bridge between X3's ioset/timeq and libkc's event adapter
 *
 * Implements kc_event_ops and kc_log_ops using X3's native event loop (ioset),
 * timer queue (timeq), and logging (log_module).
 */

#ifndef X3_KC_ADAPTER_H
#define X3_KC_ADAPTER_H

#include "kc/kc_event.h"
#include "kc/kc_log.h"

/* Initialize the adapter and return the ops structs for kc_init().
 * Must be called after ioset_init() and log_init(). */
void x3_kc_adapter_init(void);

/* Get the event ops struct for passing to kc_init(). */
const struct kc_event_ops *x3_kc_get_event_ops(void);

/* Get the log ops struct for passing to kc_init(). */
const struct kc_log_ops *x3_kc_get_log_ops(void);

/* Cleanup adapter state (call before kc_shutdown). */
void x3_kc_adapter_cleanup(void);

#endif /* X3_KC_ADAPTER_H */
