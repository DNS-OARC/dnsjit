/*
 * Copyright (c) 2018-2021, OARC, Inc.
 * All rights reserved.
 *
 * This file is part of dnsjit.
 *
 * dnsjit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dnsjit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "core/log.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

static core_log_t _log = LOG_T_INIT("core");

void core_log_debug(const core_log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    if (!l) {
        if (_log.settings.debug != 3) {
            return;
        }
    } else {
        if (l->settings.debug) {
            if (l->settings.debug != 3) {
                return;
            }
        } else if (l->module && l->module->debug) {
            if (l->module->debug != 3) {
                return;
            }
        } else if (_log.settings.debug != 3) {
            return;
        }
    }
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    for (;;) {
        if (!l) {
            if (_log.settings.display_file_line != 3) {
                break;
            }
        } else {
            if (l->settings.display_file_line) {
                if (l->settings.display_file_line != 3) {
                    break;
                }
            } else if (l->module && l->module->display_file_line) {
                if (l->module->display_file_line != 3) {
                    break;
                }
            } else if (_log.settings.display_file_line != 3) {
                break;
            }
        }
        if (l) {
            if (l->is_obj) {
                fprintf(stderr, "%s[%zu] %s[%p] debug: %s\n", file, line, l->name, l, buf);
                return;
            }
            fprintf(stderr, "%s[%zu] %s debug: %s\n", file, line, l->name, buf);
            return;
        }
        fprintf(stderr, "%s[%zu] %s debug: %s\n", file, line, _log.name, buf);
        return;
    }

    if (l) {
        if (l->is_obj) {
            fprintf(stderr, "%s[%p] debug: %s\n", l->name, l, buf);
            return;
        }
        fprintf(stderr, "%s debug: %s\n", l->name, buf);
        return;
    }
    fprintf(stderr, "%s debug: %s\n", _log.name, buf);
}

void core_log_info(const core_log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    if (!l) {
        if (_log.settings.info != 3) {
            return;
        }
    } else {
        if (l->settings.info) {
            if (l->settings.info != 3) {
                return;
            }
        } else if (l->module && l->module->info) {
            if (l->module->info != 3) {
                return;
            }
        } else if (_log.settings.info != 3) {
            return;
        }
    }
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    for (;;) {
        if (!l) {
            if (_log.settings.display_file_line != 3) {
                break;
            }
        } else {
            if (l->settings.display_file_line) {
                if (l->settings.display_file_line != 3) {
                    break;
                }
            } else if (l->module && l->module->display_file_line) {
                if (l->module->display_file_line != 3) {
                    break;
                }
            } else if (_log.settings.display_file_line != 3) {
                break;
            }
        }
        if (l) {
            if (l->is_obj) {
                fprintf(stderr, "%s[%zu] %s[%p] info: %s\n", file, line, l->name, l, buf);
                return;
            }
            fprintf(stderr, "%s[%zu] %s info: %s\n", file, line, l->name, buf);
            return;
        }
        fprintf(stderr, "%s[%zu] %s info: %s\n", file, line, _log.name, buf);
        return;
    }

    if (l) {
        if (l->is_obj) {
            fprintf(stderr, "%s[%p] info: %s\n", l->name, l, buf);
            return;
        }
        fprintf(stderr, "%s info: %s\n", l->name, buf);
        return;
    }
    fprintf(stderr, "%s info: %s\n", _log.name, buf);
}

void core_log_notice(const core_log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    if (!l) {
        if (_log.settings.notice != 3) {
            return;
        }
    } else {
        if (l->settings.notice) {
            if (l->settings.notice != 3) {
                return;
            }
        } else if (l->module && l->module->notice) {
            if (l->module->notice != 3) {
                return;
            }
        } else if (_log.settings.notice != 3) {
            return;
        }
    }
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    for (;;) {
        if (!l) {
            if (_log.settings.display_file_line != 3) {
                break;
            }
        } else {
            if (l->settings.display_file_line) {
                if (l->settings.display_file_line != 3) {
                    break;
                }
            } else if (l->module && l->module->display_file_line) {
                if (l->module->display_file_line != 3) {
                    break;
                }
            } else if (_log.settings.display_file_line != 3) {
                break;
            }
        }
        if (l) {
            if (l->is_obj) {
                fprintf(stderr, "%s[%zu] %s[%p] notice: %s\n", file, line, l->name, l, buf);
                return;
            }
            fprintf(stderr, "%s[%zu] %s notice: %s\n", file, line, l->name, buf);
            return;
        }
        fprintf(stderr, "%s[%zu] %s notice: %s\n", file, line, _log.name, buf);
        return;
    }

    if (l) {
        if (l->is_obj) {
            fprintf(stderr, "%s[%p] notice: %s\n", l->name, l, buf);
            return;
        }
        fprintf(stderr, "%s notice: %s\n", l->name, buf);
        return;
    }
    fprintf(stderr, "%s notice: %s\n", _log.name, buf);
}

void core_log_warning(const core_log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    if (!l) {
        if (_log.settings.warning != 3) {
            return;
        }
    } else {
        if (l->settings.warning) {
            if (l->settings.warning != 3) {
                return;
            }
        } else if (l->module && l->module->warning) {
            if (l->module->warning != 3) {
                return;
            }
        } else if (_log.settings.warning != 3) {
            return;
        }
    }
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    for (;;) {
        if (!l) {
            if (_log.settings.display_file_line != 3) {
                break;
            }
        } else {
            if (l->settings.display_file_line) {
                if (l->settings.display_file_line != 3) {
                    break;
                }
            } else if (l->module && l->module->display_file_line) {
                if (l->module->display_file_line != 3) {
                    break;
                }
            } else if (_log.settings.display_file_line != 3) {
                break;
            }
        }
        if (l) {
            if (l->is_obj) {
                fprintf(stderr, "%s[%zu] %s[%p] warning: %s\n", file, line, l->name, l, buf);
                return;
            }
            fprintf(stderr, "%s[%zu] %s warning: %s\n", file, line, l->name, buf);
            return;
        }
        fprintf(stderr, "%s[%zu] %s warning: %s\n", file, line, _log.name, buf);
        return;
    }

    if (l) {
        if (l->is_obj) {
            fprintf(stderr, "%s[%p] warning: %s\n", l->name, l, buf);
            return;
        }
        fprintf(stderr, "%s warning: %s\n", l->name, buf);
        return;
    }
    fprintf(stderr, "%s warning: %s\n", _log.name, buf);
}

void core_log_critical(const core_log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    for (;;) {
        if (!l) {
            if (_log.settings.display_file_line != 3) {
                break;
            }
        } else {
            if (l->settings.display_file_line) {
                if (l->settings.display_file_line != 3) {
                    break;
                }
            } else if (l->module && l->module->display_file_line) {
                if (l->module->display_file_line != 3) {
                    break;
                }
            } else if (_log.settings.display_file_line != 3) {
                break;
            }
        }
        if (l) {
            if (l->is_obj) {
                fprintf(stderr, "%s[%zu] %s[%p] critical: %s\n", file, line, l->name, l, buf);
                return;
            }
            fprintf(stderr, "%s[%zu] %s critical: %s\n", file, line, l->name, buf);
            return;
        }
        fprintf(stderr, "%s[%zu] %s critical: %s\n", file, line, _log.name, buf);
        return;
    }

    if (l) {
        if (l->is_obj) {
            fprintf(stderr, "%s[%p] critical: %s\n", l->name, l, buf);
            return;
        }
        fprintf(stderr, "%s critical: %s\n", l->name, buf);
        return;
    }
    fprintf(stderr, "%s critical: %s\n", _log.name, buf);
}

void core_log_fatal(const core_log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    for (;;) {
        if (!l) {
            if (_log.settings.display_file_line != 3) {
                break;
            }
        } else {
            if (l->settings.display_file_line) {
                if (l->settings.display_file_line != 3) {
                    break;
                }
            } else if (l->module && l->module->display_file_line) {
                if (l->module->display_file_line != 3) {
                    break;
                }
            } else if (_log.settings.display_file_line != 3) {
                break;
            }
        }
        if (l) {
            if (l->is_obj) {
                fprintf(stderr, "%s[%zu] %s[%p] fatal: %s\n", file, line, l->name, l, buf);
                exit(1);
            }
            fprintf(stderr, "%s[%zu] %s fatal: %s\n", file, line, l->name, buf);
            exit(1);
        }
        fprintf(stderr, "%s[%zu] %s fatal: %s\n", file, line, _log.name, buf);
        exit(1);
    }

    if (l) {
        if (l->is_obj) {
            fprintf(stderr, "%s[%p] fatal: %s\n", l->name, l, buf);
            exit(1);
        }
        fprintf(stderr, "%s fatal: %s\n", l->name, buf);
        exit(1);
    }
    fprintf(stderr, "%s fatal: %s\n", _log.name, buf);
    exit(1);
}

core_log_t* core_log_log()
{
    return &_log;
}

#include "core/log_errstr.c"
