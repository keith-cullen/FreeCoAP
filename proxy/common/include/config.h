/*
 * Copyright (c) 2014 Keith Cullen.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *  @file config.h
 *
 *  @brief Include file for the FreeCoAP configuration library
 */

#ifndef CONFIG_H
#define CONFIG_H

#define config_get_first_entry(config)  ((config)->first)
#define config_get_last_entry(config)   ((config)->last)

#define config_entry_get_name(entry)   ((entry)->name)
#define config_entry_get_value(entry)  ((entry)->value)
#define config_entry_get_next(entry)   ((entry)->next)

typedef enum
{
    CONFIG_DONE = 1,       /* processing (parsing) completed successfully - only used internally */
    CONFIG_OK = 0,         /* success */
    CONFIG_EINVAL = -1,    /* invalid argument */
    CONFIG_ENOMEM = -2,    /* no (dynamic) memory */
    CONFIG_ELEXICAL = -3,  /* lexical error */
    CONFIG_ESYNTAX = -4    /* syntax error */
}
config_error_t;

typedef struct config_entry_t
{
    char *name;
    char *value;
    struct config_entry_t *next;
}
config_entry_t;

typedef struct config_section_t
{
    char *name;
    config_entry_t *first;
    config_entry_t *last;
    struct config_section_t *next;
}
config_section_t;

typedef struct
{
    config_section_t *first;
    config_section_t *last;
}
config_t;

const char *config_strerr(int error);
void config_create(config_t * config);
void config_destroy(config_t *config);
int config_set(config_t *config, const char *section_name, const char *entry_name, const char *entry_value);
const char *config_get(config_t *config, const char *section_name, const char *entry_name);
int config_parse(config_t *config, const char *str, unsigned *line, unsigned *col);

#endif
