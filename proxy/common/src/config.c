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
 *  @file config.c
 *
 *  @brief Source file for the FreeCoAP configuration library
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "config.h"

#define CONFIG_NUM_STR  6

#define CONFIG_PARSER_DEF_TAB_WIDTH   4
#define CONFIG_PARSER_INIT_STR_LEN   64

typedef enum
{
    CONFIG_PARSER_EOF = -1,
    CONFIG_PARSER_NONE = 0,
    CONFIG_PARSER_EOL,
    CONFIG_PARSER_ASSIGN,
    CONFIG_PARSER_LEFT_BRACKET,
    CONFIG_PARSER_RIGHT_BRACKET,
    CONFIG_PARSER_ID,
    CONFIG_PARSER_NUM,
    CONFIG_PARSER_QUOTE
}
config_parser_token_t;

typedef struct config_parser_snode_t
{
    char *data;
    struct config_parser_snode_t *next;
}
config_parser_snode_t;

typedef struct config_parser_stack
{
    config_parser_snode_t *top;
}
config_parser_stack_t;

typedef struct config_parser_str
{
    char *buf;
    unsigned idx;
    unsigned len;
}
config_parser_str_t;

typedef int (*config_parser_cb_func_t)(void *, const char *, const char *, const char *);
typedef void *config_parser_cb_data_t;

typedef struct
{
    char *in;
    unsigned in_idx;
    unsigned in_len;
    unsigned tab_width;
    unsigned line;
    unsigned col;
    unsigned prev_line;
    unsigned prev_col;
    unsigned token_line;
    unsigned token_col;
    config_parser_stack_t id_stack;
    config_parser_token_t token;
    config_parser_str_t token_str;
    config_parser_str_t section;
    config_parser_cb_func_t cb_func;
    config_parser_cb_data_t cb_data;
}
config_parser_t;

static const char *config_str[CONFIG_NUM_STR + 1] =
{
    "ok",
    "invalid argument",
    "out of memory",
    "input/output error",
    "lexical error",
    "syntax error",
    "unknown"
};

const char *config_strerr(int error)
{
    error = -error;
    if ((error < 0) || (error > CONFIG_NUM_STR))
        return config_str[CONFIG_NUM_STR];
    return config_str[error];
}

static config_parser_snode_t *config_parser_snode_new(const char *data)
{
    config_parser_snode_t *node = NULL;

    node = (config_parser_snode_t *)calloc(1, sizeof(config_parser_snode_t));
    if (node != NULL)
    {
        node->data = strdup(data);
        if (node->data == NULL)
        {
            free(node);
            node = NULL;
        }
    }
    return node;
}

static void config_parser_snode_delete(config_parser_snode_t *node)
{
    free(node->data);
    free(node);
}

/* free node but not the data contained in it */
static inline void config_parser_snode_free(config_parser_snode_t *node)
{
    free(node);
}

static void config_parser_stack_create(config_parser_stack_t *s)
{
    memset(s, 0, sizeof(config_parser_stack_t));
}

static void config_parser_stack_destroy(config_parser_stack_t *s)
{
    config_parser_snode_t *prev = NULL;
    config_parser_snode_t *node = s->top;

    while (node != NULL)
    {
        prev = node;
        node = node->next;
        config_parser_snode_delete(prev);
    }
    memset(s, 0, sizeof(config_parser_stack_t));
}

static int config_parser_stack_push(config_parser_stack_t *s, const char *data)
{
    config_parser_snode_t *node = NULL;

    node = config_parser_snode_new(data);
    if (node == NULL)
    {
        return CONFIG_ENOMEM;
    }
    node->next = s->top;
    s->top = node;
    return CONFIG_OK;
}

/* the return value must be freed by the calling function */
static char *config_parser_stack_pop(config_parser_stack_t *s)
{
    config_parser_snode_t *node = NULL;
    char *data = NULL;

    if ((s != NULL) && (s->top != NULL))
    {
        node = s->top;
        data = node->data;
        s->top = s->top->next;
        config_parser_snode_free(node);
    }
    return data;
}

static int config_parser_str_create(config_parser_str_t *s)
{
    s->idx = 0;
    s->buf = calloc(CONFIG_PARSER_INIT_STR_LEN + 1, 1);
    if (s->buf == NULL)
    {
        s->len = 0;
        return CONFIG_ENOMEM;
    }
    s->len = CONFIG_PARSER_INIT_STR_LEN;
    return CONFIG_OK;
}

static void config_parser_str_destroy(config_parser_str_t *s)
{
    if (s->buf != NULL)
    {
        free(s->buf);
    }
    s->buf = NULL;
    s->idx = 0;
    s->len = 0;
}

static int config_parser_str_append(config_parser_str_t *s, char c)
{
    unsigned new_len = 0;
    char *new_buf = NULL;

    if (s->idx >= s->len)
    {
        new_len = 2 * s->len;
        new_buf = calloc(new_len + 1, 1);
        if (new_buf == NULL)
        {
            return CONFIG_ENOMEM;
        }
        memcpy(new_buf, s->buf, s->len);
        free(s->buf);
        s->buf = new_buf;
        s->len = new_len;
    }
    s->buf[s->idx++] = c;
    return CONFIG_OK;
}

static int config_parser_str_copy(config_parser_str_t *s, const char *str)
{
    unsigned len = 0;
    unsigned i = 0;
    int ret = 0;

    memset(s->buf, 0, s->len + 1);
    s->idx = 0;
    len = strlen(str);
    for (i = 0; i < len; i++)
    {
        ret = config_parser_str_append(s, str[i]);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
    }
    return CONFIG_OK;
}

static int config_parser_next(config_parser_t *p)
{
    int c = 0;

    p->prev_line = p->line;
    p->prev_col = p->col;
    if (p->in_idx == p->in_len)
    {
        c = '\0';
    }
    else
    {
        c = p->in[p->in_idx];
    }
    p->in_idx++;
    if (c == '\n')
    {
        p->line++;
        p->col = 0;
    }
    else if (c == '\t')
    {
        p->col = ((p->col + p->tab_width) / p->tab_width) * p->tab_width;
    }
    else
    {
        p->col++;
    }
    return c;
}

static int config_parser_next_skip_ws(config_parser_t *p)
{
    int c = 0;

    while (1)
    {
        c = config_parser_next(p);
        if (c == '\n')
        {
            return c;
        }
        if (!isspace(c))
        {
            return c;
        }
    }
    return 0;
}

static void config_parser_put_back(config_parser_t *p)
{
    if (p->in_idx > 0)
    {
        p->in_idx--;
        p->line = p->prev_line;
        p->col = p->prev_col;
    }
}

static void config_parser_set_token_pos(config_parser_t *p, int c)
{
    if (c == '\n')
    {
        p->token_line = p->prev_line;
        p->token_col = p->prev_col + 1;
    }
    else
    {
        p->token_line = p->line;
        p->token_col = p->col;
    }
}

static int config_parser_lex(config_parser_t *p)
{
    int ret = 0;
    int pc = 0;
    int c = 0;

    p->token = CONFIG_PARSER_NONE;
    config_parser_str_destroy(&p->token_str);
    c = config_parser_next_skip_ws(p);
    config_parser_set_token_pos(p, c);
    if (c == '\0')
    {
        p->token = CONFIG_PARSER_EOF;
        return CONFIG_OK;
    }
    else if (c == '\n')
    {
        p->token = CONFIG_PARSER_EOL;
        return CONFIG_OK;
    }
    else if (c == ';')
    {
        while (1)
        {
            c = config_parser_next(p);
            if (c == '\n')
            {
                p->token = CONFIG_PARSER_EOL;
                return CONFIG_OK;
            }
            if (c == '\0')
            {
                p->token = CONFIG_PARSER_EOF;
                return CONFIG_OK;
            }
        }
    }
    else if (c == '=')
    {
        p->token = CONFIG_PARSER_ASSIGN;
        return CONFIG_OK;
    }
    else if (c == '[')
    {
        p->token = CONFIG_PARSER_LEFT_BRACKET;
        return CONFIG_OK;
    }
    else if (c == ']')
    {
        p->token = CONFIG_PARSER_RIGHT_BRACKET;
        return CONFIG_OK;
    }
    else if (isalpha(c))
    {
        p->token = CONFIG_PARSER_ID;
        ret = config_parser_str_create(&p->token_str);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
        while (isalpha(c) || isdigit(c) || (c == '_'))
        {
            ret = config_parser_str_append(&p->token_str, c);
            if (ret != CONFIG_OK)
            {
                return ret;
            }
            c = config_parser_next(p);
        }
        config_parser_put_back(p);
        return CONFIG_OK;
    }
    else if (isdigit(c))
    {
        p->token = CONFIG_PARSER_NUM;
        ret = config_parser_str_create(&p->token_str);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
        while (isdigit(c))
        {
            ret = config_parser_str_append(&p->token_str, c);
            if (ret != CONFIG_OK)
            {
                return ret;
            }
            c = config_parser_next(p);
        }
        config_parser_put_back(p);
        return CONFIG_OK;
    }
    else if (c == '\"')
    {
        p->token = CONFIG_PARSER_QUOTE;
        ret = config_parser_str_create(&p->token_str);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
        pc = 0;
        c = config_parser_next(p);
        while (1)
        {
            if ((c == '\"') && (pc != '\\'))
            {
                break;
            }
            if (((c == '\n') && (pc != '\\')) || (c == '\0'))
            {
                return CONFIG_ELEXICAL;
            }
            ret = config_parser_str_append(&p->token_str, c);
            if (ret != CONFIG_OK)
            {
                return ret;
            }
            pc = c;
            c = config_parser_next(p);
        }
        return CONFIG_OK;
    }
    return CONFIG_ELEXICAL;
}

static int config_parser_id(config_parser_t *p)
{
    int ret = 0;

    if (p->token != CONFIG_PARSER_ID)
    {
        return CONFIG_ESYNTAX;
    }
    ret = config_parser_stack_push(&p->id_stack, p->token_str.buf);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    return config_parser_lex(p);
}

static int config_parser_num(config_parser_t *p)
{
    int ret = 0;

    if (p->token != CONFIG_PARSER_NUM)
    {
        return CONFIG_ESYNTAX;
    }
    ret = config_parser_stack_push(&p->id_stack, p->token_str.buf);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    return config_parser_lex(p);
}

static int config_parser_quote(config_parser_t *p)
{
    int ret = 0;

    if (p->token != CONFIG_PARSER_QUOTE)
    {
        return CONFIG_ESYNTAX;
    }
    ret = config_parser_stack_push(&p->id_stack, p->token_str.buf);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    return config_parser_lex(p);
}

static int config_parser_name(config_parser_t *p)
{
    return config_parser_id(p);
}

static int config_parser_value(config_parser_t *p)
{
    if (p->token == CONFIG_PARSER_ID)
    {
        return config_parser_id(p);
    }
    else if (p->token == CONFIG_PARSER_NUM)
    {
        return config_parser_num(p);
    }
    else if (p->token == CONFIG_PARSER_QUOTE)
    {
        return config_parser_quote(p);
    }
    return CONFIG_ESYNTAX;
}

static int config_parser_assignment(config_parser_t *p)
{
    char *value = NULL;
    char *name = NULL;
    int ret = 0;

    ret = config_parser_name(p);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    if (p->token != CONFIG_PARSER_ASSIGN)
    {
        return CONFIG_ESYNTAX;
    }
    ret = config_parser_lex(p);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    ret = config_parser_value(p);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    value = config_parser_stack_pop(&p->id_stack);
    name = config_parser_stack_pop(&p->id_stack);
    ret = (*p->cb_func)(p->cb_data, p->section.buf, name, value);
    free(name);
    free(value);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    return CONFIG_OK;
}

static int config_parser_section(config_parser_t *p)
{
    char *name = NULL;
    int ret = 0;

    if (p->token != CONFIG_PARSER_LEFT_BRACKET)
    {
        return CONFIG_ESYNTAX;
    }
    ret = config_parser_lex(p);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    ret = config_parser_name(p);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    if (p->token != CONFIG_PARSER_RIGHT_BRACKET)
    {
        return CONFIG_ESYNTAX;
    }
    name = config_parser_stack_pop(&p->id_stack);
    ret = config_parser_str_copy(&p->section, name);
    free(name);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    ret = config_parser_lex(p);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    return CONFIG_OK;
}

static int config_parser_expression(config_parser_t *p)
{
    int ret = 0;

    if (p->token == CONFIG_PARSER_ID)
    {
        ret = config_parser_assignment(p);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
    }
    else if (p->token == CONFIG_PARSER_LEFT_BRACKET)
    {
        ret = config_parser_section(p);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
    }

    if (p->token == CONFIG_PARSER_EOF)
    {
        return CONFIG_OK;
    }
    if (p->token == CONFIG_PARSER_EOL)
    {
        return CONFIG_OK;
    }
    return CONFIG_ESYNTAX;
}

static int config_parser_statement(config_parser_t *p)
{
    if (p->token == CONFIG_PARSER_EOL)
    {
        return CONFIG_OK;
    }
    if (p->token == CONFIG_PARSER_EOF)
    {
        return CONFIG_DONE;
    }
    return config_parser_expression(p);
}

static int config_parser_exec(config_parser_t *p, const char *str, unsigned *line, unsigned *col)
{
    int ret = 0;

    *line = 0;
    *col = 0;

    if (p->in != NULL)
    {
        free(p->in);
    }
    p->in_idx = 0;
    p->in_len = 0;
    p->in = strdup(str);
    if (p->in == NULL)
    {
        return CONFIG_ENOMEM;
    }
    p->in_len = strlen(p->in);
    p->line = 1;
    p->col = 0;
    p->prev_line = 1;
    p->prev_col = 0;
    p->token_line = 0;
    p->token_col = 0;
    while (1)
    {
        ret = config_parser_lex(p);
        if (ret != CONFIG_OK)
        {
            *line = p->token_line;
            *col = p->token_col;
            return ret;
        }
        ret = config_parser_statement(p);
        if (ret == CONFIG_DONE)
        {
            return CONFIG_OK;
        }
        else if (ret != CONFIG_OK)
        {
            *line = p->token_line;
            *col = p->token_col;
            return ret;
        }
    }
    return CONFIG_OK;  /* should never reach here */
}

static int config_parser_create(config_parser_t *p, config_parser_cb_func_t cb_func, config_parser_cb_data_t cb_data)
{
    int ret = 0;

    memset(p, 0, sizeof(config_parser_t));
    ret = config_parser_str_create(&p->section);
    if (ret != CONFIG_OK)
    {
        return ret;
    }
    p->tab_width = CONFIG_PARSER_DEF_TAB_WIDTH;
    config_parser_stack_create(&p->id_stack);
    p->cb_func = cb_func;
    p->cb_data = cb_data;
    return CONFIG_OK;
}

static void config_parser_destroy(config_parser_t *p)
{
    if (p->in != NULL)
    {
        free(p->in);
    }
    config_parser_stack_destroy(&p->id_stack);
    config_parser_str_destroy(&p->token_str);
    config_parser_str_destroy(&p->section);
    memset(p, 0, sizeof(config_parser_t));
}

static void config_entry_delete(config_entry_t *entry)
{
    if (entry->name != NULL)
    {
        free(entry->name);
    }
    if (entry->value != NULL)
    {
        free(entry->value);
    }
    free(entry);
}

static config_entry_t *config_entry_new(const char *entry_name, const char *entry_value)
{
    config_entry_t *entry = NULL;

    entry = (config_entry_t *)calloc(1, sizeof(config_entry_t));
    if (entry != NULL)
    {
        entry->name = strdup(entry_name);
        if (entry->name != NULL)
        {
            entry->value = strdup(entry_value);
            if (entry->value != NULL)
            {
                return entry;
            }
        }
        config_entry_delete(entry);
    }
    return NULL;
}

static void config_section_delete(config_section_t *section)
{
    config_entry_t *entry = NULL;
    config_entry_t *prev = NULL;

    if (section->name != NULL)
    {
        free(section->name);
    }
    entry = section->first;
    while (entry != NULL)
    {
        prev = entry;
        entry = entry->next;
        config_entry_delete(prev);
    }
    free(section);
}

static config_section_t *config_section_new(const char *section_name)
{
    config_section_t *section = NULL;

    section = (config_section_t *)calloc(1, sizeof(config_section_t));
    if (section != NULL)
    {
        section->name = strdup(section_name);
        if (section->name != NULL)
        {
            return section;
        }
        config_section_delete(section);
    }
    return NULL;
}

static config_entry_t *config_section_find_entry(config_section_t *section, const char *entry_name)
{
    config_entry_t *entry = section->first;

    while (entry != NULL)
    {
        if (strcmp(entry->name, entry_name) == 0)
        {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static int config_section_add_entry(config_section_t *section, const char *entry_name, const char *entry_value)
{
    config_entry_t *entry = NULL;

    entry = config_entry_new(entry_name, entry_value);
    if (entry == NULL)
    {
        return CONFIG_ENOMEM;
    }
    if (section->first == NULL)
    {
        section->first = entry;
    }
    else
    {
        section->last->next = entry;
    }
    section->last = entry;
    return CONFIG_OK;
}

void config_create(config_t *config)
{
    memset(config, 0, sizeof(config_t));
}

void config_destroy(config_t *config)
{
    config_section_t *section = config->first;
    config_section_t *prev = NULL;

    while (section != NULL)
    {
        prev = section;
        section = section->next;
        config_section_delete(prev);
    }
    memset(config, 0, sizeof(config_t));
}

static config_section_t *config_find_section(config_t *config, const char *section_name)
{
    config_section_t *section = config->first;

    while (section != NULL)
    {
        if (strcmp(section->name, section_name) == 0)
        {
            return section;
        }
        section = section->next;
    }
    return NULL;
}

static config_section_t *config_add_section(config_t *config, const char *section_name)
{
    config_section_t *section = NULL;

    section = config_section_new(section_name);
    if (section == NULL)
    {
        return NULL;
    }
    if (config->first == NULL)
    {
        config->first = section;
    }
    else
    {
        config->last->next = section;
    }
    config->last = section;
    return section;
}

int config_set(config_t *config, const char *section_name, const char *entry_name, const char *entry_value)
{
    config_section_t *section = NULL;
    config_entry_t *entry = NULL;
    int ret = 0;

    section = config_find_section(config, section_name);
    if (section == NULL)
    {
        section = config_add_section(config, section_name);
        if (section == NULL)
        {
            return CONFIG_ENOMEM;
        }
    }
    entry = config_section_find_entry(section, entry_name);
    if (entry != NULL)
    {
        /* replace existing value */
        free(entry->value);
        entry->value = strdup(entry_value);
        if (entry->value == NULL)
        {
            return CONFIG_ENOMEM;
        }
    }
    else
    {
        ret = config_section_add_entry(section, entry_name, entry_value);
        if (ret != CONFIG_OK)
        {
            return ret;
        }
    }
    return CONFIG_OK;
}

const char *config_get(config_t *config, const char *section_name, const char *entry_name)
{
    config_section_t *section = NULL;
    config_entry_t *entry = NULL;

    section = config_find_section(config, section_name);
    if (section != NULL)
    {
        entry = config_section_find_entry(section, entry_name);
        if (entry != NULL)
        {
            return entry->value;
        }
    }
    return NULL;
}

/* callback function used by the parser to set values in the config object */
static int config_cb_func(void *data, const char *section_name, const char *entry_name, const char *entry_value)
{
    return config_set((config_t *)data, section_name, entry_name, entry_value);
}

int config_parse(config_t *config, const char *str, unsigned *line, unsigned *col)
{
    config_parser_t parser = {0};
    int ret = 0;

    ret = config_parser_create(&parser, config_cb_func, config);
    if (ret == CONFIG_OK)
    {
        ret = config_parser_exec(&parser, str, line, col);
        config_parser_destroy(&parser);
    }
    return ret;
}
