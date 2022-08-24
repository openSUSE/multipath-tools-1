/*
 * Copyright (c) 2005 Christophe Varoqui
 */
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>
#include "memory.h"
#include <assert.h>
#include "vector.h"
#include "structs.h"
#include "structs_vec.h"
#include "parser.h"
#include "util.h"
#include "version.h"
#ifdef USE_LIBEDIT
#include <editline/readline.h>
#endif
#ifdef USE_LIBREADLINE
#include <readline/readline.h>
#endif

#include "mpath_cmd.h"
#include "cli.h"
#include "cli_handlers.h"
#include "debug.h"

static vector keys;
static vector handlers;

/* See KEY_INVALID in cli.h */
#define INVALID_FINGERPRINT ((uint32_t)(0))

static struct key *
alloc_key (void)
{
	return (struct key *)MALLOC(sizeof(struct key));
}

static struct handler *
alloc_handler (void)
{
	return (struct handler *)MALLOC(sizeof(struct handler));
}

static int
add_key (vector vec, char * str, uint8_t code, int has_param)
{
	struct key * kw;

	kw = alloc_key();

	if (!kw)
		return 1;

	kw->code = code;
	kw->has_param = has_param;
	kw->str = STRDUP(str);

	if (!kw->str)
		goto out;

	if (!vector_alloc_slot(vec))
		goto out1;

	vector_set_slot(vec, kw);

	return 0;

out1:
	FREE(kw->str);
out:
	FREE(kw);
	return 1;
}

static struct handler *add_handler(uint32_t fp, cli_handler *fn, bool locked)
{
	struct handler * h;

	h = alloc_handler();

	if (h == NULL)
		return NULL;

	if (!vector_alloc_slot(handlers)) {
		free(h);
		return NULL;
	}

	vector_set_slot(handlers, h);
	h->fingerprint = fp;
	h->fn = fn;
	h->locked = locked;

	return h;
}

static struct handler *
find_handler (uint32_t fp)
{
	int i;
	struct handler *h;

	if (fp == INVALID_FINGERPRINT)
		return NULL;
	vector_foreach_slot (handlers, h, i)
		if (h->fingerprint == fp)
			return h;

	return NULL;
}

int
__set_handler_callback (uint32_t fp, cli_handler *fn, bool locked)
{
	struct handler *h;

	assert(fp != INVALID_FINGERPRINT);
	assert(find_handler(fp) == NULL);
	h = add_handler(fp, fn, locked);
	if (!h) {
		condlog(0, "%s: failed to set handler for code %"PRIu32,
			__func__, fp);
		return 1;
	}
	return 0;
}

static void
free_key (struct key * kw)
{
	if (kw->str)
		FREE(kw->str);

	if (kw->param)
		FREE(kw->param);

	FREE(kw);
}

void
free_keys (vector vec)
{
	int i;
	struct key * kw;

	vector_foreach_slot (vec, kw, i)
		free_key(kw);

	vector_free(vec);
}

void
free_handlers (void)
{
	int i;
	struct handler * h;

	vector_foreach_slot (handlers, h, i)
		FREE(h);

	vector_free(handlers);
	handlers = NULL;
}

int
load_keys (void)
{
	int r = 0;
	keys = vector_alloc();

	if (!keys)
		return 1;

	r += add_key(keys, "list", VRB_LIST, 0);
	r += add_key(keys, "show", VRB_LIST, 0);
	r += add_key(keys, "add", VRB_ADD, 0);
	r += add_key(keys, "remove", VRB_DEL, 0);
	r += add_key(keys, "del", VRB_DEL, 0);
	r += add_key(keys, "switch", VRB_SWITCH, 0);
	r += add_key(keys, "switchgroup", VRB_SWITCH, 0);
	r += add_key(keys, "suspend", VRB_SUSPEND, 0);
	r += add_key(keys, "resume", VRB_RESUME, 0);
	r += add_key(keys, "reinstate", VRB_REINSTATE, 0);
	r += add_key(keys, "fail", VRB_FAIL, 0);
	r += add_key(keys, "resize", VRB_RESIZE, 0);
	r += add_key(keys, "reset", VRB_RESET, 0);
	r += add_key(keys, "reload", VRB_RELOAD, 0);
	r += add_key(keys, "forcequeueing", VRB_FORCEQ, 0);
	r += add_key(keys, "disablequeueing", VRB_DISABLEQ, 0);
	r += add_key(keys, "restorequeueing", VRB_RESTOREQ, 0);
	r += add_key(keys, "paths", KEY_PATHS, 0);
	r += add_key(keys, "maps", KEY_MAPS, 0);
	r += add_key(keys, "multipaths", KEY_MAPS, 0);
	r += add_key(keys, "path", KEY_PATH, 1);
	r += add_key(keys, "map", KEY_MAP, 1);
	r += add_key(keys, "multipath", KEY_MAP, 1);
	r += add_key(keys, "group", KEY_GROUP, 1);
	r += add_key(keys, "reconfigure", VRB_RECONFIGURE, 0);
	r += add_key(keys, "daemon", KEY_DAEMON, 0);
	r += add_key(keys, "status", KEY_STATUS, 0);
	r += add_key(keys, "stats", KEY_STATS, 0);
	r += add_key(keys, "topology", KEY_TOPOLOGY, 0);
	r += add_key(keys, "config", KEY_CONFIG, 0);
	r += add_key(keys, "blacklist", KEY_BLACKLIST, 0);
	r += add_key(keys, "devices", KEY_DEVICES, 0);
	r += add_key(keys, "raw", KEY_RAW, 0);
	r += add_key(keys, "wildcards", KEY_WILDCARDS, 0);
	r += add_key(keys, "quit", VRB_QUIT, 0);
	r += add_key(keys, "exit", VRB_QUIT, 0);
	r += add_key(keys, "shutdown", VRB_SHUTDOWN, 0);
	r += add_key(keys, "getprstatus", VRB_GETPRSTATUS, 0);
	r += add_key(keys, "setprstatus", VRB_SETPRSTATUS, 0);
	r += add_key(keys, "unsetprstatus", VRB_UNSETPRSTATUS, 0);
	r += add_key(keys, "format", KEY_FMT, 1);
	r += add_key(keys, "json", KEY_JSON, 0);
	r += add_key(keys, "getprkey", VRB_GETPRKEY, 0);
	r += add_key(keys, "setprkey", VRB_SETPRKEY, 0);
	r += add_key(keys, "unsetprkey", VRB_UNSETPRKEY, 0);
	r += add_key(keys, "key", KEY_KEY, 1);
	r += add_key(keys, "local", KEY_LOCAL, 0);
	r += add_key(keys, "setmarginal", VRB_SETMARGINAL, 0);
	r += add_key(keys, "unsetmarginal", VRB_UNSETMARGINAL, 0);


	if (r) {
		free_keys(keys);
		keys = NULL;
		return 1;
	}
	return 0;
}

static struct key *
find_key (const char * str)
{
	int i;
	int len, klen;
	struct key * kw = NULL;
	struct key * foundkw = NULL;

	len = strlen(str);

	vector_foreach_slot (keys, kw, i) {
		if (strncmp(kw->str, str, len))
			continue;
		klen = strlen(kw->str);
		if (len == klen)
			return kw; /* exact match */
		if (len < klen) {
			if (!foundkw)
				foundkw = kw; /* shortcut match */
			else
				return NULL; /* ambiguous word */
		}
	}
	return foundkw;
}

/*
 * get_cmdvec
 *
 * returns:
 * ENOMEM: not enough memory to allocate command
 * ESRCH: command not found
 * EINVAL: argument missing for command
 */
int get_cmdvec (char *cmd, vector *v)
{
	int i;
	int r = 0;
	int get_param = 0;
	char * buff;
	struct key * kw = NULL;
	struct key * cmdkw = NULL;
	vector cmdvec, strvec;

	strvec = alloc_strvec(cmd);
	if (!strvec)
		return ENOMEM;

	cmdvec = vector_alloc();

	if (!cmdvec) {
		free_strvec(strvec);
		return ENOMEM;
	}

	vector_foreach_slot(strvec, buff, i) {
		if (is_quote(buff))
			continue;
		if (get_param) {
			get_param = 0;
			cmdkw->param = strdup(buff);
			continue;
		}
		kw = find_key(buff);
		if (!kw) {
			r = ESRCH;
			goto out;
		}
		cmdkw = alloc_key();
		if (!cmdkw) {
			r = ENOMEM;
			goto out;
		}
		if (!vector_alloc_slot(cmdvec)) {
			FREE(cmdkw);
			r = ENOMEM;
			goto out;
		}
		vector_set_slot(cmdvec, cmdkw);
		cmdkw->code = kw->code;
		cmdkw->has_param = kw->has_param;
		if (kw->has_param)
			get_param = 1;
	}
	if (get_param) {
		r = EINVAL;
		goto out;
	}
	*v = cmdvec;
	free_strvec(strvec);
	return 0;

out:
	free_strvec(strvec);
	free_keys(cmdvec);
	return r;
}

uint32_t fingerprint(const struct _vector *vec)
{
	int i;
	uint32_t fp = 0;
	struct key * kw;

	if (!vec || VECTOR_SIZE(vec) > 4)
		return INVALID_FINGERPRINT;

	vector_foreach_slot(vec, kw, i) {
		if (i >= 4)
			break;
		fp |= (uint32_t)kw->code << (8 * i);
	}
	return fp;
}

struct handler *find_handler_for_cmdvec(const struct _vector *v)
{
	return find_handler(fingerprint(v));
}

int
alloc_handlers (void)
{
	handlers = vector_alloc();

	if (!handlers)
		return 1;

	return 0;
}

static int
genhelp_sprint_aliases (char * reply, int maxlen, vector keys,
			struct key * refkw)
{
	int i, len = 0;
	struct key * kw;

	vector_foreach_slot (keys, kw, i) {
		if (kw->code == refkw->code && kw != refkw) {
			len += snprintf(reply + len, maxlen - len,
					"|%s", kw->str);
			if (len >= maxlen)
				return len;
		}
	}

	return len;
}

static int
do_genhelp(char *reply, int maxlen, const char *cmd, int error) {
	int len = 0;
	int i, j, k;
	uint32_t fp;
	struct handler * h;
	struct key * kw;

	switch(error) {
	case ENOMEM:
		len += snprintf(reply + len, maxlen - len,
				"%s: Not enough memory\n", cmd);
		break;
	case ESRCH:
		len += snprintf(reply + len, maxlen - len,
				"%s: not found\n", cmd);
		break;
	case EINVAL:
		len += snprintf(reply + len, maxlen - len,
				"%s: Missing argument\n", cmd);
		break;
	}
	if (len >= maxlen)
		goto out;
	len += snprintf(reply + len, maxlen - len, VERSION_STRING);
	if (len >= maxlen)
		goto out;
	len += snprintf(reply + len, maxlen - len, "CLI commands reference:\n");
	if (len >= maxlen)
		goto out;

	vector_foreach_slot (handlers, h, i) {
		fp = h->fingerprint;
		for (k = 0; k < 4; k++, fp >>= 8) {
			uint32_t code = fp & 0xff;

			if (!code)
				break;

			vector_foreach_slot (keys, kw, j) {
				if ((uint32_t)kw->code == code) {
					len += snprintf(reply + len , maxlen - len,
							" %s", kw->str);
					if (len >= maxlen)
						goto out;
					len += genhelp_sprint_aliases(reply + len,
								      maxlen - len,
								      keys, kw);
					if (len >= maxlen)
						goto out;
					if (kw->has_param) {
						len += snprintf(reply + len,
								maxlen - len,
								" $%s", kw->str);
						if (len >= maxlen)
							goto out;

					}
				}
			}
		}
		len += snprintf(reply + len, maxlen - len, "\n");
		if (len >= maxlen)
			goto out;
	}
out:
	return len;
}


char *genhelp_handler(const char *cmd, int error)
{
	char * reply;
	char * p = NULL;
	int maxlen = INITIAL_REPLY_LEN;
	int again = 1;

	reply = MALLOC(maxlen);

	while (again) {
		if (!reply)
			return NULL;
		p = reply;
		p += do_genhelp(reply, maxlen, cmd, error);
		again = ((p - reply) >= maxlen);
		REALLOC_REPLY(reply, again, maxlen);
	}
	return reply;
}

char *
get_keyparam (vector v, uint8_t code)
{
	struct key * kw;
	int i;

	vector_foreach_slot(v, kw, i)
		if (kw->code == code)
			return kw->param;

	return NULL;
}

int
cli_init (void) {
	if (load_keys())
		return 1;

	if (alloc_handlers())
		return 1;

	init_handler_callbacks();
	return 0;
}

void cli_exit(void)
{
	free_handlers();
	free_keys(keys);
	keys = NULL;
}

#if defined(USE_LIBREADLINE) || defined(USE_LIBEDIT)
static int
key_match_fingerprint (struct key * kw, uint64_t fp)
{
	if (!fp)
		return 0;

	return ((fp & kw->code) == kw->code);
}

/*
 * This is the readline completion handler
 */
char *
key_generator (const char * str, int state)
{
	static int index, len, has_param;
	static uint64_t rlfp;
	struct key * kw;
	int i;
	struct handler *h;
	vector v = NULL;

	if (!state) {
		index = 0;
		has_param = 0;
		rlfp = 0;
		len = strlen(str);
		int r = get_cmdvec(rl_line_buffer, &v);
		/*
		 * If a word completion is in progress, we don't want
		 * to take an exact keyword match in the fingerprint.
		 * For ex "show map[tab]" would validate "map" and discard
		 * "maps" as a valid candidate.
		 */
		if (v && len)
			vector_del_slot(v, VECTOR_SIZE(v) - 1);
		/*
		 * Clean up the mess if we dropped the last slot of a 1-slot
		 * vector
		 */
		if (v && !VECTOR_SIZE(v)) {
			vector_free(v);
			v = NULL;
		}
		/*
		 * If last keyword takes a param, don't even try to guess
		 */
		if (r == EINVAL) {
			has_param = 1;
			return (strdup("(value)"));
		}
		/*
		 * Compute a command fingerprint to find out possible completions.
		 * Once done, the vector is useless. Free it.
		 */
		if (v) {
			rlfp = fingerprint(v);
			free_keys(v);
		}
	}
	/*
	 * No more completions for parameter placeholder.
	 * Brave souls might try to add parameter completion by walking paths and
	 * multipaths vectors.
	 */
	if (has_param)
		return ((char *)NULL);
	/*
	 * Loop through keywords for completion candidates
	 */
	vector_foreach_slot_after (keys, kw, index) {
		if (!strncmp(kw->str, str, len)) {
			/*
			 * Discard keywords already in the command line
			 */
			if (key_match_fingerprint(kw, rlfp)) {
				struct key * curkw = find_key(str);
				if (!curkw || (curkw != kw))
					continue;
			}
			/*
			 * Discard keywords making syntax errors.
			 *
			 * nfp is the candidate fingerprint we try to
			 * validate against all known command fingerprints.
			 */
			uint64_t nfp = rlfp | kw->code;
			vector_foreach_slot(handlers, h, i) {
				if (!rlfp || ((h->fingerprint & nfp) == nfp)) {
					/*
					 * At least one full command is
					 * possible with this keyword :
					 * Consider it validated
					 */
					index++;
					return (strdup(kw->str));
				}
			}
		}
	}
	/*
	 * No more candidates
	 */
	return ((char *)NULL);
}
#endif
