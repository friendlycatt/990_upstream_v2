// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * resolve_btfids scans an Elf object for a .BTF_ids section and resolves
 * its symbols with BTF ID values.
 *
 * Each symbol points to 4 bytes data and is expected to have
 * following name syntax:
 *
 * __BTF_ID__<type>__<symbol>[__<id>]
 *
 * type is:
 *
 *   func    - lookup BTF_KIND_FUNC symbol with <symbol> name
 *             and store its ID into the data:
 *
 *             __BTF_ID__func__vfs_close__1:
 *             .zero 4
 *
 *   struct  - lookup BTF_KIND_STRUCT symbol with <symbol> name
 *             and store its ID into the data:
 *
 *             __BTF_ID__struct__sk_buff__1:
 *             .zero 4
 *
 *   union   - lookup BTF_KIND_UNION symbol with <symbol> name
 *             and store its ID into the data:
 *
 *             __BTF_ID__union__thread_union__1:
 *             .zero 4
 *
 *   typedef - lookup BTF_KIND_TYPEDEF symbol with <symbol> name
 *             and store its ID into the data:
 *
 *             __BTF_ID__typedef__pid_t__1:
 *             .zero 4
 *
 *   set     - store symbol size into first 4 bytes and sort following
 *             ID list
 *
 *             __BTF_ID__set__list:
 *             .zero 4
 *             list:
 *             __BTF_ID__func__vfs_getattr__3:
 *             .zero 4
 *             __BTF_ID__func__vfs_fallocate__4:
 *             .zero 4
 *
 * This is a self-contained rework of the v5.10
 * tools/bpf/resolve_btfids/main.c.  The raw BTF blob is parsed here
 * directly instead of going through libbpf: the in-tree libbpf of this
 * kernel predates btf__parse()/btf__get_nr_types(), and btf__new()
 * immediately performs a BPF syscall to load the blob, which cannot be
 * done on the build host.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/btf.h>

#define BTF_IDS_SECTION	".BTF_ids"
#define BTF_ELF_SEC	".BTF"
#define BTF_ID		"__BTF_ID__"

#define BTF_STRUCT	"struct"
#define BTF_UNION	"union"
#define BTF_TYPEDEF	"typedef"
#define BTF_FUNC	"func"
#define BTF_SET		"set"

#define ADDR_CNT	100

struct btf_id {
	u32		 kind;		/* BTF_KIND_* the name refers to */
	char		*name;
	u32		 id;		/* resolved BTF type ID */
	u32		 cnt;		/* set member count (sets only) */
	int		 addr_cnt;
	Elf64_Addr	 addr[ADDR_CNT];
};

struct object {
	const char	*path;
	const char	*btf_path;

	struct {
		int		 fd;
		Elf		*elf;
		Elf_Data	*symbols;
		Elf_Data	*idlist;
		Elf_Data	*btf;
		int		 symbols_shndx;
		int		 idlist_shndx;
		size_t		 strtabidx;
		Elf64_Addr	 idlist_addr;
	} efile;

	struct btf_id	*ids;
	size_t		 nr_ids;
	struct btf_id	*sets;
	size_t		 nr_sets;
};

struct btf_parse {
	void			*data;		/* owned raw BTF data */
	const struct btf_type	**types;	/* indexed by type ID */
	__u32			 nr_types;
	const char		*strings;
	__u32			 str_len;
};

static int verbose;

static int eprintf(int level, const char *fmt, ...)
{
	va_list args;
	int ret = 0;

	if (verbose >= level) {
		va_start(args, fmt);
		ret = vfprintf(stderr, fmt, args);
		va_end(args);
	}
	return ret;
}

#define pr_debug(fmt, ...)	eprintf(1, fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	eprintf(0, fmt, ##__VA_ARGS__)

static bool is_btf_id(const char *name)
{
	return name && !strncmp(name, BTF_ID, sizeof(BTF_ID) - 1);
}

/*
 * __BTF_ID__func__vfs_truncate__0
 * prefix_end =  ^
 * pos        =    ^
 *
 * Skip the "__" separator and cut the unique __<id> suffix appended by
 * __ID() in include/linux/btf_ids.h, returning the bare symbol name.
 */
static char *get_id(const char *prefix_end)
{
	size_t len = strlen(prefix_end);
	size_t pos = sizeof("__") - 1;
	char *p, *id, *suffix;

	if (pos >= len || strncmp(prefix_end, "__", pos))
		return NULL;

	id = strdup(prefix_end + pos);
	if (!id)
		return NULL;

	p = strrchr(id, '_');
	if (!p || p == id) {
		free(id);
		return NULL;
	}
	p--;
	if (*p != '_') {
		free(id);
		return NULL;
	}
	for (suffix = p + 2; *suffix; suffix++) {
		if (*suffix < '0' || *suffix > '9') {
			free(id);
			return NULL;
		}
	}
	if (!p[2] || p == id) {
		free(id);
		return NULL;
	}
	*p = '\0';

	return id;
}

static int ids_append(struct btf_id **arr, size_t *nr, u32 kind, char *name,
		      Elf64_Addr addr)
{
	struct btf_id *tmp;

	tmp = realloc(*arr, (*nr + 1) * sizeof(**arr));
	if (!tmp)
		return -1;
	*arr = tmp;
	memset(&tmp[*nr], 0, sizeof(tmp[*nr]));
	tmp[*nr].kind = kind;
	tmp[*nr].name = name;
	tmp[*nr].addr[0] = addr;
	tmp[*nr].addr_cnt = 1;
	(*nr)++;

	return 0;
}

static int cmp_btf_id(const void *pa, const void *pb)
{
	const struct btf_id *a = pa, *b = pb;

	if (a->kind != b->kind)
		return a->kind < b->kind ? -1 : 1;
	return strcmp(a->name, b->name);
}

static int cmp_u32(const void *pa, const void *pb)
{
	const u32 *a = pa, *b = pb;

	return (*a > *b) - (*a < *b);
}

/* Sort collected IDs by kind+name and merge entries that share both. */
static int ids_sort_merge(struct object *obj)
{
	struct btf_id *out;
	size_t i, m = 0;

	if (!obj->nr_ids)
		return 0;

	qsort(obj->ids, obj->nr_ids, sizeof(*obj->ids), cmp_btf_id);

	out = calloc(obj->nr_ids, sizeof(*out));
	if (!out)
		return -1;

	for (i = 0; i < obj->nr_ids; i++) {
		if (m && out[m - 1].kind == obj->ids[i].kind &&
		    !strcmp(out[m - 1].name, obj->ids[i].name)) {
			struct btf_id *dst = &out[m - 1];
			struct btf_id *src = &obj->ids[i];

			if (dst->addr_cnt + src->addr_cnt > ADDR_CNT) {
				pr_err("FAILED symbol %s crossed the number of allowed lists\n",
				       dst->name);
				goto err;
			}
			memcpy(&dst->addr[dst->addr_cnt], src->addr,
			       src->addr_cnt * sizeof(src->addr[0]));
			dst->addr_cnt += src->addr_cnt;
			free(src->name);
			src->name = NULL;
			continue;
		}
		out[m++] = obj->ids[i];
	}

	free(obj->ids);
	obj->ids = out;
	obj->nr_ids = m;

	return 0;
err:
	/* Names remain owned by obj->ids until the merge succeeds. */
	free(out);
	return -1;
}

static struct btf_id *ids_find(struct object *obj, u32 kind, const char *name)
{
	struct btf_id key = { .kind = kind, .name = (char *)name };

	if (!obj->nr_ids)
		return NULL;

	return bsearch(&key, obj->ids, obj->nr_ids, sizeof(*obj->ids),
		       cmp_btf_id);
}

static int elf_collect(struct object *obj)
{
	size_t shdrstrndx;
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	int idx = 0;
	Elf *elf;
	int fd;

	fd = open(obj->path, O_RDWR, 0666);
	if (fd == -1) {
		pr_err("FAILED cannot open %s: %s\n",
		       obj->path, strerror(errno));
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_err("FAILED libelf initialization\n");
		close(fd);
		return -1;
	}

	elf = elf_begin(fd, ELF_C_RDWR_MMAP, NULL);
	if (!elf) {
		pr_err("FAILED cannot create ELF descriptor: %s\n",
		       elf_errmsg(-1));
		close(fd);
		return -1;
	}

	obj->efile.fd = fd;
	obj->efile.elf = elf;
	if (!gelf_getehdr(elf, &ehdr)) {
		pr_err("FAILED cannot read ELF header\n");
		return -1;
	}

	/* Raw BTF and .BTF_ids use the target's byte order. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
#else
	if (ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
#endif
		pr_err("FAILED ELF byte order differs from the build host\n");
		return -1;
	}

	/*
	 * Keep libelf from rearranging the file layout when writing the
	 * patched section back out.
	 */
	elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT);

	if (elf_getshdrstrndx(elf, &shdrstrndx) != 0) {
		pr_err("FAILED cannot get shdr str ndx\n");
		return -1;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data;
		GElf_Shdr sh;
		char *name;

		idx = elf_ndxscn(scn);
		if (gelf_getshdr(scn, &sh) != &sh) {
			pr_err("FAILED get section(%d) header\n", idx);
			return -1;
		}

		name = elf_strptr(elf, shdrstrndx, sh.sh_name);
		if (!name) {
			pr_err("FAILED get section(%d) name\n", idx);
			return -1;
		}

		data = elf_getdata(scn, 0);
		if (!data) {
			pr_err("FAILED to get section(%d) data from %s\n",
			       idx, name);
			return -1;
		}

		pr_debug("section(%d) %s, size %ld, link %d, flags %lx, type=%d\n",
			 idx, name, (unsigned long)data->d_size,
			 (int)sh.sh_link, (unsigned long)sh.sh_flags,
			 (int)sh.sh_type);

		if (sh.sh_type == SHT_SYMTAB) {
			obj->efile.symbols = data;
			obj->efile.symbols_shndx = idx;
			obj->efile.strtabidx = sh.sh_link;
		} else if (!strcmp(name, BTF_IDS_SECTION)) {
			obj->efile.idlist = data;
			obj->efile.idlist_shndx = idx;
			obj->efile.idlist_addr = sh.sh_addr;
		} else if (!strcmp(name, BTF_ELF_SEC)) {
			obj->efile.btf = data;
		}
	}

	return 0;
}

static int symbols_collect(struct object *obj)
{
	Elf_Scn *scn;
	GElf_Shdr sh;
	char *name;
	int n, i;

	scn = elf_getscn(obj->efile.elf, obj->efile.symbols_shndx);
	if (!scn)
		return -1;
	if (gelf_getshdr(scn, &sh) != &sh)
		return -1;
	if (!sh.sh_entsize || sh.sh_size % sh.sh_entsize ||
	    sh.sh_size / sh.sh_entsize > INT_MAX) {
		pr_err("FAILED malformed symbol table\n");
		return -1;
	}
	if (!obj->efile.idlist->d_buf ||
	    obj->efile.idlist->d_size % sizeof(u32)) {
		pr_err("FAILED malformed %s section\n", BTF_IDS_SECTION);
		return -1;
	}

	n = sh.sh_size / sh.sh_entsize;

	/*
	 * Scan symbols and look for the ones starting with
	 * __BTF_ID__* over .BTF_ids section.
	 */
	for (i = 0; i < n; i++) {
		char *prefix, *id;
		u32 kind;
		GElf_Sym sym;

		if (!gelf_getsym(obj->efile.symbols, i, &sym))
			return -1;

		if (sym.st_shndx != obj->efile.idlist_shndx)
			continue;

		name = elf_strptr(obj->efile.elf, obj->efile.strtabidx,
				  sym.st_name);
		if (!is_btf_id(name))
			continue;

		/*
		 * __BTF_ID__TYPE__vfs_truncate__0
		 * prefix =  ^
		 */
		prefix = name + sizeof(BTF_ID) - 1;

		if (!strncmp(prefix, BTF_SET "__", sizeof(BTF_SET "__") - 1)) {
			/*
			 * __BTF_ID__set__name
			 * id =    ^
			 */
			id = strdup(prefix + sizeof(BTF_SET "__") - 1);
			if (!id || !*id) {
				pr_err("FAILED to parse set name: %s\n",
				       prefix);
				free(id);
				return -1;
			}
			if (ids_append(&obj->sets, &obj->nr_sets, 0, id,
				       sym.st_value)) {
				free(id);
				return -1;
			}
			/*
			 * SET objects store list's count, which is encoded
			 * in symbol's size, together with 'cnt' field hence
			 * that - 1.
			 */
			if (sym.st_size < sizeof(u32) ||
			    sym.st_size % sizeof(u32) ||
			    sym.st_size / sizeof(u32) - 1 > UINT_MAX) {
				pr_err("FAILED malformed set symbol %s\n",
				       name);
				return -1;
			}
			obj->sets[obj->nr_sets - 1].cnt =
				sym.st_size / sizeof(u32) - 1;
			continue;
		}

		if (!strncmp(prefix, BTF_STRUCT, sizeof(BTF_STRUCT) - 1)) {
			kind = BTF_KIND_STRUCT;
			prefix += sizeof(BTF_STRUCT) - 1;
		} else if (!strncmp(prefix, BTF_UNION, sizeof(BTF_UNION) - 1)) {
			kind = BTF_KIND_UNION;
			prefix += sizeof(BTF_UNION) - 1;
		} else if (!strncmp(prefix, BTF_TYPEDEF, sizeof(BTF_TYPEDEF) - 1)) {
			kind = BTF_KIND_TYPEDEF;
			prefix += sizeof(BTF_TYPEDEF) - 1;
		} else if (!strncmp(prefix, BTF_FUNC, sizeof(BTF_FUNC) - 1)) {
			kind = BTF_KIND_FUNC;
			prefix += sizeof(BTF_FUNC) - 1;
		} else {
			pr_err("FAILED unsupported prefix %s\n", prefix);
			return -1;
		}

		id = get_id(prefix);
		if (!id) {
			pr_err("FAILED to parse symbol name: %s\n", name);
			return -1;
		}
		if (sym.st_size != sizeof(u32)) {
			pr_err("FAILED malformed ID symbol %s\n", name);
			free(id);
			return -1;
		}

		if (ids_append(&obj->ids, &obj->nr_ids, kind, id,
			       sym.st_value)) {
			free(id);
			return -1;
		}
	}

	return ids_sort_merge(obj);
}

/*
 * Parse the raw BTF blob into an array of type pointers indexed by
 * type ID (type 0 is the void type and never appears in the type
 * section).
 */
static int btf_parse(const void *data, size_t size, struct btf_parse *btf)
{
	const struct btf_header *hdr = data;
	const u8 *types;
	size_t off = 0;
	__u32 id = 1;

	if (size < sizeof(*hdr) || hdr->magic != BTF_MAGIC ||
	    hdr->version != BTF_VERSION || hdr->flags ||
	    hdr->hdr_len < sizeof(*hdr)) {
		pr_err("FAILED invalid BTF header\n");
		return -1;
	}
	if (hdr->hdr_len > size ||
	    hdr->type_off > size - hdr->hdr_len ||
	    hdr->type_len > size - hdr->hdr_len - hdr->type_off ||
	    hdr->str_off > size - hdr->hdr_len ||
	    hdr->str_len > size - hdr->hdr_len - hdr->str_off ||
	    (hdr->hdr_len + (size_t)hdr->type_off) % sizeof(u32) ||
	    hdr->type_len % sizeof(u32) ||
	    (size_t)hdr->type_off + hdr->type_len > hdr->str_off) {
		pr_err("FAILED BTF sections out of bounds\n");
		return -1;
	}

	btf->strings = (const char *)data + hdr->hdr_len + hdr->str_off;
	btf->str_len = hdr->str_len;
	if (!btf->str_len || btf->strings[0] ||
	    btf->strings[btf->str_len - 1]) {
		pr_err("FAILED malformed BTF string section\n");
		return -1;
	}

	types = (const u8 *)data + hdr->hdr_len + hdr->type_off;

	/* Upper bound: every type takes at least sizeof(struct btf_type). */
	btf->types = calloc(hdr->type_len / sizeof(struct btf_type) + 2,
			    sizeof(*btf->types));
	if (!btf->types)
		return -1;

	while (off < hdr->type_len) {
		const struct btf_type *type;
		u32 kind, vlen;
		size_t esz = sizeof(*type);

		if (esz > hdr->type_len - off) {
			pr_err("FAILED truncated BTF type %u\n", id);
			return -1;
		}
		type = (const void *)(types + off);
		/* Do not let the old header's 4-bit kind mask hide newer kinds. */
		kind = (type->info >> 24) & 0x7f;
		vlen = BTF_INFO_VLEN(type->info);
		if (kind > BTF_KIND_MAX || type->info & 0x00ff0000) {
			pr_err("FAILED unsupported BTF kind/info %u (see scripts/pahole-flags.sh)\n",
			       kind);
			return -1;
		}
		if (BTF_INFO_KFLAG(type->info) && kind != BTF_KIND_STRUCT &&
		    kind != BTF_KIND_UNION && kind != BTF_KIND_FWD) {
			pr_err("FAILED unsupported kind_flag for BTF kind %u\n", kind);
			return -1;
		}
		if (type->name_off >= btf->str_len) {
			pr_err("FAILED invalid name offset for BTF type %u\n", id);
			return -1;
		}

		switch (kind) {
		case BTF_KIND_INT:
			esz += sizeof(__u32);
			break;
		case BTF_KIND_ARRAY:
			esz += sizeof(struct btf_array);
			break;
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			esz += vlen * sizeof(struct btf_member);
			break;
		case BTF_KIND_ENUM:
			esz += vlen * sizeof(struct btf_enum);
			break;
		case BTF_KIND_FUNC_PROTO:
			esz += vlen * sizeof(struct btf_param);
			break;
		case BTF_KIND_VAR:
			esz += sizeof(struct btf_var);
			break;
		case BTF_KIND_DATASEC:
			esz += vlen * sizeof(struct btf_var_secinfo);
			break;
		case BTF_KIND_PTR:
		case BTF_KIND_FWD:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC:
			break;
		default:
			pr_err("FAILED unsupported BTF kind %u (generated by a too-recent pahole? see scripts/pahole-flags.sh)\n",
			       kind);
			return -1;
		}

		if (esz > hdr->type_len - off) {
			pr_err("FAILED truncated BTF type %u\n", id);
			return -1;
		}

		btf->types[id++] = type;
		off += esz;
	}

	btf->nr_types = id - 1;
	pr_debug("parsed %u BTF types\n", btf->nr_types);

	return 0;
}

static int btf_load(struct object *obj, struct btf_parse *btf)
{
	void *data = NULL;
	size_t size;

	if (obj->btf_path) {
		int fd = open(obj->btf_path, O_RDONLY);
		off_t end;
		size_t offset = 0;
		ssize_t rd;

		if (fd == -1) {
			pr_err("FAILED cannot open %s: %s\n",
			       obj->btf_path, strerror(errno));
			return -1;
		}
		end = lseek(fd, 0, SEEK_END);
		if (end < 0 || (unsigned long long)end > SSIZE_MAX ||
		    lseek(fd, 0, SEEK_SET) != 0) {
			pr_err("FAILED cannot determine size of %s\n", obj->btf_path);
			close(fd);
			return -1;
		}
		size = end;
		data = malloc(size ? size : 1);
		if (!data) {
			close(fd);
			return -1;
		}
		while (offset < size) {
			rd = read(fd, (char *)data + offset, size - offset);
			if (rd < 0 && errno == EINTR)
				continue;
			if (rd <= 0) {
				pr_err("FAILED cannot read %s\n", obj->btf_path);
				close(fd);
				free(data);
				return -1;
			}
			offset += rd;
		}
		close(fd);
	} else {
		if (!obj->efile.btf || !obj->efile.btf->d_buf) {
			pr_err("FAILED to find %s section\n", BTF_ELF_SEC);
			return -1;
		}
		size = obj->efile.btf->d_size;
		data = malloc(size ? size : 1);
		if (!data)
			return -1;
		memcpy(data, obj->efile.btf->d_buf, size);
	}

	/* Keep type/string pointers valid until resolution has finished. */
	btf->data = data;
	return btf_parse(data, size, btf);
}

static const char *btf_name_by_off(const struct btf_parse *btf, __u32 off)
{
	if (off < btf->str_len)
		return &btf->strings[off];
	return NULL;
}

static int symbols_resolve(struct object *obj, struct btf_parse *btf)
{
	__u32 type_id;
	size_t i;
	int found = 0;

	for (type_id = 1; type_id <= btf->nr_types; type_id++) {
		const struct btf_type *type = btf->types[type_id];
		struct btf_id *id;
		const char *str;
		u32 kind = BTF_INFO_KIND(type->info);

		if (kind != BTF_KIND_FUNC && kind != BTF_KIND_STRUCT &&
		    kind != BTF_KIND_UNION && kind != BTF_KIND_TYPEDEF)
			continue;

		str = btf_name_by_off(btf, type->name_off);
		if (!str) {
			pr_err("FAILED: malformed BTF, can't resolve name for ID %u\n",
			       type_id);
			return -1;
		}
		if (!*str)
			continue;

		id = ids_find(obj, kind, str);
		if (id && !id->id) {
			id->id = type_id;
			found++;
		}
	}

	pr_debug("resolved %d of %zu BTF IDs\n", found, obj->nr_ids);

	for (i = 0; i < obj->nr_ids; i++) {
		if (!obj->ids[i].id) {
			pr_err("FAILED unresolved symbol %s\n",
			       obj->ids[i].name);
			return -1;
		}
	}

	return 0;
}

static int id_patch(struct object *obj, struct btf_id *id, u32 *ptr)
{
	Elf_Data *data = obj->efile.idlist;
	int i;

	for (i = 0; i < id->addr_cnt; i++) {
		Elf64_Addr addr = id->addr[i];
		Elf64_Addr idx = addr - obj->efile.idlist_addr;

		pr_debug("patching addr %5llu: ID %7u [%s]\n",
			 (unsigned long long)idx, id->id, id->name);

		if (addr < obj->efile.idlist_addr || idx > data->d_size ||
		    sizeof(u32) > data->d_size - idx || idx % sizeof(u32)) {
			pr_err("FAILED patching index %llu out of bounds %zu\n",
			       (unsigned long long)idx, data->d_size);
			return -1;
		}

		ptr[idx / sizeof(u32)] = id->id;
	}

	return 0;
}

static int symbols_patch(struct object *obj)
{
	Elf_Data *data = obj->efile.idlist;
	u32 *ptr;
	size_t i;
	int err = -1;

	/* Validate and patch an aligned copy before changing the ELF data. */
	ptr = malloc(data->d_size ? data->d_size : 1);
	if (!ptr)
		return -1;
	memcpy(ptr, data->d_buf, data->d_size);

	for (i = 0; i < obj->nr_ids; i++) {
		if (id_patch(obj, &obj->ids[i], ptr))
			goto out;
	}

	for (i = 0; i < obj->nr_sets; i++) {
		struct btf_id *id = &obj->sets[i];
		Elf64_Addr addr = id->addr[0];
		Elf64_Addr idx = addr - obj->efile.idlist_addr;
		u32 *base;

		/* sets are unique */
		if (id->addr_cnt != 1) {
			pr_err("FAILED malformed data for set '%s'\n",
			       id->name);
			goto out;
		}
		if (addr < obj->efile.idlist_addr || idx > data->d_size ||
		    idx % sizeof(u32) ||
		    ((Elf64_Addr)id->cnt + 1) * sizeof(u32) >
		    data->d_size - idx) {
			pr_err("FAILED patching set '%s' index %llu out of bounds %zu\n",
			       id->name, (unsigned long long)idx, data->d_size);
			goto out;
		}

		base = &ptr[idx / sizeof(u32)];
		base[0] = id->cnt;
		pr_debug("sorting  addr %5llu: cnt %6u [%s]\n",
			 (unsigned long long)idx, id->cnt, id->name);
		qsort(base + 1, id->cnt, sizeof(u32), cmp_u32);
	}

	memcpy(data->d_buf, ptr, data->d_size);
	elf_flagdata(obj->efile.idlist, ELF_C_SET, ELF_F_DIRTY);

	if (elf_update(obj->efile.elf, ELF_C_WRITE) < 0) {
		pr_err("FAILED elf_update(WRITE): %s\n", elf_errmsg(-1));
		goto out;
	}

	pr_debug("update %s: ok\n", obj->path);
	err = 0;
out:
	free(ptr);
	return err;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [<options>] <ELF object>\n"
		"  -v, --verbose    be more verbose\n"
		"      --btf <file> read raw BTF from <file> instead of the ELF object\n"
		"      --no-fail    do not fail if %s section is not found\n",
		prog, BTF_IDS_SECTION);
}

int main(int argc, char **argv)
{
	struct btf_parse btf = { 0 };
	bool no_fail = false;
	struct object obj = {
		.efile = {
			.fd = -1,
			.idlist_shndx = -1,
			.symbols_shndx = -1,
		},
	};
	int i, err = -1;

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
			verbose++;
		} else if (!strcmp(arg, "--no-fail")) {
			no_fail = true;
		} else if (!strcmp(arg, "--btf")) {
			if (++i >= argc) {
				usage(argv[0]);
				return -1;
			}
			obj.btf_path = argv[i];
		} else if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
			usage(argv[0]);
			return 0;
		} else if (arg[0] == '-') {
			usage(argv[0]);
			return -1;
		} else if (obj.path) {
			usage(argv[0]);
			return -1;
		} else {
			obj.path = arg;
		}
	}

	if (!obj.path) {
		usage(argv[0]);
		return -1;
	}

	if (elf_collect(&obj))
		goto out;

	/* --no-fail applies only when there is no ID section to resolve. */
	if (obj.efile.idlist_shndx == -1) {
		if (no_fail) {
			err = 0;
			goto out;
		}
		pr_err("FAILED to find %s section\n", BTF_IDS_SECTION);
		goto out;
	}
	if (obj.efile.symbols_shndx == -1) {
		pr_err("FAILED to find symbol table for %s\n", BTF_IDS_SECTION);
		goto out;
	}

	if (symbols_collect(&obj))
		goto out;

	if (btf_load(&obj, &btf))
		goto out;

	if (symbols_resolve(&obj, &btf))
		goto out;

	if (symbols_patch(&obj))
		goto out;

	err = 0;
out:
	free(btf.types);
	free(btf.data);
	for (i = 0; i < (int)obj.nr_ids; i++)
		free(obj.ids[i].name);
	for (i = 0; i < (int)obj.nr_sets; i++)
		free(obj.sets[i].name);
	free(obj.ids);
	free(obj.sets);
	if (obj.efile.elf)
		elf_end(obj.efile.elf);
	if (obj.efile.fd >= 0)
		close(obj.efile.fd);
	return err;
}
