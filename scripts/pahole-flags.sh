#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# The caller supplies the pahole version as major * 100 + minor.
case "${1}" in
''|*[!0-9]*)
	echo "error: pahole-flags.sh requires a numeric pahole version" >&2
	exit 1
	;;
esac

extra_paholeopt=

if [ "${1}" -ge 118 ] && [ "${1}" -le 121 ]; then
	# pahole 1.18 through 1.21 cannot encode zero-sized per-CPU variables.
	extra_paholeopt="${extra_paholeopt} --skip_encoding_btf_vars"
fi

if [ "${1}" -ge 124 ]; then
	# This backport's BTF kinds stop at DATASEC; ENUM64 is not supported.
	extra_paholeopt="${extra_paholeopt} --skip_encoding_btf_enum64"
fi

# Do not add --btf_gen_floats: BTF_KIND_FLOAT is not supported either.
printf '%s\n' "${extra_paholeopt# }"
