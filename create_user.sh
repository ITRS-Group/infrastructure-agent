#!/bin/bash -x
# Company Confidential.
# Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved

user="infra-agent"
group="infra-agent"
nologin_shell=$(test -x /usr/sbin/nologin && echo "/usr/sbin/nologin" || echo "/sbin/nologin")

if getent group ${group} > /dev/null; then
    : # group already exists
else
    if /usr/sbin/groupadd -r ${group}; then
        :
    else
        >&2 echo 'Unexpected error adding group "'${group}'"'
        exit 1
    fi
fi

if getent passwd ${user} &>/dev/null; then
    chsh -s ${nologin_shell} ${user}
    passwd -l ${user}
else
    if ! /usr/sbin/useradd -r -M -s ${nologin_shell} -c "${user}" -g ${group} ${user} ; then
        >&2 echo 'Unexpected error adding user "'${group}'" to groups'
        exit 1
    else
        passwd -l ${user}
    fi
fi

exit 0
