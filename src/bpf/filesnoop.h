/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILESNOOP_H
#define __FILESNOOP_H

#define MAX_FILENAME_LEN 255

struct open_event {
    uint64_t ts;
    char filename[MAX_FILENAME_LEN];
    int32_t pid;
    int32_t ppid;
    uint32_t exit_code;
};

#endif /* __BOOTSTRAP_H */
