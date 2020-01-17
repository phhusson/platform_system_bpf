/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "BpfUtils"

#include "bpf/BpfUtils.h"

#include <elf.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pfkeyv2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sstream>
#include <string>

#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <log/log.h>
#include <processgroup/processgroup.h>

using android::base::GetUintProperty;
using android::base::unique_fd;

// The buffer size for the buffer that records program loading logs, needs to be large enough for
// the largest kernel program.

namespace android {
namespace bpf {

/*  The bpf_attr is a union which might have a much larger size then the struct we are using, while
 *  The inline initializer only reset the field we are using and leave the reset of the memory as
 *  is. The bpf kernel code will performs a much stricter check to ensure all unused field is 0. So
 *  this syscall will normally fail with E2BIG if we don't fully zero bpf_attr.
 */

static int bpf(int cmd, const bpf_attr& attr) {
    return syscall(__NR_bpf, cmd, &attr, sizeof(attr));
}

int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
              uint32_t map_flags) {
    return bpf(BPF_MAP_CREATE, {
                                       .map_type = map_type,
                                       .key_size = key_size,
                                       .value_size = value_size,
                                       .max_entries = max_entries,
                                       .map_flags = map_flags,
                               });
}

int writeToMapEntry(const base::unique_fd& map_fd, void* key, void* value, uint64_t flags) {
    return bpf(BPF_MAP_UPDATE_ELEM, {
                                            .map_fd = static_cast<__u32>(map_fd.get()),
                                            .key = ptr_to_u64(key),
                                            .value = ptr_to_u64(value),
                                            .flags = flags,
                                    });
}

int findMapEntry(const base::unique_fd& map_fd, void* key, void* value) {
    return bpf(BPF_MAP_LOOKUP_ELEM, {
                                            .map_fd = static_cast<__u32>(map_fd.get()),
                                            .key = ptr_to_u64(key),
                                            .value = ptr_to_u64(value),
                                    });
}

int deleteMapEntry(const base::unique_fd& map_fd, void* key) {
    return bpf(BPF_MAP_DELETE_ELEM, {
                                            .map_fd = static_cast<__u32>(map_fd.get()),
                                            .key = ptr_to_u64(key),
                                    });
}

int getNextMapKey(const base::unique_fd& map_fd, void* key, void* next_key) {
    return bpf(BPF_MAP_GET_NEXT_KEY, {
                                             .map_fd = static_cast<__u32>(map_fd.get()),
                                             .key = ptr_to_u64(key),
                                             .next_key = ptr_to_u64(next_key),
                                     });
}

int getFirstMapKey(const base::unique_fd& map_fd, void* firstKey) {
    return bpf(BPF_MAP_GET_NEXT_KEY, {
                                             .map_fd = static_cast<__u32>(map_fd.get()),
                                             .key = 0,
                                             .next_key = ptr_to_u64(firstKey),
                                     });
}

int bpfFdPin(const base::unique_fd& map_fd, const char* pathname) {
    return bpf(BPF_OBJ_PIN, {
                                    .pathname = ptr_to_u64(pathname),
                                    .bpf_fd = static_cast<__u32>(map_fd.get()),
                            });
}

int bpfFdGet(const char* pathname, uint32_t flag) {
    return bpf(BPF_OBJ_GET, {
                                    .pathname = ptr_to_u64(pathname),
                                    .file_flags = flag,
                            });
}

int mapRetrieve(const char* pathname, uint32_t flag) {
    return bpfFdGet(pathname, flag);
}

int attachProgram(bpf_attach_type type, uint32_t prog_fd, uint32_t cg_fd) {
    return bpf(BPF_PROG_ATTACH, {
                                        .target_fd = cg_fd,
                                        .attach_bpf_fd = prog_fd,
                                        .attach_type = type,
                                });
}

int detachProgram(bpf_attach_type type, uint32_t cg_fd) {
    return bpf(BPF_PROG_DETACH, {
                                        .target_fd = cg_fd,
                                        .attach_type = type,
                                });
}

uint64_t getSocketCookie(int sockFd) {
    uint64_t sock_cookie;
    socklen_t cookie_len = sizeof(sock_cookie);
    int res = getsockopt(sockFd, SOL_SOCKET, SO_COOKIE, &sock_cookie, &cookie_len);
    if (res < 0) {
        res = -errno;
        ALOGE("Failed to get socket cookie: %s\n", strerror(errno));
        errno = -res;
        // 0 is an invalid cookie. See sock_gen_cookie.
        return NONEXISTENT_COOKIE;
    }
    return sock_cookie;
}

int synchronizeKernelRCU() {
    // This is a temporary hack for network stats map swap on devices running
    // 4.9 kernels. The kernel code of socket release on pf_key socket will
    // explicitly call synchronize_rcu() which is exactly what we need.
    int pfSocket = socket(AF_KEY, SOCK_RAW | SOCK_CLOEXEC, PF_KEY_V2);

    if (pfSocket < 0) {
        int ret = -errno;
        ALOGE("create PF_KEY socket failed: %s", strerror(errno));
        return ret;
    }

    // When closing socket, synchronize_rcu() gets called in sock_release().
    if (close(pfSocket)) {
        int ret = -errno;
        ALOGE("failed to close the PF_KEY socket: %s", strerror(errno));
        return ret;
    }
    return 0;
}

int setrlimitForTest() {
    // Set the memory rlimit for the test process if the default MEMLOCK rlimit is not enough.
    struct rlimit limit = {
            .rlim_cur = TEST_LIMIT,
            .rlim_max = TEST_LIMIT,
    };
    int res = setrlimit(RLIMIT_MEMLOCK, &limit);
    if (res) {
        ALOGE("Failed to set the default MEMLOCK rlimit: %s", strerror(errno));
    }
    return res;
}

std::string BpfLevelToString(BpfLevel bpfLevel) {
    switch (bpfLevel) {
        case BpfLevel::NONE:      return "NONE_SUPPORT";
        case BpfLevel::BASIC:     return "BPF_LEVEL_BASIC";
        case BpfLevel::EXTENDED:  return "BPF_LEVEL_EXTENDED";
        // No default statement. We want to see errors of the form:
        // "enumeration value 'BPF_LEVEL_xxx' not handled in switch [-Werror,-Wswitch]".
    }
}

BpfLevel getBpfSupportLevel() {
    struct utsname buf;
    int kernel_version_major;
    int kernel_version_minor;

    uint64_t api_level = GetUintProperty<uint64_t>("ro.product.first_api_level", 0);
    if (api_level == 0) {
        ALOGE("Cannot determine initial API level of the device");
        api_level = GetUintProperty<uint64_t>("ro.build.version.sdk", 0);
    }

    // Check if the device is shipped originally with android P.
    if (api_level < MINIMUM_API_REQUIRED) return BpfLevel::NONE;

    int ret = uname(&buf);
    if (ret) {
        return BpfLevel::NONE;
    }
    char dummy;
    ret = sscanf(buf.release, "%d.%d%c", &kernel_version_major, &kernel_version_minor, &dummy);
    // Check the device kernel version
    if (ret < 2) return BpfLevel::NONE;
    if (kernel_version_major > 4 || (kernel_version_major == 4 && kernel_version_minor >= 14))
        return BpfLevel::EXTENDED;
    if (kernel_version_major == 4 && kernel_version_minor >= 9) return BpfLevel::BASIC;

    return BpfLevel::NONE;
}

}  // namespace bpf
}  // namespace android
