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

#ifndef BPF_BPFUTILS_H
#define BPF_BPFUTILS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "android-base/unique_fd.h"
#include "netdutils/Slice.h"
#include "netdutils/StatusOr.h"

#define BPF_PASS 1
#define BPF_DROP 0

#define ptr_to_u64(x) ((uint64_t)(uintptr_t)(x))
#define DEFAULT_LOG_LEVEL 1

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

#define TEST_LIMIT 8388608

namespace android {
namespace bpf {

int mapRetrieve(const char* pathname, uint32_t flags);

enum class BpfLevel {
    // Devices shipped before P or kernel version is lower than 4.9 do not
    // have eBPF enabled.
    NONE,
    // Devices shipped in P with android 4.9 kernel only have the basic eBPF
    // functionalities such as xt_bpf and cgroup skb filter.
    BASIC,
    // For devices that have 4.14 kernel. It supports advanced features like
    // map_in_map and cgroup socket filter.
    EXTENDED,
};

#ifndef DEFAULT_OVERFLOWUID
#define DEFAULT_OVERFLOWUID 65534
#endif

constexpr const int OVERFLOW_COUNTERSET = 2;

constexpr const uint64_t NONEXISTENT_COOKIE = 0;

constexpr const int MINIMUM_API_REQUIRED = 28;

int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
              uint32_t map_flags);
int writeToMapEntry(const base::unique_fd& map_fd, void* key, void* value, uint64_t flags);
int findMapEntry(const base::unique_fd& map_fd, void* key, void* value);
int deleteMapEntry(const base::unique_fd& map_fd, void* key);
int getNextMapKey(const base::unique_fd& map_fd, void* key, void* next_key);
int getFirstMapKey(const base::unique_fd& map_fd, void* firstKey);
int bpfFdPin(const base::unique_fd& map_fd, const char* pathname);
int bpfFdGet(const char* pathname, uint32_t flags);
int attachProgram(bpf_attach_type type, uint32_t prog_fd, uint32_t cg_fd);
int detachProgram(bpf_attach_type type, uint32_t cg_fd);
uint64_t getSocketCookie(int sockFd);
int setrlimitForTest();
std::string BpfLevelToString(BpfLevel BpfLevel);
BpfLevel getBpfSupportLevel();
int synchronizeKernelRCU();

#define SKIP_IF_BPF_NOT_SUPPORTED                                                    \
    do {                                                                             \
        if (android::bpf::getBpfSupportLevel() == android::bpf::BpfLevel::NONE) {    \
            GTEST_LOG_(INFO) << "This test is skipped since bpf is not available\n"; \
            return;                                                                  \
        }                                                                            \
    } while (0)

#define SKIP_IF_BPF_SUPPORTED                                                           \
    do {                                                                                \
        if (android::bpf::getBpfSupportLevel() != android::bpf::BpfLevel::NONE) return; \
    } while (0)

}  // namespace bpf
}  // namespace android

#endif
