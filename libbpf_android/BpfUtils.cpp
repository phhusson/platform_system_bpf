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
#include <netdutils/MemBlock.h>
#include <netdutils/Slice.h>
#include <processgroup/processgroup.h>

using android::base::GetUintProperty;
using android::base::unique_fd;
using android::netdutils::MemBlock;
using android::netdutils::Slice;

// The buffer size for the buffer that records program loading logs, needs to be large enough for
// the largest kernel program.
constexpr size_t LOG_BUF_SIZE = 0x20000;

namespace android {
namespace bpf {

/*  The bpf_attr is a union which might have a much larger size then the struct we are using, while
 *  The inline initializer only reset the field we are using and leave the reset of the memory as
 *  is. The bpf kernel code will performs a much stricter check to ensure all unused field is 0. So
 *  this syscall will normally fail with E2BIG if we don't do a memset to bpf_attr.
 */
bool operator==(const StatsKey& lhs, const StatsKey& rhs) {
    return ((lhs.uid == rhs.uid) && (lhs.tag == rhs.tag) && (lhs.counterSet == rhs.counterSet) &&
            (lhs.ifaceIndex == rhs.ifaceIndex));
}

bool operator==(const UidTag& lhs, const UidTag& rhs) {
    return ((lhs.uid == rhs.uid) && (lhs.tag == rhs.tag));
}

bool operator==(const StatsValue& lhs, const StatsValue& rhs) {
    return ((lhs.rxBytes == rhs.rxBytes) && (lhs.txBytes == rhs.txBytes) &&
            (lhs.rxPackets == rhs.rxPackets) && (lhs.txPackets == rhs.txPackets));
}

int bpf(int cmd, Slice bpfAttr) {
    return syscall(__NR_bpf, cmd, bpfAttr.base(), bpfAttr.size());
}

int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
              uint32_t map_flags) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;

    return bpf(BPF_MAP_CREATE, Slice(&attr, sizeof(attr)));
}

int writeToMapEntry(const base::unique_fd& map_fd, void* key, void* value, uint64_t flags) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd.get();
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);
    attr.flags = flags;

    return bpf(BPF_MAP_UPDATE_ELEM, Slice(&attr, sizeof(attr)));
}

int findMapEntry(const base::unique_fd& map_fd, void* key, void* value) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd.get();
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);

    return bpf(BPF_MAP_LOOKUP_ELEM, Slice(&attr, sizeof(attr)));
}

int deleteMapEntry(const base::unique_fd& map_fd, void* key) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd.get();
    attr.key = ptr_to_u64(key);

    return bpf(BPF_MAP_DELETE_ELEM, Slice(&attr, sizeof(attr)));
}

int getNextMapKey(const base::unique_fd& map_fd, void* key, void* next_key) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd.get();
    attr.key = ptr_to_u64(key);
    attr.next_key = ptr_to_u64(next_key);

    return bpf(BPF_MAP_GET_NEXT_KEY, Slice(&attr, sizeof(attr)));
}

int getFirstMapKey(const base::unique_fd& map_fd, void* firstKey) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd.get();
    attr.key = 0;
    attr.next_key = ptr_to_u64(firstKey);

    return bpf(BPF_MAP_GET_NEXT_KEY, Slice(&attr, sizeof(attr)));
}

int bpfProgLoad(bpf_prog_type prog_type, Slice bpf_insns, const char* license,
                uint32_t kern_version, Slice bpf_log) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insns = ptr_to_u64(bpf_insns.base());
    attr.insn_cnt = bpf_insns.size() / sizeof(struct bpf_insn);
    attr.license = ptr_to_u64((void*)license);
    attr.log_buf = ptr_to_u64(bpf_log.base());
    attr.log_size = bpf_log.size();
    attr.log_level = DEFAULT_LOG_LEVEL;
    attr.kern_version = kern_version;
    int ret = bpf(BPF_PROG_LOAD, Slice(&attr, sizeof(attr)));

    if (ret < 0) {
        std::string prog_log = netdutils::toString(bpf_log);
        std::istringstream iss(prog_log);
        for (std::string line; std::getline(iss, line);) {
            ALOGE("%s", line.c_str());
        }
    }
    return ret;
}

int bpfFdPin(const base::unique_fd& map_fd, const char* pathname) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void*)pathname);
    attr.bpf_fd = map_fd.get();

    return bpf(BPF_OBJ_PIN, Slice(&attr, sizeof(attr)));
}

int bpfFdGet(const char* pathname, uint32_t flag) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void*)pathname);
    attr.file_flags = flag;
    return bpf(BPF_OBJ_GET, Slice(&attr, sizeof(attr)));
}

int mapRetrieve(const char* pathname, uint32_t flag) {
    return bpfFdGet(pathname, flag);
}

int attachProgram(bpf_attach_type type, uint32_t prog_fd, uint32_t cg_fd) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cg_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = type;

    return bpf(BPF_PROG_ATTACH, Slice(&attr, sizeof(attr)));
}

int detachProgram(bpf_attach_type type, uint32_t cg_fd) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cg_fd;
    attr.attach_type = type;

    return bpf(BPF_PROG_DETACH, Slice(&attr, sizeof(attr)));
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

int loadAndPinProgram(BpfProgInfo* prog, Slice progBlock) {
    // Program doesn't exist. Try to load it.
    char bpf_log_buf[LOG_BUF_SIZE];
    Slice bpfLog = Slice(bpf_log_buf, sizeof(bpf_log_buf));
    prog->fd.reset(bpfProgLoad(prog->loadType, progBlock, "Apache 2.0", 0, bpfLog));
    if (prog->fd < 0) {
        int ret = -errno;
        ALOGE("load %s failed: %s", prog->name, strerror(errno));
        return ret;
    }
    if (prog->attachType == BPF_CGROUP_INET_EGRESS || prog->attachType == BPF_CGROUP_INET_INGRESS) {
        std::string cg2_path;
        if (!CgroupGetControllerPath(CGROUPV2_CONTROLLER_NAME, &cg2_path)) {
            int ret = -errno;
            ALOGE("Failed to find cgroup v2 root");
            return ret;
        }
        unique_fd cg_fd(open(cg2_path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
        if (cg_fd < 0) {
            int ret = -errno;
            ALOGE("Failed to open the cgroup directory");
            return ret;
        }
        int ret = android::bpf::attachProgram(prog->attachType, prog->fd, cg_fd);
        if (ret) {
            ret = -errno;
            ALOGE("%s attach failed: %s", prog->name, strerror(errno));
            return ret;
        }
    }
    if (prog->path) {
        int ret = android::bpf::bpfFdPin(prog->fd, prog->path);
        if (ret) {
            ret = -errno;
            ALOGE("Pin %s as file %s failed: %s", prog->name, prog->path, strerror(errno));
            return ret;
        }
    }
    return 0;
}

int extractAndLoadProg(BpfProgInfo* prog, Elf64_Shdr* sectionPtr, Slice fileContents,
                       const std::vector<BpfMapInfo>& mapPatterns) {
    uint64_t progSize = (uint64_t)sectionPtr->sh_size;
    Slice progSection = take(drop(fileContents, sectionPtr->sh_offset), progSize);
    if (progSection.size() < progSize) {
        ALOGE("programSection out of bound");
        return -EINVAL;
    }
    MemBlock progCopy(progSection);
    if (progCopy.get().size() != progSize) {
        ALOGE("program cannot be extracted");
        return -EINVAL;
    }
    Slice remaining = progCopy.get();
    while (remaining.size() >= MAP_CMD_SIZE) {
        // Scan the program, examining all possible places that might be the start of a
        // map load operation (i.e., all bytes of value MAP_LD_CMD_HEAD).
        // In each of these places, check whether it is the start of one of the patterns
        // we want to replace, and if so, replace it.
        Slice mapHead = findFirstMatching(remaining, MAP_LD_CMD_HEAD);
        if (mapHead.size() < MAP_CMD_SIZE) break;
        bool replaced = false;
        for (const auto& pattern : mapPatterns) {
            if (!memcmp(mapHead.base(), pattern.search.data(), MAP_CMD_SIZE)) {
                memcpy(mapHead.base(), pattern.replace.data(), MAP_CMD_SIZE);
                replaced = true;
                break;
            }
        }
        remaining = drop(mapHead, replaced ? MAP_CMD_SIZE : sizeof(uint8_t));
    }
    if (!(prog->path) || access(prog->path, R_OK) == -1) {
        return loadAndPinProgram(prog, progCopy.get());
    }
    return 0;
}

int parsePrograms(Slice fileContents, BpfProgInfo* programs, size_t size,
                  const std::vector<BpfMapInfo>& mapPatterns) {
    Slice elfHeader = take(fileContents, sizeof(Elf64_Ehdr));
    if (elfHeader.size() < sizeof(Elf64_Ehdr)) {
        ALOGE("bpf fileContents does not have complete elf header");
        return -EINVAL;
    }

    Elf64_Ehdr* elf = (Elf64_Ehdr*)elfHeader.base();
    // Find section names string table. This is the section whose index is e_shstrndx.
    if (elf->e_shstrndx == SHN_UNDEF) {
        ALOGE("cannot locate namesSection\n");
        return -EINVAL;
    }
    size_t totalSectionSize = (elf->e_shnum) * sizeof(Elf64_Shdr);
    Slice sections = take(drop(fileContents, elf->e_shoff), totalSectionSize);
    if (sections.size() < totalSectionSize) {
        ALOGE("sections corrupted");
        return -EMSGSIZE;
    }

    Slice namesSection =
        take(drop(sections, elf->e_shstrndx * sizeof(Elf64_Shdr)), sizeof(Elf64_Shdr));
    if (namesSection.size() != sizeof(Elf64_Shdr)) {
        ALOGE("namesSection corrupted");
        return -EMSGSIZE;
    }
    size_t strTabOffset = ((Elf64_Shdr*)namesSection.base())->sh_offset;
    size_t strTabSize = ((Elf64_Shdr*)namesSection.base())->sh_size;

    Slice strTab = take(drop(fileContents, strTabOffset), strTabSize);
    if (strTab.size() < strTabSize) {
        ALOGE("string table out of bound\n");
        return -EMSGSIZE;
    }

    for (int i = 0; i < elf->e_shnum; i++) {
        Slice section = take(drop(sections, i * sizeof(Elf64_Shdr)), sizeof(Elf64_Shdr));
        if (section.size() < sizeof(Elf64_Shdr)) {
            ALOGE("section %d is out of bound, section size: %zu, header size: %zu, total size: "
                  "%zu",
                  i, section.size(), sizeof(Elf64_Shdr), sections.size());
            return -EBADF;
        }
        Elf64_Shdr* sectionPtr = (Elf64_Shdr*)section.base();
        Slice nameSlice = drop(strTab, sectionPtr->sh_name);
        if (nameSlice.size() == 0) {
            ALOGE("nameSlice out of bound, i: %d, strTabSize: %zu, sh_name: %u", i, strTabSize,
                  sectionPtr->sh_name);
            return -EBADF;
        }
        for (size_t i = 0; i < size; i++) {
            BpfProgInfo* prog = programs + i;
            if (!strcmp((char*)nameSlice.base(), prog->name)) {
                int ret = extractAndLoadProg(prog, sectionPtr, fileContents, mapPatterns);
                if (ret) return ret;
            }
        }
    }

    // Check all the program struct passed in to make sure they all have a valid fd.
    for (size_t i = 0; i < size; i++) {
        BpfProgInfo* prog = programs + i;
        if (access(prog->path, R_OK) == -1) {
            ALOGE("Load program %s failed", prog->name);
            return -EINVAL;
        }
    }
    return 0;
}

int parseProgramsFromFile(const char* path, BpfProgInfo* programs, size_t size,
                          const std::vector<BpfMapInfo>& mapPatterns) {
    unique_fd fd(open(path, O_RDONLY | O_CLOEXEC));
    int ret;
    if (fd < 0) {
        ret = -errno;
        ALOGE("Failed to open %s program: %s", path, strerror(errno));
        return ret;
    }

    struct stat stat;
    if (fstat(fd.get(), &stat)) {
        ret = -errno;
        ALOGE("Failed to get file (%s) size: %s", path, strerror(errno));
        return ret;
    }

    off_t fileLen = stat.st_size;
    char* baseAddr = (char*)mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd.get(), 0);
    if (baseAddr == MAP_FAILED) {
        ALOGE("Failed to map the program (%s) into memory: %s", path, strerror(errno));
        ret = -errno;
        return ret;
    }

    ret = parsePrograms(Slice(baseAddr, fileLen), programs, size, mapPatterns);

    munmap(baseAddr, fileLen);
    return ret;
}

}  // namespace bpf
}  // namespace android
