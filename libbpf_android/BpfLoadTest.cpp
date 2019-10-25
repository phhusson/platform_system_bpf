/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <iostream>
#include "include/bpf/BpfMap.h"
#include "include/bpf/BpfUtils.h"
#include "include/libbpf_android.h"

using ::testing::Test;

constexpr const char tp_prog_path[] =
        "/sys/fs/bpf/prog_bpf_load_tp_prog_tracepoint_sched_sched_switch";
constexpr const char tp_map_path[] = "/sys/fs/bpf/map_bpf_load_tp_prog_cpu_pid_map";

constexpr const char tp_autoclear_map_path_prefix[] = "/sys/fs/bpf/map_bpf_autoclear_maps_autoclear_";

namespace android {
namespace bpf {

class BpfLoadTest : public testing::Test {
  protected:
    BpfLoadTest() {}
    int mProgFd, mMapFd;

    void SetUp() {
        SKIP_IF_BPF_NOT_SUPPORTED;

        unlink(tp_prog_path);
        unlink(tp_map_path);

        EXPECT_EQ(android::bpf::loadProg("/system/etc/bpf/bpf_load_tp_prog.o"), 0);

        mProgFd = bpf_obj_get(tp_prog_path);
        EXPECT_GT(mProgFd, 0);

        mMapFd = bpf_obj_get(tp_map_path);
        EXPECT_GT(mMapFd, 0);
    }

    void TearDown() {
        SKIP_IF_BPF_NOT_SUPPORTED;

        close(mProgFd);
        close(mMapFd);
        unlink(tp_prog_path);
        unlink(tp_map_path);
    }

    void checkMapNonZero() {
        // The test program installs a tracepoint on sched:sched_switch
        // and expects the kernel to populate a PID corresponding to CPU
        android::bpf::BpfMap<uint32_t, uint32_t> m(mMapFd);

        // Wait for program to run a little
        sleep(1);

        int non_zero = 0;
        const auto iterFunc = [&non_zero](const uint32_t& key, const uint32_t& val,
                                          BpfMap<uint32_t, uint32_t>& map) {
            if (val && !non_zero) {
                non_zero = 1;
            }

            UNUSED(key);
            UNUSED(map);
            return android::netdutils::status::ok;
        };

        EXPECT_OK(m.iterateWithValue(iterFunc));
        EXPECT_EQ(non_zero, 1);
    }
};

TEST_F(BpfLoadTest, bpfCheckMap) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    checkMapNonZero();
}

TEST(BpfLoadAutoclearTest, bpfCheckMapClearing) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    for (int i = 0; i < 2; i++) {
        EXPECT_EQ(android::bpf::loadProg("/system/etc/bpf/bpf_autoclear_maps.o"), 0);
        for (const auto &name : {"hash", "percpu_hash", "array", "percpu_array"}) {
            auto path = android::base::StringPrintf("%s%s", tp_autoclear_map_path_prefix, name);
            android::base::unique_fd mapFd(bpf_obj_get(path.c_str()));
            ASSERT_GT(mapFd, 0);

            size_t sz = android::base::StartsWith(name, "percpu") ? get_nprocs_conf() : 1;
            std::vector<uint32_t> vals(sz);

            uint32_t key;
            auto ret = android::bpf::getFirstMapKey(mapFd, &key);
            if (android::base::EndsWith(name, "hash")) {
                EXPECT_NE(ret, 0);
                EXPECT_EQ(errno, ENOENT);
            } else {
                uint32_t prevKey;
                std::vector<uint32_t> zeroes(vals.size(),0);
                do {
                    ASSERT_EQ(findMapEntry(mapFd, &key, vals.data()),0);
                    EXPECT_EQ(memcmp(vals.data(), zeroes.data(), vals.size()), 0);
                } while (prevKey = key, !android::bpf::getNextMapKey(mapFd, &prevKey, &key));
            }
            key = 0;
            std::fill(vals.begin(), vals.end(), 1);
            ASSERT_EQ(writeToMapEntry(mapFd, &key, vals.data(), BPF_ANY), 0);
            if (i == 1) unlink(path.c_str());
        }
    }
}

}  // namespace bpf
}  // namespace android
