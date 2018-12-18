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

#include <stdio.h>
#include <iostream>
#include <vector>

#include <android-base/strings.h>

using android::base::Split;
using std::string;
using std::vector;

static string pathToFilename(string path, bool noext = false) {
    vector<string> spath = android::base::Split(path, "/");
    string ret = spath.back();

    if (noext) {
        size_t lastindex = ret.find_last_of(".");
        return ret.substr(0, lastindex);
    }
    return ret;
}

static int getMachineKvers(void) {
    struct utsname un;
    char* unameOut;
    int nums[3];  // maj, min, sub

    if (uname(&un)) return -1;
    unameOut = un.release;

    string s = unameOut;
    string token;
    size_t pos = 0;
    int cur_num = 0;

    while ((pos = s.find(".")) != string::npos && cur_num < 3) {
        token = s.substr(0, pos);
        s.erase(0, pos + 1);

        if ((pos = token.find("-")) != string::npos) token = token.substr(0, pos);

        nums[cur_num++] = stoi(token);
    }

    if ((pos = s.find("-")) != string::npos)
        token = s.substr(0, pos);
    else
        token = s;

    if (token.length() > 0 && cur_num < 3) {
        nums[cur_num++] = stoi(token);
    }

    if (cur_num != 3)
        return -1;
    else
        return (65536 * nums[0] + 256 * nums[1] + nums[2]);
}

static void deslash(string& s) {
    std::replace(s.begin(), s.end(), '/', '_');
}
