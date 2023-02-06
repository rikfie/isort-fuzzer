#!/usr/bin/python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Harnass for fuzzing https://github.com/PyCQA/isort """

import sys
import struct
import atheris
import isort


def test_isort_code(inp):
    """ Testing isort code method """
    isort.code(inp)

LONGSTR = 1
MEDIUMSTR = 2
SHORTSTR = 3
SSHORTSTR = 4

TESTS = [
    (test_isort_code, str),
]

def get_input(input_bytes, idx):
    """ Get input of the right type/size """
    fdp = atheris.FuzzedDataProvider(input_bytes)
    if TESTS[idx][1] == str:
        return fdp.ConsumeUnicode(sys.maxsize)
    if TESTS[idx][1] == LONGSTR:
        return fdp.ConsumeUnicode(100000)
    if TESTS[idx][1] == MEDIUMSTR:
        return fdp.ConsumeUnicode(10000)
    if TESTS[idx][1] == SHORTSTR:
        return fdp.ConsumeUnicode(1000)
    if TESTS[idx][1] == SSHORTSTR:
        return fdp.ConsumeUnicode(100)
    return None

def test_one_input(input_bytes):
    """ Fuzzer's entry point """
    if len(input_bytes) < 1:
        return
    idx = struct.unpack('>B', input_bytes[:1])[0]
    if idx >= len(TESTS):
        return
    TESTS[idx][0](get_input(input_bytes[1:], idx))

def main():
    """ main function """
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=False)
    atheris.Fuzz()


if __name__ == "__main__":
    atheris.instrument_all()
    main()
