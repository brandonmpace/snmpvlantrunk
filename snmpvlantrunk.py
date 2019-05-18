#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# Copyright (C) 2019 Brandon M. Pace
#
# This file is part of snmpvlantrunk
#
# snmpvlantrunk is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# snmpvlantrunk is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with snmpvlantrunk.
# If not, see <https://www.gnu.org/licenses/>.
#
# Pull requests and feedback are welcome at https://github.com/brandonmpace/snmpvlantrunk

"""
Module for handling SNMP VLAN trunk data, typically received from switches as a space-separated octet string.

Usage example:
- Instantiate SnmpVlanTrunk instance
- Add VLANs with either add_vlan or add_vlan_trunk_string methods (you can use both as needed, in any order you wish)
  - You can use the group_for_oid function to get the group to pass to add_vlan_trunk_string based on oid prefix or name
- Remove VLANs with remove_vlan method if needed
  - NOTE: If you simply wish to clear ALL VLANs, just don't add any to the SnmpVlanTrunk instance.
- Get the updated string with get_vlan_trunk_string method using relevant group
  - You could also use vlan_trunk_strings attribute and iterate over the returned dict instead
- You can also access the vlans attribute to get the human-readable VLANs that are set in each group.

If you wish to catch errors to log or inform the user, the most common exception used here is ValueError
"""

import re

from typing import Dict, List


# Lowest VLAN supported by the switches
MIN_VLAN = 1

# Max VLAN supported by the switches
MAX_VLAN = 4094

VLAN_GROUP_COUNT = 4

# VLANs in each group (4 OIDs == 4 groups of 1024) Should be divisible by 8 as it is also the number of bits per-group
VLAN_GROUP_SIZE = 1024


# sanity checks in case of future changes
assert MAX_VLAN <= (VLAN_GROUP_SIZE * VLAN_GROUP_COUNT), "MAX_VLAN is outside of group ranges!"
assert (VLAN_GROUP_SIZE % 8) == 0, "VLAN_GROUP_SIZE is not divisible by 8!"


BYTES_PER_GROUP = int(VLAN_GROUP_SIZE / 8)


# Lists of OIDs in each VLAN group (as either prefix without interface digit or as the human-friendly name)
GROUP_TO_OIDS = {
    0: [".1.3.6.1.4.1.89.48.61.1.2.", "vlanTrunkModeList1to1024"],
    1: [".1.3.6.1.4.1.89.48.61.1.3.", "vlanTrunkModeList1025to2048"],
    2: [".1.3.6.1.4.1.89.48.61.1.4.", "vlanTrunkModeList2049to3072"],
    3: [".1.3.6.1.4.1.89.48.61.1.5.", "vlanTrunkModeList3073to4094"]
}


# Strict regex that matches correct number of upper-case hex bytes separated by spaces (common formatting)
VLAN_TRUNK_STRING_REGEX = f"^([0-9A-F]{{2}})( [0-9A-F]{{2}}){'{' + str(BYTES_PER_GROUP - 1) + '}'}$"
VLAN_TRUNK_STRING_REGEX_COMPILED = re.compile(VLAN_TRUNK_STRING_REGEX)


class SnmpVlanTrunk(object):
    """Client-facing class for simple manipulation of the octet strings used by SNMP for VLAN trunks"""
    def __init__(self):
        """Creates an instance with no VLANs set in all groups"""
        self._trunk_mode_lists = {}
        for group_id in range(VLAN_GROUP_COUNT):
            self._trunk_mode_lists[group_id] = VlanTrunkModeList(group_id)

    def add_vlan(self, vlan_id: int):
        instance = self._get_group_instance_from_vlan(vlan_id)
        instance.add_vlan(vlan_id)

    def add_vlan_trunk_string(self, vlan_string: str, group: int):
        instance = self._get_group_instance(group)
        instance.add_vlan_trunk_string(vlan_string)

    def get_vlan_trunk_string(self, group: int) -> str:
        instance = self._get_group_instance(group)
        return instance.get_vlan_trunk_string()

    def has_vlan(self, vlan_id: int) -> bool:
        instance = self._get_group_instance_from_vlan(vlan_id)
        return instance.has_vlan(vlan_id)

    def remove_vlan(self, vlan_id: int):
        instance = self._get_group_instance_from_vlan(vlan_id)
        instance.remove_vlan(vlan_id)

    @property
    def vlan_trunk_strings(self) -> Dict[int, str]:
        """Return a dict with group number as key and VLAN trunk string as value"""
        vlan_lists = {}
        for group, instance in self._trunk_mode_lists.items():
            vlan_lists[group] = instance.get_vlan_trunk_string()
        return vlan_lists

    @property
    def vlans(self) -> Dict[int, List[int]]:
        """Return a dict with group number as key and list of int VLAN IDs for value"""
        vlan_lists = {}
        for group, instance in self._trunk_mode_lists.items():
            vlan_lists[group] = instance.vlans
        return vlan_lists

    def _get_group_instance(self, group: int) -> 'VlanTrunkModeList':
        if group in self._trunk_mode_lists:
            return self._trunk_mode_lists[group]
        else:
            raise ValueError(f"Unexpected value for group: {group}")

    def _get_group_instance_from_vlan(self, vlan_id: int) -> 'VlanTrunkModeList':
        group = group_for_vlan(vlan_id)
        return self._get_group_instance(group)


class VlanTrunkModeList(object):
    """Internal class for backend data manipulation"""
    def __init__(self, group: int):
        self._group = group
        self._value = 0

    def add_vlan(self, vlan_id: int):
        if vlan_in_group(vlan_id, self._group):
            # Binary OR to set this VLAN's bit to 1 (even if already set)
            self._value |= vlan_bit(vlan_id)
        else:
            raise ValueError(f"VLAN {vlan_id} is not part of group {self._group}")

    def add_vlan_trunk_string(self, vlan_string: str):
        if is_valid_vlan_trunk_string(vlan_string):
            without_whitespace = ''.join(vlan_string.split())
            int_value = int(without_whitespace, 16)
            reversed_int_value = reverse_bits(int_value, VLAN_GROUP_SIZE)
            self._value |= reversed_int_value
        else:
            raise ValueError(f"Unexpected value for vlan_string: {vlan_string}")

    def get_vlan_trunk_string(self) -> str:
        byte_values = reverse_bits(self._value, VLAN_GROUP_SIZE).to_bytes(BYTES_PER_GROUP, 'big')
        hex_string = byte_values.hex().upper()

        # Use striding to split the byte-pairs into two lists. Use zip to join the byte-pairs back together as tuples.
        # Then use the list of tuples to make a list of two-character strings and finally join with spaces between them.
        hex_list = [a + b for a, b in list(zip(hex_string[::2], hex_string[1::2]))]
        return ' '.join(hex_list)

    @property
    def group(self):
        return self._group

    def has_vlan(self, vlan_id: int) -> bool:
        return bool(vlan_bit(vlan_id) & self._value)

    @property
    def vlans(self) -> List[int]:
        return bits_to_vlans(self._value, self._group)

    def remove_vlan(self, vlan_id: int):
        if vlan_in_group(vlan_id, self._group):
            # Binary AND with one's compliment to set just this VLAN's bit to 0
            self._value &= ~vlan_bit(vlan_id)

    @property
    def value(self) -> int:
        """Get the integer value representing the contained VLANs."""
        return self._value


def bit_to_vlan(bit_value: int, group: int) -> int:
    """
    Take an int with a single bit set to 1 and return the VLAN ID as an int
    :param bit_value: int with a single bit set to 1
    :param group: int VLAN group for calculation
    :return: int VLAN ID
    """
    if not bit_value:
        raise ValueError(f"Got bit_value with no bits set!")
    elif bit_value < 0:
        raise ValueError(f"Got negative bit_value! Value: {bit_value}")

    bin_string = bin(bit_value).lstrip('0b')

    if bin_string.count('1') > 1:
        raise ValueError(f"Got bit_value with more than one bit set! Value: {bit_value}")

    position = len(bin_string)
    vlan_id = (position + (VLAN_GROUP_SIZE * group))

    return vlan_id


def bits_to_vlans(bit_values: int, group: int) -> List[int]:
    """Get a list of VLAN IDs represented by the bits set to 1 in bit_values"""
    vlan_list = []
    for bit_value in range(VLAN_GROUP_SIZE):
        check_value = (1 << bit_value) & bit_values
        if check_value:
            vlan_list.append(bit_to_vlan(check_value, group))
    return vlan_list


def group_for_oid(oid: str) -> int:
    """
    Find the VLAN group that the OID string belongs to
    :param oid: str OID that should have a numerical prefix or full name exist in GROUPS_TO_OIDS
    :return: int
    """
    for group, oid_list in GROUP_TO_OIDS.items():
        if any(oid.startswith(item) for item in oid_list):
            return group
    # No group found:
    raise ValueError(f"OID {oid} does not exist in groups dict!")


def group_for_vlan(vlan_id: int) -> int:
    """Get the group the VLAN falls under based on the VLAN_GROUP_SIZE"""
    validate_vlan(vlan_id)

    group = 0
    test_value = vlan_id

    while test_value > VLAN_GROUP_SIZE:
        group += 1
        test_value -= VLAN_GROUP_SIZE

    return group


def is_valid_vlan(vlan_id: int) -> bool:
    return validate_vlan(vlan_id, safe=True)


def is_valid_vlan_trunk_string(vlan_trunk_string: str) -> bool:
    if VLAN_TRUNK_STRING_REGEX_COMPILED.match(vlan_trunk_string):
        return True
    else:
        return False


def reverse_bits(input_value: int, bit_width: int) -> int:
    """
    Flip endianness for bits. (bit-order instead of byte-order)
    :param input_value: int value to reverse the bits of
    :param bit_width: int width that represents the data (number of *bits* required to display necessary values)
    :return: int
    """
    # Convert to binary string
    bit_string = bin(input_value).lstrip('0b')

    # Pad with zeros to maintain correct bit width
    padded_string = bit_string.zfill(bit_width)

    # Reverse the string
    reversed_bit_string = padded_string[::-1]

    return int(reversed_bit_string, 2)


# initially created before finding that it wasn't relevant, left here in case it is for different model switches
def reverse_bytes(input_value: int, width: int) -> int:
    """
    Reverse the byte-order (endianness) of the input
    :param input_value: int value to reverse
    :param width: int number of *bytes* needed to represent the number
    :return: int
    """
    byte_value = input_value.to_bytes(width, 'little')
    return int.from_bytes(byte_value, 'big')


def validate_vlan(vlan_id: int, safe: bool = False) -> bool:
    """Confirm that a VLAN ID is within the allowed range"""
    if (vlan_id >= MIN_VLAN) and (vlan_id <= MAX_VLAN):
        return True
    elif safe:
        return False
    else:
        raise ValueError(f"Unexpected value for vlan_id: {vlan_id}")


def vlan_bit(vlan_id: int) -> int:
    """Get the int value with the VLAN's bit set to 1"""
    validate_vlan(vlan_id)
    group = group_for_vlan(vlan_id)
    value = (1 << (vlan_id - (group * VLAN_GROUP_SIZE) - 1))
    return value


def vlan_in_group(vlan_id: int, group: int) -> bool:
    """Confirm whether or not the VLAN ID belongs in the group according to the global group size"""
    result = vlan_id - (VLAN_GROUP_SIZE * group)
    return (result >= 0) and (result <= VLAN_GROUP_SIZE)


if __name__ == "__main__":
    # When this file is run directly, run sanity tests.

    # Test string with first VLAN bit set
    test_string = ("80" + (" 00" * (BYTES_PER_GROUP - 1)))

    print(f"Test string is: {test_string}")

    if is_valid_vlan_trunk_string(test_string) is False:
        print("Test string validation failed!")
        exit(1)

    trunk_instance = SnmpVlanTrunk()

    # Get the first VLAN ID in each group (e.g. 1, 1025, 2049, ...) and add them to the instance
    first_vlans = {}
    for group_number in range(VLAN_GROUP_COUNT):
        vlan_number = first_vlans[group_number] = (1 + (group_number * VLAN_GROUP_SIZE))
        # test add_vlan
        print(f"Adding VLAN {vlan_number}, expected group is {group_for_vlan(vlan_number)}")
        trunk_instance.add_vlan(vlan_number)
        if trunk_instance.has_vlan(vlan_number):
            print(f"VLAN {vlan_number} set successfully")
        else:
            print(f"VLAN does not appear to be set! ID: {vlan_number}")

    print(f"First VLAN in each group: {first_vlans}")

    for group_number, trunk_string in trunk_instance.vlan_trunk_strings.items():
        if trunk_string == test_string:
            print(f"Group {group_number} vlan trunk string matched test string (success)")
        else:
            raise ValueError(f"Group {group_number} has invalid data! String: {trunk_string}")

    for group_number in range(VLAN_GROUP_COUNT):
        # test add_vlan_trunk_string
        print(f"Adding test string for group {group_number}")
        trunk_instance.add_vlan_trunk_string(test_string, group_number)

    # Test vlans attribute as well as validate that adding the trunk string worked properly
    for group_number, vlan_list in trunk_instance.vlans.items():
        print(f"Group {group_number} has vlans: {vlan_list}")
        if first_vlans[group_number] not in vlan_list:
            raise ValueError(f"Group {group_number} has invalid data! Missing VLAN: {first_vlans[group_number]}")

    print("All tests passed")
