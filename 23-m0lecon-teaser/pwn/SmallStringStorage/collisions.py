from ctypes import *
import math
from tqdm import tqdm

class HashMapCollisions:
    def __init__(self, size: int, load_factor: float):
        self.n = self._array_size(size, load_factor)
        self.mask: c_int32 = c_int32(self.n.value - 1)


    def _array_size(self, size, f):

        s = c_int64(max(2, self._next_power_of_two(c_int64(math.ceil(size / f))).value))
        if s.value > 1073741824:
            print("ERROR")

        # print(s.value)
        return c_uint32(s.value)

    def _next_power_of_two(self, x: c_int64):
        x.value -= 1
        x.value |= x.value >> 1
        x.value |= x.value >> 2
        x.value |= x.value >> 4
        x.value |= x.value >> 8
        x.value |= x.value >> 16
        return c_int64(x.value + 1)

    def get_position(self, k: c_int64):
        return c_int32(c_int32(self._mix(k).value).value & self.mask.value)

    def _mix(self, x: c_int64) -> c_int64:
            h: c_int64 = c_int64(x.value * -7046029254386353131)
            h.value ^= h.value >> 32
            h.value &= 0xFFFFFFFF
            h.value ^= h.value >> 16
            h.value &= 0xFFFF  # Mask to 16 bits
            return h

if __name__ == '__main__':
    # Map sizes are aligned to the closest power of 2 of initial_size / load factor
    map_size = 8192
    load_factor = 0.9

    size = math.floor(map_size * 0.9)

    print(f"You will have to create a map of size {size}")
    print(f"If you fill it over this limit you will trigger rehashing and collisions will change")

    map = HashMapCollisions(size, load_factor)
    collisions = {}
    for c in range(map_size):
        collisions[c] = []
    
    for c in tqdm(range(100_000_000)):
        collisions[map.get_position(c_int64(c)).value].append(c)

    max_length = 0
    for lst in collisions.keys():
        if len(collisions[lst]) > max_length:
            longest_list = lst
            max_length = len(collisions[lst])

    print("Longest list:", longest_list)
    print("Length:", max_length)


    import json
    with open('collisions.json', 'w') as fp:
        json.dump(collisions, fp, indent=4)
        
