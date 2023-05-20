from tqdm import tqdm
import math
from ctypes import *
import cProfile
import ijson


import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('hashMap')

class CustomHashMap:
    def __init__(self, initial_size, load_factor):

        self.n: c_int32 = self._array_size(initial_size, load_factor)
        self.f = load_factor
        self.mask: c_int32 = c_int32(self.n.value - 1)
        self.max_fill: c_int32 = self._max_fill(self.n, self.f)

        self.contains_null_key: bool = False
        self.size: c_int32 = c_int32(0)
        self.key = [0 for _ in range(self.n.value + 1)]      #keys
        self.value = [None for _ in range(self.n.value + 1)] #objects

        self.defaultReturnValue = None
        log.info(f"Creating Map, initial size: {self.n.value}, load factor: {self.f}, max fill: {self.max_fill.value}")


    # public static int arraySize(int expected, float f) {
    #     long s = Math.max(2L, nextPowerOfTwo((long)Math.ceil((double)((float)expected / f))));
    #     if (s > 1073741824L) {
    #         throw new IllegalArgumentException("Too large (" + expected + " expected elements with load factor " + f + ")");
    #     } else {
    #         return (int)s;
    #     }
    # }
    def _array_size(self, size, f):

        s = c_int64(max(2, self.next_power_of_two(c_int64(math.ceil(size / f))).value))
        if s.value > 1073741824:
            print("ERROR")

        # print(s.value)
        return c_uint32(s.value)

    # public static long nextPowerOfTwo(long x) {
    #     return 1L << 64 - Long.numberOfLeadingZeros(x - 1L);
    # }
    def next_power_of_two(self, x: c_int64):
        x.value -= 1
        x.value |= x.value >> 1
        x.value |= x.value >> 2
        x.value |= x.value >> 4
        x.value |= x.value >> 8
        x.value |= x.value >> 16
        return c_int64(x.value + 1)


    # public static int maxFill(int n, float f) {
    #     return Math.min((int)Math.ceil((double)((float)n * f)), n - 1);
    # }
    def _max_fill(self, n: c_int32, f: float):
        return c_int32(min(math.ceil(n.value * f), n.value - 1))


    def __setitem__(self, key, value):
        self._put(c_int64(key), value)


    # public V put(long k, V v) {
    #     int pos = this.find(k);
    #     if (pos < 0) {
    #         this.insert(-pos - 1, k, v);
    #         return this.defRetValue;
    #     } else {
    #         V oldValue = this.value[pos];
    #         this.value[pos] = v;
    #         return oldValue;
    #     }
    # }
    def _put(self, k: c_int64, value):
        pos: c_int32 = self._find(k)
        if pos.value < 0:
            self._insert(c_int32(-pos.value - 1), k, value)
            return self.defaultReturnValue
        
        else:
            old_value = self.value[pos.value]
            self.value[pos.value] = value
            return old_value


    # private int find(long k) {
    #     if (k == 0L) {
    #         return this.containsNullKey ? this.n : -(this.n + 1);
    #     } else {
    #         long[] key = this.key;
    #         long curr;
    #         int pos;
    #         if ((curr = key[pos = (int)HashCommon.mix(k) & this.mask]) == 0L) {
    #             return -(pos + 1);
    #         } else if (k == curr) {
    #             return pos;
    #         } else {
    #             while((curr = key[pos = pos + 1 & this.mask]) != 0L) {
    #                 if (k == curr) {
    #                     return pos;
    #                 }
    #             }

    #             return -(pos + 1);
    #         }
    #     }
    # }
    def _find(self, k: c_int64):
        # log.info(f"{k}")
        if k.value == 0:
            log.debug(f"Adding Null key: {k.value}")
            return c_int32(self.n.value) if self.contains_null_key else c_int32(-(self.n.value + 1))
        else:
            # key = self.key
            pos = c_int32(c_int32(self._mix(k).value).value & self.mask.value)
            curr = self.key[pos.value]

            if curr == 0:
                return c_int32(-(pos.value + 1))
            elif k.value == curr: # has collision does not exist
                return c_int32(pos.value)
            else: # hash collision
                while True:
                    pos = c_int32(pos.value + 1 & self.mask.value)
                    # print(pos.value)
                    curr = self.key[pos.value] #NOTE: Vulnerable if another process modifies self.key 
                    if curr == 0: # found next position to add colliding key
                        break
                    if k.value == curr: #Already exists
                        return c_int32(pos.value)
                
            return c_int32(-(pos.value + 1))


    # private void insert(int pos, long k, V v) {
    #     if (pos == this.n) {
    #         this.containsNullKey = true;
    #     }
    #     this.key[pos] = k;
    #     this.value[pos] = v;
    #     if (this.size++ >= this.maxFill) {
    #         this.rehash(HashCommon.arraySize(this.size + 1, this.f));
    #     }
    # }
    def _insert(self, pos: c_int32, k: c_int64, v):
        if pos.value == self.n.value:
            self.contains_null_key = True 
        
        self.key[pos.value] = k.value
        self.value[pos.value] = v

        self.size.value+=1
        if self.size.value >= self.max_fill.value:
            self._rehash(self._array_size(self.size.value + 1, self.f))

        
    

    # public static long mix(long x) {
    #     long h = x * -7046029254386353131L;
    #     h ^= h >>> 32;
    #     return h ^ h >>> 16;self.size
    # }
    def _mix(self, x: c_int64) -> c_int64:
        h: c_int64 = c_int64(x.value * -7046029254386353131)
        h.value ^= h.value >> 32
        h.value &= 0xFFFFFFFF
        h.value ^= h.value >> 16
        h.value &= 0xFFFF  # Mask to 16 bits
        return h


    # private int realSize() {
    #     return this.containsNullKey ? this.size - 1 : this.size;
    # }
    def _real_size(self):
        assert (isinstance(self.size, c_int32))
        return c_int32(self.size.value - 1) if self.contains_null_key else c_int32(self.size.value)


    # protected void rehash(int newN) {
    #     long[] key = this.key;
    #     V[] value = this.value;
    #     int mask = newN - 1;
    #     long[] newKey = new long[newN + 1];
    #     V[] newValue = new Object[newN + 1];
    #     int i = this.n;

    #     int pos;
    #     for(int j = this.realSize(); j-- != 0; newValue[pos] = value[i]) {
    #         do {
    #             --i;
    #         } while(key[i] == 0L);

    #         if (newKey[pos = (int)HashCommon.mix(key[i]) & mask] != 0L) {
    #             while(newKey[pos = pos + 1 & mask] != 0L) {
    #             }
    #         }

    #         newKey[pos] = key[i];
    #     }

    #     newValue[newN] = value[this.n];
    #     this.n = newN;
    #     this.mask = mask;
    #     this.maxFill = HashCommon.maxFill(this.n, this.f);
    #     this.key = newKey;
    #     this.value = newValue;
    # }
    def _rehash(self, new_n: c_int32):
        log.info(f"Rehashing, reached: {self.max_fill.value}/{self.size.value} elements, old size: {self.n.value}, new size: {new_n.value}")
        mask: c_int32 = c_int32(new_n.value - 1)  
        pos: c_int32 = c_int32(0)
        new_key: list[c_int64] = [0 for _ in range(new_n.value + 1)]
        new_value = [None for _ in range(new_n.value + 1)]
          
        i: c_int32 = c_int32(self.n.value)
        j: c_int32 = self._real_size()
        # new_value[pos.value] = self.value[i.value]
        while j.value != 0:
            j.value -= 1
            while True:
                i.value -= 1
                if not self.key[i.value] == 0:
                    break
            
            pos = c_int32(
                    c_int32(
                            self._mix(c_int64(self.key[i.value])).value
                    ).value & mask.value
                )

            if new_key[pos.value] != 0:
                pos = c_int32(pos.value + 1 & mask.value)
                while new_key[pos.value] != 0:
                    pos = c_int32(pos.value + 1 & mask.value)
            
            new_key[pos.value] = self.key[i.value]
            new_value[pos.value] = self.value[i.value]
            
        
        new_value[new_n.value] = self.value[self.n.value]
        self.n.value = new_n.value
        self.mask.value = mask.value
        self.max_fill.value = self._max_fill(self.n, self.f).value
        self.key = new_key
        self.value = new_value


        
    def __getitem__(self, key):
        return self._get(c_int64(key))
        
    # public V get(long k) {
    #     if (k == 0L) {
    #         return this.containsNullKey ? this.value[this.n] : this.defRetValue;
    #     } else {
    #         long[] key = this.key;
    #         long curr;
    #         int pos;
    #         if ((curr = key[pos = (int)HashCommon.mix(k) & this.mask]) == 0L) {
    #             return this.defRetValue;
    #         } else if (k == curr) {
    #             return this.value[pos];
    #         } else {
    #             while((curr = key[pos = pos + 1 & this.mask]) != 0L) {
    #                 if (k == curr) {
    #                     return this.value[pos];
    #                 }
    #             }

    #             return this.defRetValue;
    #         }
    #     }
    # }
    def _get(self, k: c_int64):
        if k.value == 0:
            return self.value[self.n.value] if self.contains_null_key else self.defaultReturnValue
        else:
            # key = self.key
            pos = c_int32(self._mix(k).value).value & self.mask.value
            curr = self.key[pos]

            if curr == 0:
                return self.defaultReturnValue
            elif k.value == curr:

                return self.value[pos]
            else:
                while True:
                    pos = pos + 1 & self.mask.value
                    curr = self.key[pos]  #NOTE: Vulnerable if self.key is modified by another process
                    if curr == 0:
                        break
                    if k.value == curr:
                        return self.value[pos]

            return self.defaultReturnValue



    def __delitem__(self, key):
        raise NotImplementedError

def load_list_from_json(json_file, key):
    with open(json_file, 'rb') as file:
        parser = ijson.parse(file)
        current_key = ''
        loading_target_list = False
        target_list = []

        for prefix, event, value in parser:
            if event == 'map_key':
                current_key = value
                if current_key == key:
                    loading_target_list = True
                else:
                    loading_target_list = False
            elif loading_target_list and event == 'start_array':
                target_list = []
            elif loading_target_list and event == 'number':
                target_list.append(value)

        return target_list

target_page="3876"      
collisions: list[int] = []
collisions: list[int] = load_list_from_json('collisions.json', target_page)


map_size = 8192 * 0.9
pages = int(map_size)
max_fill = 8192 * 0.9
map = CustomHashMap(initial_size=map_size, load_factor=0.9)

for p in collisions[:int(map_size)+1]:
    map[p] = "AAA"

print(map.key)