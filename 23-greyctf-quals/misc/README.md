# MISC
Sources for challs: https://github.com/NUSGreyhats/greyctf23-challs-public/tree/main/misc
## CrashPython

> I am hosting an uncrashable Python executor API. Crash it to get the flag.
>
> Author: Junhua
>
> points: 50
>
> flag: grey{pyth0n-cv3-2021-3177_0r_n0t?_cd924ee8df15912dd55c718685517d24}

**Tags**: python segmentation fault

```python
import ctypes
ctypes.string_at(0)
```

## Gotcha

> I have designed my own Captcha. If you solve it fast enough I'll give you my flag. Can you help me test it?
>
> Author: Junhua
>
> points: 50
>
> flag: grey{I_4m_hum4n_n0w_059e3995f03a783dae82580ec144ad16}

**Tags**: captcha

```python
import cv2
from pytesseract import image_to_string
import base64
import requests
from bs4 import BeautifulSoup as BSHTML
import re
import time
import numpy as np
from unidecode import unidecode

home = "http://34.124.157.94:5003/"
submit = "http://34.124.157.94:5003/submit"


if __name__ == '__main__':
    s = requests.Session()
    score = 0
    r = s.get(home)
    limit = 120
    start_t = time.time()

    while True:
        
        match = re.search("<h3>.*?</h3>", r.text, re.IGNORECASE | re.MULTILINE)
        
        try :
            score = match.group().strip('<h3>').strip('</h3>').strip('Score: ')
            score = int(score)
        except ValueError:
            print(f"WHY? {match.group()}")
            score = 0

        print(f"Score: {score} {time.time() - start_t} / {limit}")

        soup = BSHTML(r.text, "html.parser")
        images = soup.findAll('img')

        for image in images:
            img_data = image['src'].split(',')[1]

        with open("imageToSave.png", "wb") as fh:
            fh.write(base64.b64decode(img_data))

        img = cv2.imread("imageToSave.png")
        img = cv2.resize(img, None, fx=1.2, fy=1.2, interpolation=cv2.INTER_CUBIC)
        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        kernel = np.ones((1, 1), np.uint8)
        img = cv2.dilate(img, kernel, iterations=1)
        img = cv2.erode(img, kernel, iterations=1)
        
        # TODO: Test ONE of the following if not accurate
        # cv2.threshold(cv2.bilateralFilter(img, 5, 75, 75), 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        # cv2.threshold(cv2.medianBlur(img, 3), 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        cv2.adaptiveThreshold(cv2.bilateralFilter(img, 9, 75, 75), 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 2)
        # cv2.adaptiveThreshold(cv2.medianBlur(img, 3), 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 2)

        # cv2.imshow('Gray image', img)
        # cv2.waitKey()

        txt = image_to_string(img, lang='eng', config="-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ --psm 6") # TODO: maybe try psm 8 also
        txt = unidecode(txt.strip())
        print(txt.encode())

        data_t = {
            "captcha": txt.upper()
        }

        r = s.post(submit, data=data_t)
        if score >= 100:
            print(r.text)
            break
```

## beepboop

> beep boop you have a message from the radio waves beep boop
>
> Warning: File may be loud!
>
> Note: if you have GREY SOME FLAG, submit grey{some_flag}
>
> Author: jiefeng
>
> points: 460
>
> flag: grey{try_r3c31v1ing_fr0m_th3_a1r_cq09wecj90qso}

**Tags**: Forensics, RTTY

- tool: `FLDIGI`

Open in FLDIGI with opcode `RTTY-750W`. Get flag!





