# Writeup: Escaping the Maze Challenge

## Introduction

In this challenge, we were presented with an executable file named `maze`, which appeared to be a PyInstaller-compiled Python application. Our goal was to reverse engineer the application, navigate through layers of obfuscation, and ultimately retrieve the hidden flag.

This writeup documents the steps taken to solve the challenge, from decompiling the PyInstaller executable to reversing an ELF binary and extracting the final key.

---

## Step 1: Decompiling the PyInstaller Executable

### Extracting Contents from the Executable

PyInstaller executables bundle Python bytecode in a packed format. To extract the contents, we used the `pyinstxtractor` script:

```bash
python pyinstxtractor.py maze
```

This produced a directory containing the extracted files, including `obf_path.pyc` and other Python bytecode files.

### Decompiling the Extracted Bytecode

We decompiled the `.pyc` files using `uncompyle6`:

```bash
uncompyle6 obf_path.pyc > obf_path.py
```

---

## Step 2: Analyzing `maze` Script

Upon inspecting the decompiled code, we found that the main functionality was in a script that manipulated the `maze` file and produced a `dec_maze` file.

The code snippet responsible for this was:

```python
with open("maze", "rb") as file:
    content = file.read()
data = bytearray(content)
data = [x for x in data]
key = [0] * len(data)
for i in range(0, len(data), 10):
    data[i] = (data[i] + 80) % 256
else:
    for i in range(0, len(data), 10):
        data[i] = (data[i] ^ key[i % len(key)]) % 256
    else:
        with open("dec_maze", "wb") as f:
            for b in data:
                f.write(bytes([b]))
```

We noticed that the `key` was initialized to zeros, and XORing with zero doesn't change the data. This suggested that the actual key was supposed to be derived elsewhere.

---

## Step 3: Decompiling `obf_path.pyc`

We turned our attention to `obf_path.pyc`, which seemed to be obfuscated. The decompiled code contained an `exec` call with a base64-encoded and compressed byte string.

### Extracting and Decompressing the Embedded Code

We extracted the byte string and wrote a script to decompress and unmarshal it:

```python
import marshal
import zlib
import lzma

# Extracted byte string from the `exec` call
compressed_data = b'...'

# Decompress with lzma
lzma_decompressed = lzma.decompress(compressed_data)

# Decompress with zlib
zlib_decompressed = zlib.decompress(lzma_decompressed)

# Load the code object
code_object = marshal.loads(zlib_decompressed)
```

We then wrote the code object to a `.pyc` file with the correct magic number for Python 3.8:

```python
import struct

with open('obfuscated_code.pyc', 'wb') as f:
    f.write(b'\x42\x0d\x0d\x0a')  # Magic number for Python 3.8
    f.write(struct.pack('I', 0))  # Timestamp
    marshal.dump(code_object, f)
```

Finally, we decompiled it using `uncompyle6`:

```bash
uncompyle6 obfuscated_code.pyc > obfuscated_code.py
```

---

## Step 4: Analyzing the Deobfuscated Code

The decompiled `obfuscated_code.py` revealed a script that performed several checks and printed messages:

```python
import os, sys
from time import sleep

path = sys.argv[0]
current_directory = os.getcwd()
index_file = "maze.png"

if ".py" in path:
    print("Ignoring the problem won't make it disappear;")
    print("confronting and addressing it is the true path to resolution.")
    sys.exit(0)

if not os.path.exists(os.path.join(current_directory, index_file)):
    print("Ok that's good but I guess that u should now return from the previous path")
    sys.exit(0)

index = open(index_file, "rb").read()
seed = index[4817] + index[2624] + index[2640] + index[2720]

print("\n\nG00d!! you could escape the obfuscated path")
print("take this it may help you: ")
sleep(2)
print(f"\nseed({seed})\nfor i in range(300):\n    randint(32,125)\n")
print("Be Careful!!!! the route from here is not safe.")
sys.exit(0)
```

The script hinted that we needed to:

1. Ensure `maze.png` is present in the current directory.
2. Calculate a `seed` from specific bytes of `maze.png`.
3. Use this seed to generate random numbers.

---

## Step 5: Generating the Random Numbers

We wrote a script to compute the seed and generate the random numbers:

```python
import random

# Read maze.png and compute the seed
with open('maze.png', 'rb') as f:
    index = f.read()

positions = [4817, 2624, 2640, 2720]
seed = sum(index[pos - 1] for pos in positions)
print(f"Computed seed: {seed}")

# Seed the random number generator
random.seed(seed)

# Generate 300 random integers between 32 and 125
random_numbers = [random.randint(32, 125) for _ in range(300)]
```

---

## Step 6: Deciphering the Output

From earlier steps, we had an output string that seemed garbled:

```
@wFj@M`nuK_%uA;oFD>hatWzlM3KFd=/'n"mazOu+}"kF+l'pw=/YN,.w,=upup>6{m.QI8cXf:G4u8U'...
```

We realized that this output might be the result of encrypting or encoding the flag, possibly using the random numbers we generated.

### Combining the Random Numbers with the Decryption Process

We revisited the initial decryption process in the `maze` script and modified it to use the random numbers as the key:

```python
# Ensure the key is the same length as data
key_length = len(random_numbers)
data_length = len(data)
if key_length < data_length:
    key = (random_numbers * (data_length // key_length + 1))[:data_length]
else:
    key = random_numbers[:data_length]

# Process data using the key
for i in range(0, len(data), 10):
    data[i] = (data[i] + 80) % 256

for i in range(0, len(data), 10):
    data[i] = (data[i] ^ key[i]) % 256
```

We then wrote the processed data to `dec_maze`.

---

## Step 7: Analyzing `dec_maze`

After generating `dec_maze`, we checked its file type:

```bash
file dec_maze
```

It turned out to be an ELF executable file.

---

## Step 8: Reverse Engineering the ELF Binary

We executed `dec_maze` and observed that it prompted for input. Suspecting it contained the final flag verification logic, we loaded it into IDA Pro for analysis.

### Understanding the Verification Logic

The main function in the binary compared the user input against an encrypted key using the following logic:

```c
v4 &= (input[i - 1] + input[i] + input[i + 1]) == encrypted[i - 1];
```

The encrypted key was stored as an array of DWORDs.

### Reconstructing the Key

We wrote an IDA Python script to reverse the encryption and recover the key:

```python
from idc import *
from idaapi import *

input_chars = [ord('H'), ord('T'), ord('B')]

encrypted_addr = 0x00404000  # Address of 'encrypted'
encrypted_count = 20         # Number of DWORDs in 'encrypted'

encrypted_data = []
for i in range(encrypted_count):
    dword_value = get_wide_dword(encrypted_addr + i * 4)
    encrypted_data.append(dword_value)

for i in range(encrypted_count):
    next_char = (encrypted_data[i] - input_chars[i] - input_chars[i + 1]) % 256
    input_chars.append(next_char)

key = ''.join(chr(c) for c in input_chars)

print("Recovered Key: {}".format(key))
```

---

## Step 9: Retrieving the Final Flag

Executing the script yielded the key:

```
HTB{some_freaking_key}
```

This was the flag we were looking for.

---

## Conclusion

Through methodical analysis and reverse engineering, we successfully navigated through multiple layers of obfuscation and encryption to retrieve the hidden flag. The challenge tested our skills in decompiling Python bytecode, interpreting obfuscated code, and reversing binary executables.

---

## Key Takeaways

- **Decompiling PyInstaller Executables**: Using tools like `pyinstxtractor` and `uncompyle6` can help retrieve source code from compiled Python executables.
- **Handling Obfuscated Code**: Patience and careful analysis are required when dealing with obfuscated scripts, especially those that execute embedded code.
- **Combining Clues Across Steps**: Sometimes, solutions require integrating information from different parts of a challenge.
- **Reversing Binaries**: Understanding assembly code and writing scripts in IDA Pro can greatly aid in reversing compiled binaries.

---****
