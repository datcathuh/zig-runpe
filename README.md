simple runpe / process hollowing from url with string obfuscation — written in zig

## what it does
Loads a payload from a remote URL into memory, obscures string data, and executes it using process hollowing.  
implemented in Zig because i was bored, confirmed to work on zig 0.15.2

## build
1. Install [Zig](https://ziglang.org/download/) (latest stable). 
2. Clone this repository.
3. Open a terminal in the project folder and run:
```bash
zig build