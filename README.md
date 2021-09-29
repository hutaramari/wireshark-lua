# Description
This bea lua scipt is used for dissecting BEA public protocol in Wireshark.

# Features
* Support UDP protocol only
* Support fixed port number for UDP, but be able to change in script directly


# Usage


1. Copy file bea.lua to Wireshark directory. For example, "C:\Programe Files\Wireshark\"

2. Open file init.lua in Wireshark directory, add below line to the end of the file
```
    dofile(DATA_DIR.."bea.lua")
```
3. If need to change dissector port number, open bea.lua file, change PORT variable
```
    -- You can change the port number here
    PORT = 50020
```
