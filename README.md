**socketh-utils** provides a set of networking tools implemented using the `socket.h` library. These tools are designed for Linux users and include capabilities like ARP spoofing. To compile the project using the GCC compiler, simply run `make compile` in the terminal. If you'd like to clean up the generated files, run `make clean`. The ARP spoofing tool can be executed with the following command:

```
./arpspoof <INTERFACE> <TARGET_IP> <GATEWAY_IP>
```

Note: If you compile the program manually without the makefile, you'll need to use `sudo` to execute the tools.