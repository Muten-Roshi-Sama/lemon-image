# Citronics Lemon kernel images

This repository builds the .deb packages for relevant kernel versions to be used on the Lemon board by Citronics.

Implementation following : https://github.com/parastuffs/linux-kernel-modules/wiki


Cross-compiler toolchain from a linux Fedora machine, find all source files inside `/kernel-build`.

## Embedded LKM:
Create and upload a simple module to the citro board.


## Pocket Monster:
The aim is to create a virtual pocket monster living inside the kernel. When the module is loaded, the monster is born, it receives a name and some initial state. As time passes, it becomes hungry, loses energy and its mood can change. When the module is unloaded, the monster disappears cleanly from the kernel.

