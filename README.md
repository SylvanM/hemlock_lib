# Hemlock

Hemlock is a security application that enables an individual or organization to split a document among multiple semi-trusted parties. 
It is primarily for data that only needs to be accessed in an unlikely event. (E.g., a company is being sued and needs to produce 
sensitive records for evidence, a family member has passed away and legal documents they left behind need to be activated, or 
you for some reason need to authorize a nuclear launch.)

## What's this repository?

`hemlock_lib` is the Rust library that implements all the basic functionality of the application *except* a UI, because I'm bad at designing UI's.
My attempt at creating a UI for macOS can be found [here](https://github.com/SylvanM/Hemlock). I have included a C header file that allows the core
components of the library to be called from C code, for portability. (Not everyone uses Rust yet, even if they should.)


