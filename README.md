# bcrypter
bcrypter is a C++ class wrapper around the Windows CryptoAPI with two goals:

* Leverage classes to store/manipulate variables the developer otherwise has to juggle
* Flexible usage *while retaining granular control*

## Status

**This project is currently under development. *Do not attempt to use in production yet.***

Sorry, guys. When it's a one-man project, my code reflects it.

## Building

Pretty sure this requires C++17, so... use /std:c++latest in VS.

## Usage

(Example usage is in bcrypttest.cpp. main2() is derived from Microsoft's example, and main() is the same code leveraging BCrypter)

## Roadmap/TODO
#### One-Time
- [ ] Complete/Stabilize existing code (currently breaks on Line 48 of bcrypttest.cpp: BCrypter::GenerateSymmetricKey())
- [ ] Clean up mess (from hotswapping code and debugging)
- [ ] Move functions to the right files (currently split between bcrypter.h & bcrypter.cpp)
- [ ] Slim down BCrypter struct
- [ ] Add "workflow" functions (multiple bcrypt.h functions in one)
- [ ] Write to lower version of C++ (optional)
- [ ] Rely on fewer dependencies (optional)
#### Continuous
- [ ] Add support for more bcrypt.h functions
- [ ] Support more use cases (e.g., add more templates)
- [ ] Optimize (e.g., make conversions modular, maybe dynamically convert between supplied and needed object types on any BCrypter call.)

## Contributing
Pull requests are welcome and appreciated.

## License
Modified [GNU AGPLv3](https://choosealicense.com/licenses/agpl-3.0/)

* All improvements must be pushed to this repository or otherwise made equally available to the public
* Commercial use or offering is not permitted whatsoever
