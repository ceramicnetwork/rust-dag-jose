# Rust DAG-JOSE

A Rust implementation of the [IPLD DAG-JOSE specification](https://ipld.io/specs/codecs/dag-jose/spec/) that can be used in conjunction with [libipld](https://github.com/ipld/libipld).


## Contributing

We are happy to accept small and large contributions, feel free to make a suggestion or submit a pull request.

Use the provided `Makefile` for basic actions to ensure your changes are ready for CI.

    $ make build
    $ make check-clippy
    $ make check-fmt
    $ make test

Using the makefile is not necessary during your developement cycle, feel free to use the relvant cargo commands directly.
However running `make` before publishing a PR will provide a good signal if you PR will pass CI.


## License

Fully open source and dual-licensed under MIT and Apache 2.
