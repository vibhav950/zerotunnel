# Specification changelog

All notable changes to any of the specifications MUST be documented in this file. This changelog records change by description, and a seperate changelog must be maintained for implementation changes in the codebase.

## [KAPPA - Revision 1.1] - 2-12-25

### Added

- Added a block cipher algorithm to the list of KAPPA parameters. This is different from the AEAD algorithm and does not provide implicit authentication. 

### Changed

- AEAD encryption of the initiator PQ-KEM public key has been replaced with un-authenticated encryption to prevent offline brute-force attacks on the master password.

## [KAPPA - Revision 1.2] - 2-16-25

### Changed

- Fixed a severe flaw in the protocol where the entire Kyber key share was being encrypted with AES. This made the keys vulnerable to brute-force attacks due to the bias in the plaintext space since the Kyber parameter t in the public share (rho, t) is a vector containing elements in a modulo ring. As a result, not all decryptions will give valid Kyber keys allowing for offline rejection of candidate passwords during a brute-force search for the password.
