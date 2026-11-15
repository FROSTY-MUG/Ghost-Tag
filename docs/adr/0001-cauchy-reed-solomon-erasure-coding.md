# ADR 0001: Cauchy Reed-Solomon Matrix Erasure Coding

## Status
**Accepted** (2026-11-13)

## Context
Ghost-Tag distributes sensitive files across physical NFC tags. Physical tags can be misplaced, physically fractured, or degraded over time. 
Traditional replication (e.g. copying each chunk 2 or 3 times) incurs massive storage overhead, which is prohibitive on memory-constrained NFC chips (typically 144 to 888 bytes per tag).

## Decision
We implement Cauchy Reed-Solomon Erasure Coding over Galois Field $GF(2^8)$:
- A file is partitioned into $K$ data chunks and generates $M$ parity chunks (total $N = K + M$ tags).
- Any $K$ tags collected out of the $N$ total tags allow deterministic and instantaneous mathematical reconstruction of the original file.
- The generator matrix is structured using a Cauchy matrix over $GF(2^8)$, which guarantees that every submatrix is invertible without singular matrix failure edge cases.

## Consequences
### Positive
- Optimal storage efficiency: The storage overhead is strictly $(K + M) / K$, rather than integer multiples.
- Resilience: Up to $M$ damaged or missing tags can be tolerated with 100% data recovery.
- Random-order tapping: The user can tap tags in arbitrary order without sequence constraints.

### Negative
- Requires finite field matrix arithmetic computation during encryption and decoding.
- Maximum number of total tags $N \le 256$ in $GF(2^8)$ (more than sufficient for typical physical tag sets).
