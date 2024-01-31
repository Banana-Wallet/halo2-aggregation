# Halo2 Aggregation circuit for N Groth16 proofs

To run the tests

```
cargo test --release -- --nocapture
```

Currently its taking 364.5s for aggregating two groth16 proofs. This time if for running the code in my M1 Macbook Pro(8 Gb RAM). 

You will get the following output when you run the tests.

```
running 1 test
p1_p2_p3_p4 Fq12 { c0: Fq6 { c0: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000001, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c1: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c2: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 } }, c1: Fq6 { c0: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c1: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c2: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 } } }
test test_pairing_circuit has been running for over 60 seconds
Gate Chip | Phase 0: 25336601 advice cells
Total 202 fixed cells
Total range check advice cells to lookup per phase: [2631220, 0, 0]
Elapsed time in proof generation: 364.560696792s
test test_pairing_circuit ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 534.64s
```

Running Halo2 Aggregation in c6a.32xlarge machine with 128 vCPU and 256gb RAM

```
Running groth16 aggregation
p1_p2_p3_p4 Fq12 { c0: Fq6 { c0: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000001, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c1: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c2: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 } }, c1: Fq6 { c0: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c1: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 }, c2: Fq2 { c0: 0x0000000000000000000000000000000000000000000000000000000000000000, c1: 0x0000000000000000000000000000000000000000000000000000000000000000 } } }


Gate Chip | Phase 0: 25336601 advice cells
Total 202 fixed cells
Total range check advice cells to lookup per phase: [2631220, 0, 0]
Elapsed time in proof generation: 322.089379927s
```
