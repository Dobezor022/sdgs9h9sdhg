# FedMes Android 32-bit compatibility patch

Upstream module: `github.com/bytemare/ksf v0.5.0` (MIT).

The upstream Argon2id parameter validation passes the untyped constant
`math.MaxUint32` directly to `fmt.Errorf`. During gomobile builds for 32-bit
Android ABIs, the variadic argument is inferred as `int` and overflows.

FedMes keeps the upstream validation semantics and changes only the two error
format arguments to `uint64(math.MaxUint32)`. This permits the same source to
compile for `android/386` and `android/arm` without changing Argon2id output,
parameters, or protocol compatibility.
