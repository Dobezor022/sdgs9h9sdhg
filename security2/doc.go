// Package security2 implements the FedMes 2.0 endpoint security state machine.
//
// It intentionally uses established cryptographic primitives from the Go standard
// library. FedMes-specific innovation is confined to key separation, state
// transitions, trust generations, opaque capsules, and realtime media epochs.
package security2
