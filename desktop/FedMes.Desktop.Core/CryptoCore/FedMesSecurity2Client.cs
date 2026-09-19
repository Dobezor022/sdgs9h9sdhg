using System.Text.Json.Serialization;

namespace FedMes.Desktop.Core.CryptoCore;

/// <summary>
/// Typed Windows bridge to the shared FedMes 2.0 FSA2 core.
/// No cryptographic primitive is reimplemented in C#; Android and Windows use
/// the same Go core and therefore the same state transitions and wire format.
/// </summary>
public sealed class FedMesSecurity2Client
{
    private readonly FedMesCryptoWorkerClient _worker;
    public FedMesSecurity2Client(FedMesCryptoWorkerClient worker) => _worker = worker;

    public Task<string> VersionAsync(CancellationToken ct) =>
        _worker.InvokeAsync("security2.version", new { }, ct);

    public Task<S2UserRoot> GenerateUserRootAsync(CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2UserRoot>("security2.identity.user_root.generate", new { }, ct);

    public Task<S2DeviceIdentity> GenerateDeviceIdentityAsync(CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2DeviceIdentity>("security2.identity.device.generate", new { }, ct);

    public Task<string> SharedSecretAsync(string localPrivate, string peerPublic, CancellationToken ct) =>
        _worker.InvokeAsync("security2.identity.shared_secret", new { local_private = localPrivate, peer_public = peerPublic }, ct);

    public Task<S2RatchetState> NewRatchetAsync(string seed, string domain, long generation, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2RatchetState>("security2.ratchet.new", new { seed, domain, generation }, ct);

    public Task<S2CapsuleResult> EncryptCapsuleAsync(S2RatchetState state, string route, long transportEpoch, string plaintext, int padTo, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2CapsuleResult>("security2.capsule.encrypt", new {
            state = Json(state), route, transport_epoch = transportEpoch, plaintext, pad_to = padTo
        }, ct);

    public Task<S2PlainResult> DecryptCapsuleAsync(S2RatchetState state, S2Capsule capsule, string route, long transportEpoch, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2PlainResult>("security2.capsule.decrypt", new {
            state = Json(state), capsule = Json(capsule), route, transport_epoch = transportEpoch
        }, ct);

    public Task<S2RatchetState> HealRatchetAsync(S2RatchetState state, string shared, string transcript, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2RatchetState>("security2.ratchet.heal", new { state = Json(state), shared, transcript }, ct);

    public Task<string> NewCallRootAsync(string shared, string transcript, CancellationToken ct) =>
        _worker.InvokeAsync("security2.call.root", new { shared, transcript }, ct);

    public Task<string> MediaEpochKeyAsync(string callRoot, int domain, int direction, long epoch, string fresh, CancellationToken ct) =>
        _worker.InvokeAsync("security2.call.media_epoch", new { call_root = callRoot, domain, direction, epoch, fresh }, ct);

    public Task<S2MediaPacket> EncryptMediaAsync(string epochKey, string route, long epoch, long sequence, string plaintext, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2MediaPacket>("security2.call.media_encrypt", new { epoch_key = epochKey, route, epoch, sequence, plaintext }, ct);

    public Task<string> DecryptMediaAsync(string epochKey, string route, S2MediaPacket packet, CancellationToken ct) =>
        _worker.InvokeAsync("security2.call.media_decrypt", new { epoch_key = epochKey, route, packet = Json(packet) }, ct);

    public Task<string> DeriveFileRootAsync(string seed, string fileId, CancellationToken ct) =>
        _worker.InvokeAsync("security2.blob.file_root", new { seed, file_id = fileId }, ct);

    public Task<string> EncryptChunkAsync(string root, string fileId, long index, string data, CancellationToken ct) =>
        _worker.InvokeAsync("security2.blob.encrypt_chunk", new { root, file_id = fileId, index, data }, ct);

    public Task<string> DecryptChunkAsync(string root, string fileId, long index, string data, CancellationToken ct) =>
        _worker.InvokeAsync("security2.blob.decrypt_chunk", new { root, file_id = fileId, index, data }, ct);

    public Task<S2AdmissionRequest> NewAdmissionAsync(string userRootId, long generation, long securityEpoch, S2TrustedDevice device, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2AdmissionRequest>("security2.admission.new", new {
            user_root_id = userRootId, generation, security_epoch = securityEpoch, device = Json(device)
        }, ct);

    public Task<string> AdmissionCodeAsync(S2AdmissionRequest request, CancellationToken ct) =>
        _worker.InvokeAsync("security2.admission.code", new { request = Json(request) }, ct);

    public Task<S2DeviceApproval> ApproveAdmissionAsync(S2AdmissionRequest request, string approverDeviceId, string signPrivate, CancellationToken ct) =>
        _worker.InvokeJsonAsync<S2DeviceApproval>("security2.admission.approve", new {
            request = Json(request), approver_device_id = approverDeviceId, sign_private = signPrivate
        }, ct);

    private static string Json<T>(T value) => System.Text.Json.JsonSerializer.Serialize(value);
}

public sealed record S2UserRoot(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("sign_public")] string SignPublic,
    [property: JsonPropertyName("sign_private")] string SignPrivate);

public sealed record S2DeviceIdentity(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("sign_public")] string SignPublic,
    [property: JsonPropertyName("sign_private")] string SignPrivate,
    [property: JsonPropertyName("agreement_public")] string AgreementPublic,
    [property: JsonPropertyName("agreement_private")] string AgreementPrivate);

public sealed record S2RatchetState(
    [property: JsonPropertyName("version")] ushort Version,
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("root_key")] string RootKey,
    [property: JsonPropertyName("chain_key")] string ChainKey,
    [property: JsonPropertyName("counter")] ulong Counter,
    [property: JsonPropertyName("generation")] ulong Generation);

public sealed record S2Capsule(
    [property: JsonPropertyName("version")] ushort Version,
    [property: JsonPropertyName("route")] string Route,
    [property: JsonPropertyName("transport_epoch")] ulong TransportEpoch,
    [property: JsonPropertyName("generation")] ulong Generation,
    [property: JsonPropertyName("position")] ulong Position,
    [property: JsonPropertyName("length_class")] ushort LengthClass,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("ciphertext")] string Ciphertext);

public sealed record S2CapsuleResult(
    [property: JsonPropertyName("state")] S2RatchetState State,
    [property: JsonPropertyName("capsule")] S2Capsule Capsule);

public sealed record S2PlainResult(
    [property: JsonPropertyName("state")] S2RatchetState State,
    [property: JsonPropertyName("plaintext")] string Plaintext);

public sealed record S2MediaPacket(
    [property: JsonPropertyName("route")] string Route,
    [property: JsonPropertyName("epoch")] ulong Epoch,
    [property: JsonPropertyName("sequence")] ulong Sequence,
    [property: JsonPropertyName("ciphertext")] string Ciphertext);

public sealed record S2TrustedDevice(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("sign_public")] string SignPublic,
    [property: JsonPropertyName("agreement_public")] string AgreementPublic,
    [property: JsonPropertyName("status")] byte Status,
    [property: JsonPropertyName("admitted_at_generation")] ulong AdmittedAtGeneration);

public sealed record S2AdmissionRequest(
    [property: JsonPropertyName("user_root_id")] string UserRootId,
    [property: JsonPropertyName("current_generation")] ulong CurrentGeneration,
    [property: JsonPropertyName("security_epoch")] ulong SecurityEpoch,
    [property: JsonPropertyName("device")] S2TrustedDevice Device,
    [property: JsonPropertyName("nonce")] string Nonce);

public sealed record S2DeviceApproval(
    [property: JsonPropertyName("device_id")] string DeviceId,
    [property: JsonPropertyName("signature")] string Signature);
