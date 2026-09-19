using System.Security.Cryptography;
using System.Text;
using FedMes.Desktop.Core.CryptoCore;
using FedMes.Desktop.Core.Transport2;

namespace FedMes.Desktop.Core.Security2;

/// <summary>FedMes 2.0 opaque event send/receive path for Windows.</summary>
public sealed class Fsa2MessageEngine
{
    private readonly FedMesSecurity2Client _core;
    private readonly BlindObjectClient _transport;
    public Fsa2MessageEngine(FedMesSecurity2Client core, BlindObjectClient transport){_core=core;_transport=transport;}

    public async Task<(S2RatchetState State,string ObjectId)> SendAsync(Uri server,S2RatchetState state,ReadOnlyMemory<byte> routeCapability,long transportEpoch,ReadOnlyMemory<byte> eventBytes,CancellationToken ct)
    {
        if(routeCapability.Length!=32||eventBytes.IsEmpty)throw new ArgumentException("invalid FSA2 event");
        string cap=Raw(routeCapability.Span);string plain=Raw(eventBytes.Span);int pad=PaddingTarget(eventBytes.Length+4);
        S2CapsuleResult encrypted=await _core.EncryptCapsuleAsync(state,cap,transportEpoch,plain,pad,ct).ConfigureAwait(false);
        string id=BlindObjectClient.RandomObjectId();byte[] capsuleJson=Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(encrypted.Capsule));
        try{await _transport.PutAsync(server,cap,id,encrypted.Capsule.LengthClass,Raw(capsuleJson),ct).ConfigureAwait(false);}finally{CryptographicOperations.ZeroMemory(capsuleJson);}
        return(encrypted.State,id);
    }

    public async Task<(S2RatchetState State,byte[] Plaintext,string ObjectId)?> ReceiveOneAsync(Uri server,S2RatchetState state,ReadOnlyMemory<byte> routeCapability,long transportEpoch,CancellationToken ct)
    {
        if(routeCapability.Length!=32)throw new ArgumentException("invalid route capability");string cap=Raw(routeCapability.Span);var objects=await _transport.PullAsync(server,cap,1,ct).ConfigureAwait(false);if(objects.Count==0)return null;var cell=objects[0];byte[] capsuleBytes=DecodeRaw(cell.Ciphertext);try{var capsule=System.Text.Json.JsonSerializer.Deserialize<S2Capsule>(capsuleBytes)??throw new CryptographicException("invalid FSA2 capsule");S2PlainResult result=await _core.DecryptCapsuleAsync(state,capsule,cap,transportEpoch,ct).ConfigureAwait(false);byte[] plaintext=DecodeRaw(result.Plaintext);await _transport.AckAsync(server,cap,cell.ObjectId,ct).ConfigureAwait(false);return(result.State,plaintext,cell.ObjectId);}finally{CryptographicOperations.ZeroMemory(capsuleBytes);}
    }

    private static int PaddingTarget(int n)=>n<=256?256:n<=1024?1024:n<=4096?4096:n<=16384?16384:n<=65536?65536:checked(((n+65535)/65536)*65536);
    private static string Raw(ReadOnlySpan<byte> b)=>Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
    private static byte[] DecodeRaw(string s){string p=s.Replace('-','+').Replace('_','/');p+=new string('=',(4-p.Length%4)%4);return Convert.FromBase64String(p);}
}
