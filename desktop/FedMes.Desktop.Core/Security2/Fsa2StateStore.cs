using System.Security.Cryptography;
using FedMes.Desktop.Core.Security;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.Security2;

/// <summary>DPAPI/CNG-backed local envelope for FSA2 state. The file never contains plaintext state.</summary>
public sealed class Fsa2StateStore
{
    private const int MaximumStateBytes = 4 * 1024 * 1024;
    private readonly ISecretProtector _protector;
    private readonly string _path;
    private readonly object _gate = new();

    public Fsa2StateStore(ISecretProtector protector,string? path=null){_protector=protector??throw new ArgumentNullException(nameof(protector));_path=path??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"FedMes","fsa2-state.v1.bin");}
    public void Write(ReadOnlySpan<byte> state){if(state.IsEmpty||state.Length>MaximumStateBytes)throw new ArgumentOutOfRangeException(nameof(state));lock(_gate){byte[] protectedBytes=_protector.Protect(state);try{Directory.CreateDirectory(Path.GetDirectoryName(_path)!);string tmp=_path+"."+Guid.NewGuid().ToString("N")+".tmp";try{using(var f=new FileStream(tmp,FileMode.CreateNew,FileAccess.Write,FileShare.None,64*1024,FileOptions.WriteThrough)){f.Write(protectedBytes);f.Flush(true);}File.Move(tmp,_path,true);}finally{TryDelete(tmp);}}finally{CryptographicOperations.ZeroMemory(protectedBytes);}}}
    public byte[]? Read(){lock(_gate){if(!File.Exists(_path))return null;byte[] p=File.ReadAllBytes(_path);try{if(p.Length>MaximumStateBytes+4096)throw new InvalidDataException("FedMes FSA2 state is too large.");return _protector.Unprotect(p);}finally{CryptographicOperations.ZeroMemory(p);}}}
    public void Clear(){lock(_gate){TryDelete(_path);}}
    private static void TryDelete(string p){try{File.Delete(p);}catch(Exception e) when(e is IOException or UnauthorizedAccessException){}}
}
