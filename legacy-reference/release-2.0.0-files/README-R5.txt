FedMes 2.0.0 Windows Build Hotfix R5

IMPORTANT: This archive has NO wrapper directory.
Extract it directly into the FedMes project root (for example C:\Fedmes2) with -Force.
It cumulatively contains:
- CA1512 fix in AccountVaultCrypto.cs
- Recovery CryptographicException normalization
- CA1822 fix in WindowsRatchetMessageCrypto.cs
- FedUI2 VisualTreeHelper.GetDpi(this) fix
- forced removal of desktop bin/obj before windowsclient build
