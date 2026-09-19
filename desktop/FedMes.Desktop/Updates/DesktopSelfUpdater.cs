using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace FedMes.Desktop.Updates;

public static class DesktopSelfUpdater
{
    public static void Launch(string downloadedExecutable)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(downloadedExecutable);
        if (!File.Exists(downloadedExecutable)) throw new FileNotFoundException("Файл обновления не найден.", downloadedExecutable);
        string currentExecutable = Environment.ProcessPath
            ?? throw new InvalidOperationException("Не удалось определить путь текущего FedMes.exe.");
        string script = Path.Combine(Path.GetTempPath(), $"fedmes-update-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(script, UpdateScript, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        if (!CanWriteDirectory(Path.GetDirectoryName(currentExecutable)!))
        {
            start.Verb = "runas";
        }
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(script);
        start.ArgumentList.Add("-PidToWait");
        start.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        start.ArgumentList.Add("-Source");
        start.ArgumentList.Add(downloadedExecutable);
        start.ArgumentList.Add("-Destination");
        start.ArgumentList.Add(currentExecutable);
        using Process process = Process.Start(start)
            ?? throw new InvalidOperationException("Не удалось запустить установщик обновления.");
    }

    private static bool CanWriteDirectory(string directory)
    {
        try
        {
            string probe = Path.Combine(directory, $".fedmes-write-{Guid.NewGuid():N}");
            using (File.Create(probe, 1, FileOptions.DeleteOnClose))
            {
            }
            return true;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private const string UpdateScript = """
param(
    [Parameter(Mandatory=$true)][int]$PidToWait,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
try { Wait-Process -Id $PidToWait -Timeout 60 -ErrorAction SilentlyContinue } catch {}
$backup = $Destination + '.previous'
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    try {
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        if (Test-Path -LiteralPath $Destination) { Move-Item -LiteralPath $Destination -Destination $backup -Force }
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        Start-Process -FilePath $Destination
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        exit 0
    } catch {
        if ((Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $Destination)) {
            Move-Item -LiteralPath $backup -Destination $Destination -Force
        }
        Start-Sleep -Milliseconds 500
    }
}
throw 'Не удалось заменить FedMes.Desktop.exe.'
""";
}
