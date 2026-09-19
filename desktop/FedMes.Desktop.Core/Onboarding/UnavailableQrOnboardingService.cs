namespace FedMes.Desktop.Core.Onboarding;

public sealed class UnavailableQrOnboardingService : IQrOnboardingService
{
    public Task<QrOnboardingResult> ScanAndRedeemAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(QrOnboardingResult.Rejected(OnboardingFailure.ScannerUnavailable));
    }
}
