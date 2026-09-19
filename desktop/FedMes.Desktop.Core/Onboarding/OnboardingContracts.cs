namespace FedMes.Desktop.Core.Onboarding;

public enum OnboardingPhase
{
    Ready,
    Scanning,
    Provisioned,
    Failed,
}

public enum OnboardingFailure
{
    None,
    ScannerUnavailable,
    InvitationRejected,
    InvalidFamilyAccount,
    Cancelled,
    UnexpectedFailure,
}

public sealed record OnboardingState(
    OnboardingPhase Phase,
    string? ProvisionedUserName = null,
    OnboardingFailure Failure = OnboardingFailure.None)
{
    public static OnboardingState Ready { get; } = new(OnboardingPhase.Ready);

    public bool CanStartQrScan => Phase is OnboardingPhase.Ready or OnboardingPhase.Failed;
}

public sealed record QrOnboardingResult(
    bool IsSuccess,
    string? UserName,
    OnboardingFailure Failure)
{
    public static QrOnboardingResult Success(string userName) =>
        new(true, userName, OnboardingFailure.None);

    public static QrOnboardingResult Rejected(OnboardingFailure failure)
    {
        if (failure == OnboardingFailure.None)
        {
            throw new ArgumentOutOfRangeException(nameof(failure), "A rejected result requires a failure code.");
        }

        return new(false, null, failure);
    }
}

public interface IQrOnboardingService
{
    Task<QrOnboardingResult> ScanAndRedeemAsync(CancellationToken cancellationToken);
}
