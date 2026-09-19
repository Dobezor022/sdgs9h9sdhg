using FedMes.Desktop.Core.Domain;

namespace FedMes.Desktop.Core.Onboarding;

public sealed class OnboardingController
{
    private readonly IQrOnboardingService _service;
    private readonly object _stateLock = new();
    private OnboardingState _state = OnboardingState.Ready;
    private bool _operationActive;

    public OnboardingController(IQrOnboardingService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
    }

    public event EventHandler<OnboardingState>? StateChanged;

    public OnboardingState State
    {
        get
        {
            lock (_stateLock)
            {
                return _state;
            }
        }
    }

    public async Task<bool> StartQrOnboardingAsync(CancellationToken cancellationToken = default)
    {
        lock (_stateLock)
        {
            if (_operationActive || !_state.CanStartQrScan)
            {
                return false;
            }

            _operationActive = true;
        }

        SetState(new OnboardingState(OnboardingPhase.Scanning));

        try
        {
            QrOnboardingResult result = await _service
                .ScanAndRedeemAsync(cancellationToken)
                .ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                OnboardingFailure failure = result.Failure == OnboardingFailure.None
                    ? OnboardingFailure.UnexpectedFailure
                    : result.Failure;
                SetState(new OnboardingState(OnboardingPhase.Failed, Failure: failure));
                return true;
            }

            if (!FixedFamilyUsers.IsAllowed(result.UserName))
            {
                SetState(new OnboardingState(
                    OnboardingPhase.Failed,
                    Failure: OnboardingFailure.InvalidFamilyAccount));
                return true;
            }

            SetState(new OnboardingState(
                OnboardingPhase.Provisioned,
                FixedFamilyUsers.RequireAllowed(result.UserName!)));
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            SetState(new OnboardingState(
                OnboardingPhase.Failed,
                Failure: OnboardingFailure.Cancelled));
            return true;
        }
        catch
        {
            // Exception messages may contain provider data. Expose only a fixed error code.
            SetState(new OnboardingState(
                OnboardingPhase.Failed,
                Failure: OnboardingFailure.UnexpectedFailure));
            return true;
        }
        finally
        {
            lock (_stateLock)
            {
                _operationActive = false;
            }
        }
    }

    private void SetState(OnboardingState state)
    {
        lock (_stateLock)
        {
            _state = state;
        }

        StateChanged?.Invoke(this, state);
    }
}
