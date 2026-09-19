using FedMes.Desktop.Core.Onboarding;

namespace FedMes.Desktop.Tests.Onboarding;

[TestClass]
public sealed class OnboardingControllerTests
{
    [TestMethod]
    public async Task StartQrOnboardingAsyncProvisionedForAllowedUser()
    {
        var service = new StubQrOnboardingService(QrOnboardingResult.Success("mama"));
        var controller = new OnboardingController(service);

        bool started = await controller.StartQrOnboardingAsync();

        Assert.IsTrue(started);
        Assert.AreEqual(OnboardingPhase.Provisioned, controller.State.Phase);
        Assert.AreEqual("mama", controller.State.ProvisionedUserName);
        Assert.AreEqual(OnboardingFailure.None, controller.State.Failure);
    }

    [TestMethod]
    public async Task StartQrOnboardingAsyncRejectsUnknownUser()
    {
        var service = new StubQrOnboardingService(QrOnboardingResult.Success("mallory"));
        var controller = new OnboardingController(service);

        await controller.StartQrOnboardingAsync();

        Assert.AreEqual(OnboardingPhase.Failed, controller.State.Phase);
        Assert.AreEqual(OnboardingFailure.InvalidFamilyAccount, controller.State.Failure);
        Assert.IsNull(controller.State.ProvisionedUserName);
    }

    [TestMethod]
    public async Task StartQrOnboardingAsyncDoesNotExposeProviderException()
    {
        var controller = new OnboardingController(new ThrowingQrOnboardingService());

        await controller.StartQrOnboardingAsync();

        Assert.AreEqual(OnboardingPhase.Failed, controller.State.Phase);
        Assert.AreEqual(OnboardingFailure.UnexpectedFailure, controller.State.Failure);
    }

    [TestMethod]
    public async Task StartQrOnboardingAsyncAllowsOnlyOneActiveOperation()
    {
        var service = new ControllableQrOnboardingService();
        var controller = new OnboardingController(service);

        Task<bool> first = controller.StartQrOnboardingAsync();
        await service.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        bool second = await controller.StartQrOnboardingAsync();
        service.Complete(QrOnboardingResult.Rejected(OnboardingFailure.InvitationRejected));

        Assert.IsFalse(second);
        Assert.IsTrue(await first);
        Assert.AreEqual(1, service.InvocationCount);
    }

    private sealed class StubQrOnboardingService(QrOnboardingResult result) : IQrOnboardingService
    {
        public Task<QrOnboardingResult> ScanAndRedeemAsync(CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }

    private sealed class ThrowingQrOnboardingService : IQrOnboardingService
    {
        public Task<QrOnboardingResult> ScanAndRedeemAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("provider payload that must not escape");
    }

    private sealed class ControllableQrOnboardingService : IQrOnboardingService
    {
        private readonly TaskCompletionSource<QrOnboardingResult> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int InvocationCount { get; private set; }

        public Task<QrOnboardingResult> ScanAndRedeemAsync(CancellationToken cancellationToken)
        {
            InvocationCount++;
            Started.TrySetResult();
            return _completion.Task.WaitAsync(cancellationToken);
        }

        public void Complete(QrOnboardingResult result) => _completion.TrySetResult(result);
    }
}
