package com.fedmes.app.di

import android.content.Context
import com.fedmes.app.BuildConfig
import com.fedmes.app.accountsecurity.AccountSecurityCoordinator
import com.fedmes.app.accountsecurity.AccountSecurityHttpApi
import com.fedmes.app.accountsecurity.AccountVaultCrypto
import com.fedmes.app.accountsecurity.AndroidAccountVaultStore
import com.fedmes.app.security.AndroidProvisioningKeyStore
import com.fedmes.app.messaging.RatchetMessageCrypto
import com.fedmes.app.messaging.RatchetHttpApi
import com.fedmes.app.messaging.AndroidRatchetStore
import com.fedmes.app.cryptocore.FedMesCryptoCore
import com.fedmes.app.calling.FedMesCallCoordinator
import com.fedmes.app.accountsecurity.OpaqueRecoveryCrypto
import com.fedmes.app.accountsecurity.OpaqueAuthHttpApi
import com.fedmes.app.accountsecurity.OpaqueAuthCoordinator
import com.fedmes.app.accountsecurity.DeviceProvisioningHttpApi
import com.fedmes.app.accountsecurity.DeviceProvisioningCrypto
import com.fedmes.app.accountsecurity.DeviceProvisioningCoordinator
import com.fedmes.app.FedMesSyncService
import com.fedmes.app.InterfaceSoundPlayer
import com.fedmes.app.domain.family.FamilyDirectory
import com.fedmes.app.domain.family.FixedFamilyDirectory
import com.fedmes.app.devices.DeviceLinkingHttpApi
import com.fedmes.app.devices.DeviceManagerRepository
import com.fedmes.app.messaging.AndroidMessageKeyStore
import com.fedmes.app.messaging.DeviceAttachmentRepository
import com.fedmes.app.messaging.MessageCrypto
import com.fedmes.app.messaging.MessagingHttpApi
import com.fedmes.app.messaging.MessagingRepository
import com.fedmes.app.provisioning.ProvisioningCoordinator
import com.fedmes.app.provisioning.ProvisioningHttpApi
import com.fedmes.app.provisioning.ProvisioningInviteParser
import com.fedmes.app.provisioning.UrlConnectionJsonHttpTransport
import com.fedmes.app.security.AndroidDeviceIdentity
import com.fedmes.app.security.EncryptedSessionStore
import com.fedmes.app.security.SessionStore
import com.fedmes.app.security2.Fsa2StateStore
import com.fedmes.app.settings.UserPreferences
import com.fedmes.app.updates.AppUpdateCoordinator

/** Application-scoped dependencies with explicit constructor injection. */
class AppContainer(
    context: Context,
    val familyDirectory: FamilyDirectory = FixedFamilyDirectory,
) {
    val applicationContext: Context = context.applicationContext
    val sessionStore: SessionStore = EncryptedSessionStore(context.applicationContext)
    val userPreferences = UserPreferences(context.applicationContext)
    val interfaceSoundPlayer = InterfaceSoundPlayer(context.applicationContext)
    val updateCoordinator = AppUpdateCoordinator(context.applicationContext, sessionStore)
    private val messageKeyStore = AndroidMessageKeyStore(applicationContext, sessionStore)
    private val deviceIdentity = AndroidDeviceIdentity(applicationContext)
    private val provisioningKeys = AndroidProvisioningKeyStore(applicationContext)
    private val accountVaultStore = AndroidAccountVaultStore(applicationContext)
    private val accountVaultCrypto = AccountVaultCrypto()
    val cryptoCore = FedMesCryptoCore()
    val fsa2StateStore = Fsa2StateStore(applicationContext)
    private val provisioningApi = ProvisioningHttpApi(UrlConnectionJsonHttpTransport())
    val accountSecurityCoordinator = AccountSecurityCoordinator(
        sessionStore = sessionStore,
        api = AccountSecurityHttpApi(),
        crypto = accountVaultCrypto,
        localStore = accountVaultStore,
    )
    val opaqueAuthCoordinator = OpaqueAuthCoordinator(
        sessionStore = sessionStore,
        core = cryptoCore,
        api = OpaqueAuthHttpApi(),
        identity = deviceIdentity,
        provisioningKeys = provisioningKeys,
        securityApi = AccountSecurityHttpApi(),
        vaultCrypto = accountVaultCrypto,
        vaultStore = accountVaultStore,
        opaqueRecoveryCrypto = OpaqueRecoveryCrypto(),
    )
    val deviceProvisioningCoordinator = DeviceProvisioningCoordinator(
        sessionStore = sessionStore,
        api = DeviceProvisioningHttpApi(),
        identity = deviceIdentity,
        crypto = DeviceProvisioningCrypto(provisioningKeys),
        securityApi = AccountSecurityHttpApi(),
        vaultCrypto = accountVaultCrypto,
        vaultStore = accountVaultStore,
    )

    val provisioningCoordinator = ProvisioningCoordinator(
        inviteParser = ProvisioningInviteParser(),
        deviceIdentity = deviceIdentity,
        messageEncryptionIdentityProvider = { serverUrl, username ->
            com.fedmes.app.provisioning.MessageEncryptionIdentity(
                algorithm = AndroidMessageKeyStore.ALGORITHM,
                publicKeySpkiBase64 = messageKeyStore.getOrCreatePublicKeySpkiBase64(serverUrl, username),
            )
        },
        provisioningApi = provisioningApi,
        authenticationApi = provisioningApi,
        sessionStore = sessionStore,
        allowInsecureHttp = BuildConfig.DEBUG,
    )

    val deviceAttachmentRepository = DeviceAttachmentRepository(applicationContext)
    private val messageCrypto = MessageCrypto(messageKeyStore)
    private val ratchetMessageCrypto = RatchetMessageCrypto(
        core = cryptoCore,
        api = RatchetHttpApi(),
        store = AndroidRatchetStore(applicationContext),
        vaultStore = accountVaultStore,
        deviceIdentity = deviceIdentity,
        messageCrypto = messageCrypto,
    )
    val messagingRepository = MessagingRepository(
        sessionStore = sessionStore,
        provisioningCoordinator = provisioningCoordinator,
        api = MessagingHttpApi(),
        keyStore = messageKeyStore,
        crypto = messageCrypto,
        ratchetCrypto = ratchetMessageCrypto,
    )

    val callCoordinator = FedMesCallCoordinator(
        context = applicationContext,
        sessionStore = sessionStore,
        messagingRepository = messagingRepository,
        crypto = cryptoCore,
    )

    val deviceManagerRepository = DeviceManagerRepository(
        sessionStore = sessionStore,
        provisioningCoordinator = provisioningCoordinator,
        deviceIdentity = deviceIdentity,
        api = DeviceLinkingHttpApi(),
        messagingRepository = messagingRepository,
    )

    fun startBackgroundSync() = FedMesSyncService.start(applicationContext)

    fun stopBackgroundSync() = FedMesSyncService.stop(applicationContext)
}

