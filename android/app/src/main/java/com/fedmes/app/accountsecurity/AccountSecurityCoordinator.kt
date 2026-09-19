package com.fedmes.app.accountsecurity

import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.security.SessionStore

class AccountSecurityCoordinator(
    private val sessionStore: SessionStore,
    private val api: AccountSecurityHttpApi,
    private val crypto: AccountVaultCrypto,
    private val localStore: AndroidAccountVaultStore,
) {
    fun localVaultAvailable(account: ProvisionedAccount): Boolean =
        localStore.hasVault(account.serverUrl, account.username)

    fun getSecurityState(account: ProvisionedAccount): AccountSecurityState = api.getState(account)

    fun pendingRecoveryKey(account: ProvisionedAccount): String? =
        localStore.loadPendingRecoveryKey(account.serverUrl, account.username)

    /**
     * Creates or resumes Account Root Key and Recovery Key enrollment on a trusted device.
     * Neither the active local vault nor the current account is replaced until every candidate
     * record has been encrypted, written, read back and accepted by the server.
     */
    fun enrollRecovery(account: ProvisionedAccount): String {
        require(account.authenticationState == AccountSecurityProtocol.STATE_READY)
        val state = api.getState(account)
        if (state.state != AccountSecurityProtocol.STATE_READY) {
            throw AccountSecurityException("security_state_conflict")
        }

        val active = localStore.load(account.serverUrl, account.username)
        val pending = localStore.loadPending(account.serverUrl, account.username)
        if (active == null && pending == null && state.vaultRevision > 0L) {
            throw AccountSecurityException("recovery_required")
        }

        val rootKey = when {
            active != null -> active.accountRootKey.copyOf()
            pending != null -> pending.accountRootKey.copyOf()
            else -> crypto.generateAccountRootKey()
        }
        try {
            val serverVault = if (state.vaultRevision == 0L) {
                val (candidate, _) = crypto.encryptVault(
                    serverUrl = account.serverUrl,
                    username = account.username,
                    accountRootKey = rootKey,
                    previousRevision = 0L,
                )
                localStore.savePending(
                    account.serverUrl,
                    account.username,
                    LocalAccountVault(rootKey, candidate.revision, candidate.cryptoVersion),
                )
                val accessVerifier = crypto.accessVerifier(
                    account.serverUrl,
                    account.username,
                    rootKey,
                    candidate.revision,
                )
                val stored = try {
                    api.putVault(account, 0L, candidate, accessVerifier)
                } finally {
                    accessVerifier.fill(0)
                }
                crypto.verifyAndDecryptVault(account.serverUrl, account.username, rootKey, stored)
                if (stored.revision != candidate.revision) {
                    throw AccountSecurityException("vault_revision_mismatch")
                }
                localStore.promotePending(account.serverUrl, account.username).accountRootKey.fill(0)
                stored
            } else {
                val stored = api.getVault(account)
                if (stored.revision != state.vaultRevision) {
                    throw AccountSecurityException("vault_revision_mismatch")
                }
                crypto.verifyAndDecryptVault(account.serverUrl, account.username, rootKey, stored)
                when {
                    pending != null -> {
                        if (pending.vaultRevision != stored.revision) {
                            throw AccountSecurityException("pending_vault_revision_mismatch")
                        }
                        localStore.promotePending(account.serverUrl, account.username).accountRootKey.fill(0)
                    }
                    active == null -> {
                        localStore.savePending(
                            account.serverUrl,
                            account.username,
                            LocalAccountVault(rootKey, stored.revision, stored.cryptoVersion),
                        )
                        localStore.promotePending(account.serverUrl, account.username).accountRootKey.fill(0)
                    }
                }
                stored
            }

            val savedButUnconfirmedKey = localStore.loadPendingRecoveryKey(account.serverUrl, account.username)
            if (state.recoveryConfigured) {
                return savedButUnconfirmedKey ?: throw AccountSecurityException("recovery_already_configured")
            }

            val recoveryKeyText = savedButUnconfirmedKey ?: crypto.generateRecoveryKeyText().also {
                localStore.savePendingRecoveryKey(account.serverUrl, account.username, it)
            }
            val recoveryPackage = crypto.createRecoveryPackage(
                serverUrl = account.serverUrl,
                username = account.username,
                recoveryKeyText = recoveryKeyText,
                accountRootKey = rootKey,
                vaultRevision = serverVault.revision,
            )
            val storedRecovery = api.putRecoveryPackage(account, recoveryPackage)
            if (storedRecovery.vaultRevision != serverVault.revision) {
                throw AccountSecurityException("recovery_package_revision_mismatch")
            }
            return recoveryKeyText
        } finally {
            active?.accountRootKey?.fill(0)
            pending?.accountRootKey?.fill(0)
            rootKey.fill(0)
        }
    }

    fun confirmRecoveryKeySaved(account: ProvisionedAccount) {
        localStore.clearPendingRecoveryKey(account.serverUrl, account.username)
    }

    fun recoverWithRecoveryKey(account: ProvisionedAccount, recoveryKeyText: String): RecoveryResult {
        val state = api.getState(account)
        val active = localStore.load(account.serverUrl, account.username)
        if (state.state == AccountSecurityProtocol.STATE_READY && active != null) {
            return try {
                val readyAccount = account.copy(authenticationState = AccountSecurityProtocol.STATE_READY)
                sessionStore.save(readyAccount)
                RecoveryResult(vaultRevision = active.vaultRevision)
            } finally {
                active.accountRootKey.fill(0)
            }
        }
        active?.accountRootKey?.fill(0)

        val alreadyPending = localStore.loadPending(account.serverUrl, account.username)
        if (state.state == AccountSecurityProtocol.STATE_READY && alreadyPending != null) {
            return try {
                val promoted = localStore.promotePending(account.serverUrl, account.username)
                try {
                    sessionStore.save(account.copy(authenticationState = AccountSecurityProtocol.STATE_READY))
                    RecoveryResult(vaultRevision = promoted.vaultRevision)
                } finally {
                    promoted.accountRootKey.fill(0)
                }
            } finally {
                alreadyPending.accountRootKey.fill(0)
            }
        }
        alreadyPending?.accountRootKey?.fill(0)

        val encryptedRecovery = api.getRecoveryPackage(account)
        val encryptedVault = api.getVault(account)
        if (encryptedRecovery.vaultRevision != encryptedVault.revision) {
            throw AccountSecurityException("recovery_package_revision_mismatch")
        }
        val accountRootKey = crypto.recoverAccountRootKey(
            serverUrl = account.serverUrl,
            username = account.username,
            recoveryKeyText = recoveryKeyText,
            recoveryPackage = encryptedRecovery,
        )
        return try {
            crypto.verifyAndDecryptVault(
                serverUrl = account.serverUrl,
                username = account.username,
                accountRootKey = accountRootKey,
                vault = encryptedVault,
            )
            localStore.savePending(
                account.serverUrl,
                account.username,
                LocalAccountVault(accountRootKey, encryptedVault.revision, encryptedVault.cryptoVersion),
            )
            val accessVerifier = crypto.accessVerifier(
                account.serverUrl,
                account.username,
                accountRootKey,
                encryptedVault.revision,
            )
            try {
                api.completeRecovery(account, encryptedVault.revision, accessVerifier)
            } finally {
                accessVerifier.fill(0)
            }
            val promoted = localStore.promotePending(account.serverUrl, account.username)
            try {
                sessionStore.save(account.copy(authenticationState = AccountSecurityProtocol.STATE_READY))
                RecoveryResult(promoted.vaultRevision)
            } finally {
                promoted.accountRootKey.fill(0)
            }
        } finally {
            accountRootKey.fill(0)
        }
    }

    fun cancelRecovery(account: ProvisionedAccount) {
        localStore.discardPending(account.serverUrl, account.username)
    }

    fun deleteLocalKeys(account: ProvisionedAccount) {
        localStore.deleteLocal(account.serverUrl, account.username)
    }
}
