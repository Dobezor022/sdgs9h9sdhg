package com.fedmes.app

import android.app.Application
import com.fedmes.app.di.AppContainer
import com.fedmes.app.security.AppIntegrityVerifier

class FedMesApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppIntegrityVerifier.verifyOrThrow(this)
    }

    val appContainer: AppContainer by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        AppContainer(applicationContext)
    }
}
