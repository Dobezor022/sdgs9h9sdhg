package com.fedmes.app

import android.content.Context
import android.media.AudioAttributes
import android.media.SoundPool

/** Original FedMes UI sound, synthesized for this project and not copied from Telegram. */
class InterfaceSoundPlayer(context: Context) {
    private val pool = SoundPool.Builder()
        .setMaxStreams(2)
        .setAudioAttributes(
            AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build(),
        )
        .build()
    private val sendSound = pool.load(context.applicationContext, R.raw.fedmes_send, 1)
    @Volatile private var loaded = false
    @Volatile private var playWhenLoaded = false

    init {
        pool.setOnLoadCompleteListener { _, sampleId, status ->
            if (sampleId == sendSound && status == 0) {
                loaded = true
                if (playWhenLoaded) {
                    playWhenLoaded = false
                    pool.play(sendSound, 0.36f, 0.36f, 1, 0, 1f)
                }
            }
        }
    }

    fun playSend() {
        if (loaded) pool.play(sendSound, 0.36f, 0.36f, 1, 0, 1f)
        else playWhenLoaded = true
    }
}
