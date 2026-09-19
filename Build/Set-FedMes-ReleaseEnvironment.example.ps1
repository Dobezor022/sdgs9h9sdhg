# Скопируйте файл за пределы проекта, заполните значения и НЕ добавляйте его в Git/ZIP.
$env:FEDMES_ANDROID_KEYSTORE = 'C:\FedMesSecrets\fedmes-release.jks'
$env:FEDMES_ANDROID_KEYSTORE_PASSWORD = 'ЗАМЕНИТЬ'
$env:FEDMES_ANDROID_KEY_ALIAS = 'fedmes'
$env:FEDMES_ANDROID_KEY_PASSWORD = 'ЗАМЕНИТЬ'

# При необходимости:
$env:ANDROID_SDK_ROOT = 'C:\Android\Sdk'
$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
