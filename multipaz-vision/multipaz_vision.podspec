Pod::Spec.new do |spec|
    spec.name                     = 'multipaz_vision'
    spec.version                  = '0.95.0-pre.0.6994e40b'
    spec.homepage                 = ''
    spec.source                   = { :http=> ''}
    spec.authors                  = ''
    spec.license                  = ''
    spec.summary                  = ''
    spec.vendored_frameworks      = 'build/cocoapods/framework/multipaz_vision.framework'
    spec.libraries                = 'c++'
    spec.ios.deployment_target    = '16.0'
    spec.dependency 'GoogleMLKit/BarcodeScanning', '8.0.0'
    spec.dependency 'GoogleMLKit/FaceDetection', '8.0.0'
    spec.dependency 'MLKitVision', '9.0.0'
    spec.dependency 'TensorFlowLiteObjC', '2.17.0'
                
    if !Dir.exist?('build/cocoapods/framework/multipaz_vision.framework') || Dir.empty?('build/cocoapods/framework/multipaz_vision.framework')
        raise "

        Kotlin framework 'multipaz_vision' doesn't exist yet, so a proper Xcode project can't be generated.
        'pod install' should be executed after running ':generateDummyFramework' Gradle task:

            ./gradlew :multipaz-vision:generateDummyFramework

        Alternatively, proper pod installation is performed during Gradle sync in the IDE (if Podfile location is set)"
    end
                
    spec.xcconfig = {
        'ENABLE_USER_SCRIPT_SANDBOXING' => 'NO',
    }
                
    spec.pod_target_xcconfig = {
        'KOTLIN_PROJECT_PATH' => ':multipaz-vision',
        'PRODUCT_MODULE_NAME' => 'multipaz_vision',
    }
                
    spec.script_phases = [
        {
            :name => 'Build multipaz_vision',
            :execution_position => :before_compile,
            :shell_path => '/bin/sh',
            :script => <<-SCRIPT
                if [ "YES" = "$OVERRIDE_KOTLIN_BUILD_IDE_SUPPORTED" ]; then
                  echo "Skipping Gradle build task invocation due to OVERRIDE_KOTLIN_BUILD_IDE_SUPPORTED environment variable set to \"YES\""
                  exit 0
                fi
                set -ev
                REPO_ROOT="$PODS_TARGET_SRCROOT"
                "$REPO_ROOT/../gradlew" -p "$REPO_ROOT" $KOTLIN_PROJECT_PATH:syncFramework \
                    -Pkotlin.native.cocoapods.platform=$PLATFORM_NAME \
                    -Pkotlin.native.cocoapods.archs="$ARCHS" \
                    -Pkotlin.native.cocoapods.configuration="$CONFIGURATION"
            SCRIPT
        }
    ]
    spec.resources = ['build/compose/cocoapods/compose-resources']
end