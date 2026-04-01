# Sentinel Code Map
```text
sentinel/
├── cli/
│   └── index.js
├── sentinel.db
├── src/
├── start.js
└── ui/
    ├── .gitignore
    ├── README.md
    ├── backend/
    │   ├── lib/
    │   │   ├── db.js
    │   │   ├── gh_bridge.js
    │   │   ├── git_hooks.js
    │   │   └── sanitizer.js
    │   ├── scanner/
    │   │   ├── detector_entropy.js
    │   │   ├── detector_unicode.js
    │   │   ├── index.js
    │   │   ├── lifecycle_filter.js
    │   │   ├── rules/
    │   │   │   ├── go.yaml
    │   │   │   ├── malware.yaml
    │   │   │   ├── python.yaml
    │   │   │   ├── rust.yaml
    │   │   │   ├── secrets.yaml
    │   │   │   └── supply-chain.yaml
    │   │   └── test_scanner.js
    │   ├── server/
    │   │   └── index.js
    │   └── services/
    │       ├── hardener.js
    │       └── polling.js
    ├── build-cache/
    │   └── winCodeSign/
    │       ├── 385996511/
    │       │   ├── .DS_Store
    │       │   ├── appxAssets/
    │       │   │   ├── SampleAppx.150x150.png
    │       │   │   ├── SampleAppx.310x150.png
    │       │   │   ├── SampleAppx.44x44.png
    │       │   │   └── SampleAppx.50x50.png
    │       │   ├── darwin/
    │       │   │   ├── 10.12/
    │       │   │   │   ├── lib/
    │       │   │   │   │   ├── engines/
    │       │   │   │   │   │   ├── lib4758cca.dylib
    │       │   │   │   │   │   ├── libaep.dylib
    │       │   │   │   │   │   ├── libatalla.dylib
    │       │   │   │   │   │   ├── libcapi.dylib
    │       │   │   │   │   │   ├── libchil.dylib
    │       │   │   │   │   │   ├── libcswift.dylib
    │       │   │   │   │   │   ├── libgmp.dylib
    │       │   │   │   │   │   ├── libgost.dylib
    │       │   │   │   │   │   ├── libnuron.dylib
    │       │   │   │   │   │   ├── libpadlock.dylib
    │       │   │   │   │   │   ├── libsureware.dylib
    │       │   │   │   │   │   └── libubsec.dylib
    │       │   │   │   │   ├── libcrypto.1.0.0.dylib
    │       │   │   │   │   ├── libcrypto.a
    │       │   │   │   │   ├── libcrypto.dylib
    │       │   │   │   │   ├── libssl.1.0.0.dylib
    │       │   │   │   │   ├── libssl.a
    │       │   │   │   │   ├── libssl.dylib
    │       │   │   │   │   └── pkgconfig/
    │       │   │   │   │       ├── libcrypto.pc
    │       │   │   │   │       ├── libssl.pc
    │       │   │   │   │       └── openssl.pc
    │       │   │   │   └── osslsigncode
    │       │   │   ├── ci/
    │       │   │   │   └── osslsigncode
    │       │   │   ├── osslsigncode
    │       │   │   └── readme.md
    │       │   ├── linux/
    │       │   │   ├── Dockerfile
    │       │   │   ├── build.sh
    │       │   │   └── osslsigncode
    │       │   ├── openssl-ia32/
    │       │   │   ├── OpenSSL License.txt
    │       │   │   ├── libeay32.dll
    │       │   │   ├── openssl.exe
    │       │   │   └── ssleay32.dll
    │       │   ├── rcedit-ia32.exe
    │       │   ├── rcedit-x64.exe
    │       │   ├── windows-10/
    │       │   │   ├── ia32/
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │   │   ├── appxpackaging.dll
    │       │   │   │   ├── appxsip.dll
    │       │   │   │   ├── makeappx.exe
    │       │   │   │   ├── makecat.exe
    │       │   │   │   ├── makecat.exe.manifest
    │       │   │   │   ├── makecert.exe
    │       │   │   │   ├── makepri.exe
    │       │   │   │   ├── mssign32.dll
    │       │   │   │   ├── opcservices.dll
    │       │   │   │   ├── pvk2pfx.exe
    │       │   │   │   ├── signtool.exe
    │       │   │   │   ├── signtool.exe.manifest
    │       │   │   │   └── wintrust.dll
    │       │   │   └── x64/
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │       ├── appxpackaging.dll
    │       │   │       ├── appxsip.dll
    │       │   │       ├── makeappx.exe
    │       │   │       ├── makecat.exe
    │       │   │       ├── makecat.exe.manifest
    │       │   │       ├── makecert.exe
    │       │   │       ├── makepri.exe
    │       │   │       ├── mssign32.dll
    │       │   │       ├── opcservices.dll
    │       │   │       ├── pvk2pfx.exe
    │       │   │       ├── signtool.exe
    │       │   │       ├── signtool.exe.manifest
    │       │   │       └── wintrust.dll
    │       │   └── windows-6/
    │       │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │       ├── makecat.exe
    │       │       ├── makecat.exe.manifest
    │       │       ├── mssign32.dll
    │       │       ├── signtool.exe
    │       │       ├── signtool.exe.manifest
    │       │       └── wintrust.dll
    │       ├── 385996511.7z
    │       ├── 715456203/
    │       │   ├── .DS_Store
    │       │   ├── appxAssets/
    │       │   │   ├── SampleAppx.150x150.png
    │       │   │   ├── SampleAppx.310x150.png
    │       │   │   ├── SampleAppx.44x44.png
    │       │   │   └── SampleAppx.50x50.png
    │       │   ├── darwin/
    │       │   │   ├── 10.12/
    │       │   │   │   ├── lib/
    │       │   │   │   │   ├── engines/
    │       │   │   │   │   │   ├── lib4758cca.dylib
    │       │   │   │   │   │   ├── libaep.dylib
    │       │   │   │   │   │   ├── libatalla.dylib
    │       │   │   │   │   │   ├── libcapi.dylib
    │       │   │   │   │   │   ├── libchil.dylib
    │       │   │   │   │   │   ├── libcswift.dylib
    │       │   │   │   │   │   ├── libgmp.dylib
    │       │   │   │   │   │   ├── libgost.dylib
    │       │   │   │   │   │   ├── libnuron.dylib
    │       │   │   │   │   │   ├── libpadlock.dylib
    │       │   │   │   │   │   ├── libsureware.dylib
    │       │   │   │   │   │   └── libubsec.dylib
    │       │   │   │   │   ├── libcrypto.1.0.0.dylib
    │       │   │   │   │   ├── libcrypto.a
    │       │   │   │   │   ├── libcrypto.dylib
    │       │   │   │   │   ├── libssl.1.0.0.dylib
    │       │   │   │   │   ├── libssl.a
    │       │   │   │   │   ├── libssl.dylib
    │       │   │   │   │   └── pkgconfig/
    │       │   │   │   │       ├── libcrypto.pc
    │       │   │   │   │       ├── libssl.pc
    │       │   │   │   │       └── openssl.pc
    │       │   │   │   └── osslsigncode
    │       │   │   ├── ci/
    │       │   │   │   └── osslsigncode
    │       │   │   ├── osslsigncode
    │       │   │   └── readme.md
    │       │   ├── linux/
    │       │   │   ├── Dockerfile
    │       │   │   ├── build.sh
    │       │   │   └── osslsigncode
    │       │   ├── openssl-ia32/
    │       │   │   ├── OpenSSL License.txt
    │       │   │   ├── libeay32.dll
    │       │   │   ├── openssl.exe
    │       │   │   └── ssleay32.dll
    │       │   ├── rcedit-ia32.exe
    │       │   ├── rcedit-x64.exe
    │       │   ├── windows-10/
    │       │   │   ├── ia32/
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │   │   ├── appxpackaging.dll
    │       │   │   │   ├── appxsip.dll
    │       │   │   │   ├── makeappx.exe
    │       │   │   │   ├── makecat.exe
    │       │   │   │   ├── makecat.exe.manifest
    │       │   │   │   ├── makecert.exe
    │       │   │   │   ├── makepri.exe
    │       │   │   │   ├── mssign32.dll
    │       │   │   │   ├── opcservices.dll
    │       │   │   │   ├── pvk2pfx.exe
    │       │   │   │   ├── signtool.exe
    │       │   │   │   ├── signtool.exe.manifest
    │       │   │   │   └── wintrust.dll
    │       │   │   └── x64/
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │       ├── appxpackaging.dll
    │       │   │       ├── appxsip.dll
    │       │   │       ├── makeappx.exe
    │       │   │       ├── makecat.exe
    │       │   │       ├── makecat.exe.manifest
    │       │   │       ├── makecert.exe
    │       │   │       ├── makepri.exe
    │       │   │       ├── mssign32.dll
    │       │   │       ├── opcservices.dll
    │       │   │       ├── pvk2pfx.exe
    │       │   │       ├── signtool.exe
    │       │   │       ├── signtool.exe.manifest
    │       │   │       └── wintrust.dll
    │       │   └── windows-6/
    │       │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │       ├── makecat.exe
    │       │       ├── makecat.exe.manifest
    │       │       ├── mssign32.dll
    │       │       ├── signtool.exe
    │       │       ├── signtool.exe.manifest
    │       │       └── wintrust.dll
    │       ├── 715456203.7z
    │       ├── 749423435/
    │       │   ├── .DS_Store
    │       │   ├── appxAssets/
    │       │   │   ├── SampleAppx.150x150.png
    │       │   │   ├── SampleAppx.310x150.png
    │       │   │   ├── SampleAppx.44x44.png
    │       │   │   └── SampleAppx.50x50.png
    │       │   ├── darwin/
    │       │   │   ├── 10.12/
    │       │   │   │   ├── lib/
    │       │   │   │   │   ├── engines/
    │       │   │   │   │   │   ├── lib4758cca.dylib
    │       │   │   │   │   │   ├── libaep.dylib
    │       │   │   │   │   │   ├── libatalla.dylib
    │       │   │   │   │   │   ├── libcapi.dylib
    │       │   │   │   │   │   ├── libchil.dylib
    │       │   │   │   │   │   ├── libcswift.dylib
    │       │   │   │   │   │   ├── libgmp.dylib
    │       │   │   │   │   │   ├── libgost.dylib
    │       │   │   │   │   │   ├── libnuron.dylib
    │       │   │   │   │   │   ├── libpadlock.dylib
    │       │   │   │   │   │   ├── libsureware.dylib
    │       │   │   │   │   │   └── libubsec.dylib
    │       │   │   │   │   ├── libcrypto.1.0.0.dylib
    │       │   │   │   │   ├── libcrypto.a
    │       │   │   │   │   ├── libcrypto.dylib
    │       │   │   │   │   ├── libssl.1.0.0.dylib
    │       │   │   │   │   ├── libssl.a
    │       │   │   │   │   ├── libssl.dylib
    │       │   │   │   │   └── pkgconfig/
    │       │   │   │   │       ├── libcrypto.pc
    │       │   │   │   │       ├── libssl.pc
    │       │   │   │   │       └── openssl.pc
    │       │   │   │   └── osslsigncode
    │       │   │   ├── ci/
    │       │   │   │   └── osslsigncode
    │       │   │   ├── osslsigncode
    │       │   │   └── readme.md
    │       │   ├── linux/
    │       │   │   ├── Dockerfile
    │       │   │   ├── build.sh
    │       │   │   └── osslsigncode
    │       │   ├── openssl-ia32/
    │       │   │   ├── OpenSSL License.txt
    │       │   │   ├── libeay32.dll
    │       │   │   ├── openssl.exe
    │       │   │   └── ssleay32.dll
    │       │   ├── rcedit-ia32.exe
    │       │   ├── rcedit-x64.exe
    │       │   ├── windows-10/
    │       │   │   ├── ia32/
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │   │   ├── appxpackaging.dll
    │       │   │   │   ├── appxsip.dll
    │       │   │   │   ├── makeappx.exe
    │       │   │   │   ├── makecat.exe
    │       │   │   │   ├── makecat.exe.manifest
    │       │   │   │   ├── makecert.exe
    │       │   │   │   ├── makepri.exe
    │       │   │   │   ├── mssign32.dll
    │       │   │   │   ├── opcservices.dll
    │       │   │   │   ├── pvk2pfx.exe
    │       │   │   │   ├── signtool.exe
    │       │   │   │   ├── signtool.exe.manifest
    │       │   │   │   └── wintrust.dll
    │       │   │   └── x64/
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │       ├── appxpackaging.dll
    │       │   │       ├── appxsip.dll
    │       │   │       ├── makeappx.exe
    │       │   │       ├── makecat.exe
    │       │   │       ├── makecat.exe.manifest
    │       │   │       ├── makecert.exe
    │       │   │       ├── makepri.exe
    │       │   │       ├── mssign32.dll
    │       │   │       ├── opcservices.dll
    │       │   │       ├── pvk2pfx.exe
    │       │   │       ├── signtool.exe
    │       │   │       ├── signtool.exe.manifest
    │       │   │       └── wintrust.dll
    │       │   └── windows-6/
    │       │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │       ├── makecat.exe
    │       │       ├── makecat.exe.manifest
    │       │       ├── mssign32.dll
    │       │       ├── signtool.exe
    │       │       ├── signtool.exe.manifest
    │       │       └── wintrust.dll
    │       ├── 749423435.7z
    │       ├── 911603879/
    │       │   ├── .DS_Store
    │       │   ├── appxAssets/
    │       │   │   ├── SampleAppx.150x150.png
    │       │   │   ├── SampleAppx.310x150.png
    │       │   │   ├── SampleAppx.44x44.png
    │       │   │   └── SampleAppx.50x50.png
    │       │   ├── darwin/
    │       │   │   ├── 10.12/
    │       │   │   │   ├── lib/
    │       │   │   │   │   ├── engines/
    │       │   │   │   │   │   ├── lib4758cca.dylib
    │       │   │   │   │   │   ├── libaep.dylib
    │       │   │   │   │   │   ├── libatalla.dylib
    │       │   │   │   │   │   ├── libcapi.dylib
    │       │   │   │   │   │   ├── libchil.dylib
    │       │   │   │   │   │   ├── libcswift.dylib
    │       │   │   │   │   │   ├── libgmp.dylib
    │       │   │   │   │   │   ├── libgost.dylib
    │       │   │   │   │   │   ├── libnuron.dylib
    │       │   │   │   │   │   ├── libpadlock.dylib
    │       │   │   │   │   │   ├── libsureware.dylib
    │       │   │   │   │   │   └── libubsec.dylib
    │       │   │   │   │   ├── libcrypto.1.0.0.dylib
    │       │   │   │   │   ├── libcrypto.a
    │       │   │   │   │   ├── libcrypto.dylib
    │       │   │   │   │   ├── libssl.1.0.0.dylib
    │       │   │   │   │   ├── libssl.a
    │       │   │   │   │   ├── libssl.dylib
    │       │   │   │   │   └── pkgconfig/
    │       │   │   │   │       ├── libcrypto.pc
    │       │   │   │   │       ├── libssl.pc
    │       │   │   │   │       └── openssl.pc
    │       │   │   │   └── osslsigncode
    │       │   │   ├── ci/
    │       │   │   │   └── osslsigncode
    │       │   │   ├── osslsigncode
    │       │   │   └── readme.md
    │       │   ├── linux/
    │       │   │   ├── Dockerfile
    │       │   │   ├── build.sh
    │       │   │   └── osslsigncode
    │       │   ├── openssl-ia32/
    │       │   │   ├── OpenSSL License.txt
    │       │   │   ├── libeay32.dll
    │       │   │   ├── openssl.exe
    │       │   │   └── ssleay32.dll
    │       │   ├── rcedit-ia32.exe
    │       │   ├── rcedit-x64.exe
    │       │   ├── windows-10/
    │       │   │   ├── ia32/
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │   │   ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │   │   ├── appxpackaging.dll
    │       │   │   │   ├── appxsip.dll
    │       │   │   │   ├── makeappx.exe
    │       │   │   │   ├── makecat.exe
    │       │   │   │   ├── makecat.exe.manifest
    │       │   │   │   ├── makecert.exe
    │       │   │   │   ├── makepri.exe
    │       │   │   │   ├── mssign32.dll
    │       │   │   │   ├── opcservices.dll
    │       │   │   │   ├── pvk2pfx.exe
    │       │   │   │   ├── signtool.exe
    │       │   │   │   ├── signtool.exe.manifest
    │       │   │   │   └── wintrust.dll
    │       │   │   └── x64/
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.AppxSip.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Appx.OpcServices.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │   │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │   │       ├── appxpackaging.dll
    │       │   │       ├── appxsip.dll
    │       │   │       ├── makeappx.exe
    │       │   │       ├── makecat.exe
    │       │   │       ├── makecat.exe.manifest
    │       │   │       ├── makecert.exe
    │       │   │       ├── makepri.exe
    │       │   │       ├── mssign32.dll
    │       │   │       ├── opcservices.dll
    │       │   │       ├── pvk2pfx.exe
    │       │   │       ├── signtool.exe
    │       │   │       ├── signtool.exe.manifest
    │       │   │       └── wintrust.dll
    │       │   └── windows-6/
    │       │       ├── Microsoft.Windows.Build.Signing.mssign32.dll.manifest
    │       │       ├── Microsoft.Windows.Build.Signing.wintrust.dll.manifest
    │       │       ├── makecat.exe
    │       │       ├── makecat.exe.manifest
    │       │       ├── mssign32.dll
    │       │       ├── signtool.exe
    │       │       ├── signtool.exe.manifest
    │       │       └── wintrust.dll
    │       └── 911603879.7z
    ├── cli/
    │   └── index.js
    ├── dist-electron/
    │   ├── Sentinel Setup.exe
    │   ├── Sentinel Setup.exe.blockmap
    │   ├── builder-debug.yml
    │   ├── builder-effective-config.yaml
    │   └── win-unpacked/
    │       ├── LICENSE.electron.txt
    │       ├── LICENSES.chromium.html
    │       ├── Sentinel.exe
    │       ├── chrome_100_percent.pak
    │       ├── chrome_200_percent.pak
    │       ├── d3dcompiler_47.dll
    │       ├── ffmpeg.dll
    │       ├── icudtl.dat
    │       ├── libEGL.dll
    │       ├── libGLESv2.dll
    │       ├── locales/
    │       │   ├── af.pak
    │       │   ├── am.pak
    │       │   ├── ar.pak
    │       │   ├── bg.pak
    │       │   ├── bn.pak
    │       │   ├── ca.pak
    │       │   ├── cs.pak
    │       │   ├── da.pak
    │       │   ├── de.pak
    │       │   ├── el.pak
    │       │   ├── en-GB.pak
    │       │   ├── en-US.pak
    │       │   ├── es-419.pak
    │       │   ├── es.pak
    │       │   ├── et.pak
    │       │   ├── fa.pak
    │       │   ├── fi.pak
    │       │   ├── fil.pak
    │       │   ├── fr.pak
    │       │   ├── gu.pak
    │       │   ├── he.pak
    │       │   ├── hi.pak
    │       │   ├── hr.pak
    │       │   ├── hu.pak
    │       │   ├── id.pak
    │       │   ├── it.pak
    │       │   ├── ja.pak
    │       │   ├── kn.pak
    │       │   ├── ko.pak
    │       │   ├── lt.pak
    │       │   ├── lv.pak
    │       │   ├── ml.pak
    │       │   ├── mr.pak
    │       │   ├── ms.pak
    │       │   ├── nb.pak
    │       │   ├── nl.pak
    │       │   ├── pl.pak
    │       │   ├── pt-BR.pak
    │       │   ├── pt-PT.pak
    │       │   ├── ro.pak
    │       │   ├── ru.pak
    │       │   ├── sk.pak
    │       │   ├── sl.pak
    │       │   ├── sr.pak
    │       │   ├── sv.pak
    │       │   ├── sw.pak
    │       │   ├── ta.pak
    │       │   ├── te.pak
    │       │   ├── th.pak
    │       │   ├── tr.pak
    │       │   ├── uk.pak
    │       │   ├── ur.pak
    │       │   ├── vi.pak
    │       │   ├── zh-CN.pak
    │       │   └── zh-TW.pak
    │       ├── resources/
    │       │   ├── app.asar
    │       │   ├── app.asar.unpacked/
    │       │   ├── backend/
    │       │   │   ├── lib/
    │       │   │   │   ├── db.js
    │       │   │   │   ├── gh_bridge.js
    │       │   │   │   ├── git_hooks.js
    │       │   │   │   └── sanitizer.js
    │       │   │   ├── scanner/
    │       │   │   │   ├── detector_entropy.js
    │       │   │   │   ├── detector_unicode.js
    │       │   │   │   ├── index.js
    │       │   │   │   ├── lifecycle_filter.js
    │       │   │   │   ├── rules/
    │       │   │   │   │   ├── go.yaml
    │       │   │   │   │   ├── malware.yaml
    │       │   │   │   │   ├── python.yaml
    │       │   │   │   │   ├── rust.yaml
    │       │   │   │   │   ├── secrets.yaml
    │       │   │   │   │   └── supply-chain.yaml
    │       │   │   │   └── test_scanner.js
    │       │   │   ├── server/
    │       │   │   │   └── index.js
    │       │   │   └── services/
    │       │   │       ├── hardener.js
    │       │   │       └── polling.js
    │       │   └── elevate.exe
    │       ├── resources.pak
    │       ├── sentinel.cmd
    │       ├── snapshot_blob.bin
    │       ├── v8_context_snapshot.bin
    │       ├── vk_swiftshader.dll
    │       ├── vk_swiftshader_icd.json
    │       └── vulkan-1.dll
    ├── electron/
    │   ├── main.js
    │   └── preload.js
    ├── escape-onedrive.ps1
    ├── eslint.config.js
    ├── index.html
    ├── package-lock.json
    ├── package.json
    ├── postcss.config.js
    ├── sentinel.db
    ├── setup-cli.ps1
    ├── src/
    │   ├── App.css
    │   ├── App.tsx
    │   ├── components/
    │   │   ├── CLIReference.tsx
    │   │   ├── Dashboard.tsx
    │   │   ├── OnboardingScreen.tsx
    │   │   ├── PreferencesPanel.tsx
    │   │   ├── RepoCard.tsx
    │   │   ├── RepoSelector.tsx
    │   │   ├── ScoreRing.tsx
    │   │   ├── SecurityControls.tsx
    │   │   ├── SecurityHardener.tsx
    │   │   ├── SentinelTerminal.tsx
    │   │   ├── StatusBar.tsx
    │   │   ├── ThreatFlowMap.tsx
    │   │   ├── ThreatLog.tsx
    │   │   └── TrustedContributors.tsx
    │   ├── contexts/
    │   │   └── LanguageContext.tsx
    │   ├── index.css
    │   ├── locales/
    │   │   ├── en.json
    │   │   └── es.json
    │   └── main.tsx
    ├── src-tauri/
    │   ├── .gitignore
    │   ├── Cargo.lock
    │   ├── Cargo.toml
    │   ├── build.rs
    │   ├── capabilities/
    │   │   └── default.json
    │   ├── icons/
    │   │   ├── 128x128.png
    │   │   ├── 128x128@2x.png
    │   │   ├── 32x32.png
    │   │   ├── Square107x107Logo.png
    │   │   ├── Square142x142Logo.png
    │   │   ├── Square150x150Logo.png
    │   │   ├── Square284x284Logo.png
    │   │   ├── Square30x30Logo.png
    │   │   ├── Square310x310Logo.png
    │   │   ├── Square44x44Logo.png
    │   │   ├── Square71x71Logo.png
    │   │   ├── Square89x89Logo.png
    │   │   ├── StoreLogo.png
    │   │   ├── icon.icns
    │   │   ├── icon.ico
    │   │   └── icon.png
    │   ├── src/
    │   │   ├── lib.rs
    │   │   └── main.rs
    │   ├── target/
    │   │   ├── .rustc_info.json
    │   │   ├── CACHEDIR.TAG
    │   │   ├── debug/
    │   │   │   ├── .cargo-lock
    │   │   │   ├── .fingerprint/
    │   │   │   │   ├── adler2-1e5ec3f8b15c65bb/
    │   │   │   │   ├── aho-corasick-83aecfd9df0ec687/
    │   │   │   │   ├── alloc-no-stdlib-f59cd5a6c5f96f5e/
    │   │   │   │   ├── alloc-stdlib-99a00925db8f1695/
    │   │   │   │   ├── anyhow-9c61e8388b25f952/
    │   │   │   │   ├── anyhow-ac4c078c7555bd0c/
    │   │   │   │   ├── anyhow-ef3f532a3e874254/
    │   │   │   │   ├── app-2f600e2b50f3e0f5/
    │   │   │   │   ├── app-4e7dc2d6835c5d74/
    │   │   │   │   ├── app-fd385b5cccf19c57/
    │   │   │   │   ├── arrayvec-7292719946941a73/
    │   │   │   │   ├── autocfg-366f5d561938d235/
    │   │   │   │   ├── base64-2e84cc5ce5f260d0/
    │   │   │   │   ├── bitflags-6d41a7059d8e9a4f/
    │   │   │   │   ├── bitflags-8c0ae3db4412dfef/
    │   │   │   │   ├── block-buffer-b30367c0202fed33/
    │   │   │   │   ├── brotli-8128af6fe42e38c1/
    │   │   │   │   ├── brotli-decompressor-aa673f67dd1b0668/
    │   │   │   │   ├── byte-unit-8e4466caab181127/
    │   │   │   │   ├── byteorder-436e3834e4390f18/
    │   │   │   │   ├── bytes-094af595bf028992/
    │   │   │   │   ├── camino-0344da72ad067128/
    │   │   │   │   ├── camino-19870f041f30b086/
    │   │   │   │   ├── camino-6101e5ce36eada85/
    │   │   │   │   ├── cargo-platform-6e4805b1d79e6ff0/
    │   │   │   │   ├── cargo_metadata-334f62ed8e0a6c42/
    │   │   │   │   ├── cargo_toml-8071bbc6c0bd53a0/
    │   │   │   │   ├── cc-ac3b2a77d850abf2/
    │   │   │   │   ├── cfb-5a8885908e4ea54f/
    │   │   │   │   ├── cfb-5e33097d4617fd8c/
    │   │   │   │   ├── cfg-if-709781a0f9096a35/
    │   │   │   │   │   ├── dep-lib-cfg_if
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-cfg_if
    │   │   │   │   │   └── lib-cfg_if.json
    │   │   │   │   ├── convert_case-0cdceb8ea030dfb5/
    │   │   │   │   ├── cookie-62a633fbc947d7a4/
    │   │   │   │   ├── cookie-7fe14d1e890e7be9/
    │   │   │   │   ├── cookie-a8acf99441167794/
    │   │   │   │   ├── cpufeatures-7b85bbbfdfe10e6d/
    │   │   │   │   ├── crc32fast-608fafa2d8f1def2/
    │   │   │   │   ├── crc32fast-6e29aeaeefd6703d/
    │   │   │   │   ├── crc32fast-8c36a370c113c737/
    │   │   │   │   ├── crossbeam-channel-6c57a97f3e87d763/
    │   │   │   │   ├── crossbeam-utils-0880ffa1557110b1/
    │   │   │   │   ├── crossbeam-utils-5e5a3957de4ba188/
    │   │   │   │   ├── crossbeam-utils-9fd4ff4a897eb43c/
    │   │   │   │   ├── crypto-common-9ebb2a89d54ddd71/
    │   │   │   │   ├── cssparser-98f082d1526bd3d0/
    │   │   │   │   ├── cssparser-ca194861894c3b41/
    │   │   │   │   ├── cssparser-f133bffcc55b518f/
    │   │   │   │   ├── cssparser-macros-53d9476efdeff9fe/
    │   │   │   │   ├── ctor-5cfac8cdfb80453c/
    │   │   │   │   ├── darling-96ba711bbb8efa27/
    │   │   │   │   ├── darling_core-a45466f0b3097e89/
    │   │   │   │   ├── darling_macro-028e6623f126344c/
    │   │   │   │   ├── deranged-6265d8f0f7d315f2/
    │   │   │   │   ├── derive_more-0cfe25fbf73f7822/
    │   │   │   │   ├── digest-3ac7b92d83159a19/
    │   │   │   │   ├── dirs-0723cbadb40319e2/
    │   │   │   │   ├── dirs-ee6a1d8bda52c264/
    │   │   │   │   ├── dirs-sys-bfa4a21c1e050849/
    │   │   │   │   ├── dirs-sys-dad32de7d7147df3/
    │   │   │   │   ├── displaydoc-a1ec6ee82dc50d00/
    │   │   │   │   ├── dpi-9953e495728fa673/
    │   │   │   │   ├── dtoa-c2b318fecabefda9/
    │   │   │   │   ├── dtoa-short-933d64352c4de922/
    │   │   │   │   ├── dunce-6479b6b5c4938cba/
    │   │   │   │   ├── dyn-clone-fe4d536a77d3f02e/
    │   │   │   │   ├── embed-resource-ec448ab3e8bd4b26/
    │   │   │   │   ├── equivalent-b18a2aa0a98994d2/
    │   │   │   │   ├── erased-serde-01ffea4d5692d3cc/
    │   │   │   │   ├── erased-serde-b366d046f64d88ad/
    │   │   │   │   ├── erased-serde-e6c4359da85b46c7/
    │   │   │   │   ├── erased-serde-f3d90efe71e2341b/
    │   │   │   │   ├── fdeflate-0f5b2ed779f98f6c/
    │   │   │   │   ├── fern-1de11c54d7320219/
    │   │   │   │   ├── find-msvc-tools-48a2c1d1d39bee89/
    │   │   │   │   ├── flate2-438438d569ffc97d/
    │   │   │   │   ├── fnv-39571206bdee82c0/
    │   │   │   │   ├── form_urlencoded-1c7ad76420b104be/
    │   │   │   │   ├── form_urlencoded-86afc30499f03e3d/
    │   │   │   │   ├── futf-5ad50d9e61f6ad46/
    │   │   │   │   ├── fxhash-fd9f86a80da8701e/
    │   │   │   │   ├── generic-array-051b58dc231ad154/
    │   │   │   │   ├── generic-array-4291246aa468be0c/
    │   │   │   │   ├── generic-array-90aaaf90cf2e7517/
    │   │   │   │   ├── getrandom-103fad18c88720eb/
    │   │   │   │   ├── getrandom-21b0fa6c6e137403/
    │   │   │   │   ├── getrandom-403f847939508a4e/
    │   │   │   │   ├── getrandom-7220c0f8f497c3ba/
    │   │   │   │   ├── getrandom-73edeb63e8671c26/
    │   │   │   │   ├── getrandom-9768303197773d60/
    │   │   │   │   ├── getrandom-b4bedf87196e6fc4/
    │   │   │   │   ├── getrandom-cb3f0d0039451c78/
    │   │   │   │   ├── getrandom-e2f0731c7b3a3de7/
    │   │   │   │   │   ├── dep-lib-getrandom
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-getrandom
    │   │   │   │   │   └── lib-getrandom.json
    │   │   │   │   ├── getrandom-e697738bf1933868/
    │   │   │   │   ├── glob-b6bfd93967bffe80/
    │   │   │   │   ├── hashbrown-1decbdc2930032a4/
    │   │   │   │   ├── hashbrown-c9a65cf1a858047e/
    │   │   │   │   ├── heck-623bf4e7b8866a7e/
    │   │   │   │   ├── html5ever-1e84eb57f16046e7/
    │   │   │   │   ├── http-996c81750e896565/
    │   │   │   │   ├── ico-d292aaea32ebf593/
    │   │   │   │   ├── icu_collections-951ca3cada33def1/
    │   │   │   │   ├── icu_collections-c115a98bde4b445a/
    │   │   │   │   ├── icu_locale_core-b7bd7c6481fe4c64/
    │   │   │   │   ├── icu_locale_core-e7d5977ffb0302f5/
    │   │   │   │   ├── icu_normalizer-1c62b4bd4a867ad8/
    │   │   │   │   ├── icu_normalizer-dc06720da33db4c0/
    │   │   │   │   ├── icu_normalizer_data-2a007683dd6a9bc1/
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   └── output-build-script-build-script-build
    │   │   │   │   ├── icu_normalizer_data-624a63f695a4a57d/
    │   │   │   │   ├── icu_normalizer_data-625de2592f708529/
    │   │   │   │   ├── icu_properties-702d2d513fe39e7d/
    │   │   │   │   ├── icu_properties-ffbc0b94e1bbab9e/
    │   │   │   │   ├── icu_properties_data-385ff54ce868d001/
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   └── output-build-script-build-script-build
    │   │   │   │   ├── icu_properties_data-c64eb8ca058d3fec/
    │   │   │   │   ├── icu_properties_data-dd552b4a0761d072/
    │   │   │   │   ├── icu_provider-8e0f0be1391ac383/
    │   │   │   │   ├── icu_provider-bd1e517673964652/
    │   │   │   │   ├── ident_case-5d4bbebb5e7921e3/
    │   │   │   │   ├── idna-3a42178041534c76/
    │   │   │   │   ├── idna-bcf3e9ad7962bc2f/
    │   │   │   │   ├── idna_adapter-007c8f348974971e/
    │   │   │   │   ├── idna_adapter-ab981200e248dd86/
    │   │   │   │   ├── indexmap-0cb7852a8c86f777/
    │   │   │   │   ├── indexmap-0e490beb7241da00/
    │   │   │   │   ├── indexmap-22824f73a35bb8d3/
    │   │   │   │   ├── indexmap-5a4aa791b3840359/
    │   │   │   │   ├── infer-3436235823c2d5e8/
    │   │   │   │   ├── infer-5bddc7497451239d/
    │   │   │   │   ├── itoa-35525c49b7e45c6c/
    │   │   │   │   │   ├── dep-lib-itoa
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-itoa
    │   │   │   │   │   └── lib-itoa.json
    │   │   │   │   ├── json-patch-2755a9fb67bda1e9/
    │   │   │   │   ├── json-patch-9dc58d20ec4e3d08/
    │   │   │   │   ├── jsonptr-5b9f0fd5bcfeb781/
    │   │   │   │   ├── jsonptr-aa9ed32820e464db/
    │   │   │   │   ├── keyboard-types-70d5cba5e1923815/
    │   │   │   │   ├── kuchikiki-0ae9e22fe2261303/
    │   │   │   │   ├── libc-132353d9ff10d470/
    │   │   │   │   ├── libc-13ea44a0161cbded/
    │   │   │   │   ├── libc-73d12b80b827efd2/
    │   │   │   │   ├── litemap-cf265ac91c812e91/
    │   │   │   │   │   ├── dep-lib-litemap
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-litemap
    │   │   │   │   │   └── lib-litemap.json
    │   │   │   │   ├── lock_api-a52a2fbddb4ed2a4/
    │   │   │   │   ├── log-c724bb64db33dd92/
    │   │   │   │   ├── log-f6eff6278ca41a80/
    │   │   │   │   ├── mac-5150d4b256ca038f/
    │   │   │   │   ├── markup5ever-27961978c6582026/
    │   │   │   │   ├── markup5ever-8016bb603ba29cd2/
    │   │   │   │   ├── markup5ever-b7f81d073d9a0642/
    │   │   │   │   ├── match_token-48c91af15e03fd19/
    │   │   │   │   ├── matches-1abf903cb54bddae/
    │   │   │   │   ├── memchr-3d7b66307f89874c/
    │   │   │   │   │   ├── dep-lib-memchr
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-memchr
    │   │   │   │   │   └── lib-memchr.json
    │   │   │   │   ├── mime-a962d4c6a07196aa/
    │   │   │   │   ├── miniz_oxide-b46acd21676a1f48/
    │   │   │   │   ├── muda-53ca475149ea4bb9/
    │   │   │   │   ├── new_debug_unreachable-571e6ea7d12725e9/
    │   │   │   │   ├── nodrop-627049a982a18505/
    │   │   │   │   ├── num-conv-cd5276e86718a7df/
    │   │   │   │   ├── num-traits-05f3b28ed9b93c2c/
    │   │   │   │   ├── num-traits-9b3ef0c46ccdae0a/
    │   │   │   │   ├── num-traits-b1e07223420e736d/
    │   │   │   │   ├── once_cell-c74ed1f5792c849f/
    │   │   │   │   ├── option-ext-fc8a87742b3ee687/
    │   │   │   │   ├── parking_lot-d8211c643d33cc40/
    │   │   │   │   ├── parking_lot_core-08b84e2825604398/
    │   │   │   │   ├── parking_lot_core-a0ead7ce42dc14ee/
    │   │   │   │   ├── parking_lot_core-dd14c1e1ced32ba1/
    │   │   │   │   ├── percent-encoding-441821491d446cb5/
    │   │   │   │   ├── percent-encoding-ff5ab4ec61499fe2/
    │   │   │   │   ├── phf-0074984ce4aed167/
    │   │   │   │   ├── phf-aa7d349248a8ff28/
    │   │   │   │   ├── phf-ac3548d271f93838/
    │   │   │   │   ├── phf-c1566d7719ff8bb9/
    │   │   │   │   ├── phf_codegen-8f8bb860597648a2/
    │   │   │   │   ├── phf_codegen-aa7543c5a5405180/
    │   │   │   │   ├── phf_generator-3af2d8f76ead7ed6/
    │   │   │   │   ├── phf_generator-981b9aca68a3a69a/
    │   │   │   │   ├── phf_generator-fd139fda31a2a9e2/
    │   │   │   │   ├── phf_macros-8fb5522a4b951286/
    │   │   │   │   ├── phf_macros-a3577e734e79e937/
    │   │   │   │   ├── phf_shared-32590c8b176c3fa3/
    │   │   │   │   ├── phf_shared-522447da5fc3f0c2/
    │   │   │   │   ├── phf_shared-620a3b25bab06765/
    │   │   │   │   ├── phf_shared-bc3fa6ad61ccfdcf/
    │   │   │   │   ├── pin-project-lite-53ba8b2f4c52301c/
    │   │   │   │   ├── png-a4290c67e3454706/
    │   │   │   │   ├── potential_utf-cbd74fb76bfdc167/
    │   │   │   │   ├── potential_utf-e3396bfbc0501561/
    │   │   │   │   ├── powerfmt-3b1cc4c5d9f5fa9c/
    │   │   │   │   ├── ppv-lite86-d0bc45aef11ed834/
    │   │   │   │   ├── precomputed-hash-6ba0050332bb5af0/
    │   │   │   │   ├── proc-macro-hack-1f2e48d8834d8483/
    │   │   │   │   ├── proc-macro-hack-50fc6a5b5f0b1bfa/
    │   │   │   │   ├── proc-macro-hack-931fabd5113b4262/
    │   │   │   │   ├── proc-macro2-104b1de8b1d694c9/
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   └── output-build-script-build-script-build
    │   │   │   │   ├── proc-macro2-37d56d7e5c885f76/
    │   │   │   │   ├── proc-macro2-d20d4bde3836c231/
    │   │   │   │   ├── quote-369d1a48d2def978/
    │   │   │   │   ├── quote-3e6408bd1f221479/
    │   │   │   │   ├── quote-7f47f72891ace304/
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   └── output-build-script-build-script-build
    │   │   │   │   ├── rand-08dc4f0fddd4d364/
    │   │   │   │   ├── rand-d994b2f2d95aceab/
    │   │   │   │   ├── rand_chacha-1ada0c1a0f7cf913/
    │   │   │   │   ├── rand_chacha-a2ae50e5f2a5953e/
    │   │   │   │   ├── rand_core-0fc0ee13450f6e1f/
    │   │   │   │   ├── rand_core-4b3903806202d4f6/
    │   │   │   │   │   ├── dep-lib-rand_core
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-rand_core
    │   │   │   │   │   └── lib-rand_core.json
    │   │   │   │   ├── rand_pcg-138ff1d37b9d9f4d/
    │   │   │   │   ├── raw-window-handle-38a613b1bb5e669d/
    │   │   │   │   ├── regex-039c5209c9ae8a04/
    │   │   │   │   ├── regex-automata-70f5f29be286b54a/
    │   │   │   │   ├── regex-syntax-a10934fb780db29a/
    │   │   │   │   ├── rust_decimal-7806f171f13c8dd1/
    │   │   │   │   ├── rust_decimal-a4d1d56ab597444b/
    │   │   │   │   ├── rust_decimal-d68d4814e3dd73c5/
    │   │   │   │   ├── rustc_version-a103c8960696a4ba/
    │   │   │   │   ├── same-file-12d7da8490f158fd/
    │   │   │   │   ├── same-file-cf71c48818679a65/
    │   │   │   │   ├── schemars-32a19964ae7de16a/
    │   │   │   │   ├── schemars-8d31a01e3913b41b/
    │   │   │   │   ├── schemars-914a7d7e5a7a6040/
    │   │   │   │   ├── schemars_derive-6ac1c27b4d10b647/
    │   │   │   │   ├── scopeguard-bbf2bc2b401ee9c7/
    │   │   │   │   ├── selectors-36aa43e3cbd632e3/
    │   │   │   │   ├── selectors-372cf3f0611a2fa6/
    │   │   │   │   ├── selectors-4d566faa81edbd1f/
    │   │   │   │   ├── semver-6335e1a1e21322a2/
    │   │   │   │   ├── semver-f0e042982859cd97/
    │   │   │   │   ├── serde-067f5d802e3783e3/
    │   │   │   │   ├── serde-1fe7c0c3e06e366c/
    │   │   │   │   ├── serde-6989a8f582dacaa4/
    │   │   │   │   ├── serde-8e879bbf256b0bcb/
    │   │   │   │   ├── serde-b6a2782e30451e8c/
    │   │   │   │   ├── serde-f1dcd1860c115102/
    │   │   │   │   ├── serde-untagged-58f5328dfd95f242/
    │   │   │   │   ├── serde-untagged-b513a65ea52ee13a/
    │   │   │   │   ├── serde_core-052e4700b62359e9/
    │   │   │   │   ├── serde_core-39fc2d35c7f3e26a/
    │   │   │   │   ├── serde_core-5fb37b3e854d9008/
    │   │   │   │   ├── serde_core-834ecedf65ffcfd5/
    │   │   │   │   ├── serde_core-87b179de3ef1c944/
    │   │   │   │   ├── serde_core-89e74970a1c024b0/
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   └── output-build-script-build-script-build
    │   │   │   │   ├── serde_derive-6e734527f0c6edb4/
    │   │   │   │   ├── serde_derive_internals-eee8bea09ec35dad/
    │   │   │   │   ├── serde_json-1bb9a15324b5934a/
    │   │   │   │   ├── serde_json-4fb470950419b6b1/
    │   │   │   │   ├── serde_json-6c76ffe5ef2774e2/
    │   │   │   │   ├── serde_json-b8ae817c7c5a8959/
    │   │   │   │   ├── serde_json-d5c8d7c9a057827e/
    │   │   │   │   ├── serde_json-f69c682e9069c140/
    │   │   │   │   ├── serde_repr-8c812b4b4794ff35/
    │   │   │   │   ├── serde_spanned-047a260239306ef0/
    │   │   │   │   ├── serde_spanned-1f6f4916abe9681f/
    │   │   │   │   ├── serde_with-67e6bc29fc53f9d9/
    │   │   │   │   ├── serde_with-d7250b1534888dd0/
    │   │   │   │   ├── serde_with_macros-fdeb5c6446a92045/
    │   │   │   │   ├── serialize-to-javascript-3b6d3f452ca48735/
    │   │   │   │   ├── serialize-to-javascript-impl-c746d437db03a343/
    │   │   │   │   ├── servo_arc-4fe140cf88f2c9f5/
    │   │   │   │   ├── sha2-736451e1cf2ebed3/
    │   │   │   │   ├── shlex-d2aac3fd770a1dca/
    │   │   │   │   ├── simd-adler32-46252b25eef01863/
    │   │   │   │   ├── siphasher-3260a1cd0909352c/
    │   │   │   │   ├── siphasher-45af281d0fdcb55f/
    │   │   │   │   │   ├── dep-lib-siphasher
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-siphasher
    │   │   │   │   │   └── lib-siphasher.json
    │   │   │   │   ├── smallvec-373da207a4f9c630/
    │   │   │   │   │   ├── dep-lib-smallvec
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-smallvec
    │   │   │   │   │   └── lib-smallvec.json
    │   │   │   │   ├── softbuffer-230db6d00b9adf1b/
    │   │   │   │   ├── stable_deref_trait-7236b80e2b8dd665/
    │   │   │   │   │   ├── dep-lib-stable_deref_trait
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-stable_deref_trait
    │   │   │   │   │   └── lib-stable_deref_trait.json
    │   │   │   │   ├── stable_deref_trait-c1a18707beb8878e/
    │   │   │   │   ├── string_cache-7e7872aa5c937135/
    │   │   │   │   ├── string_cache_codegen-fd12c3e9c7b005fd/
    │   │   │   │   ├── strsim-e3a93f8f8dc0532d/
    │   │   │   │   ├── syn-0097c8b4aa202675/
    │   │   │   │   ├── syn-924e20929bd9a232/
    │   │   │   │   ├── syn-db5ea1a6c0aa3081/
    │   │   │   │   ├── syn-ff8f898c2a4c26d6/
    │   │   │   │   ├── synstructure-730055e4b4ae226c/
    │   │   │   │   ├── tao-afefbf98e134657e/
    │   │   │   │   ├── tauri-164158a0dac60a90/
    │   │   │   │   ├── tauri-build-578550ef91694923/
    │   │   │   │   ├── tauri-c590d2e4bf9ca363/
    │   │   │   │   ├── tauri-codegen-57395c8523067d3e/
    │   │   │   │   ├── tauri-efaf1f0bce1cfdef/
    │   │   │   │   ├── tauri-macros-709dca1cb61c5014/
    │   │   │   │   ├── tauri-plugin-6b3b03911fc03b12/
    │   │   │   │   ├── tauri-plugin-log-69842e18b2e9f906/
    │   │   │   │   ├── tauri-plugin-log-a678ace8b65f7ed7/
    │   │   │   │   ├── tauri-plugin-log-d86647a63457ed6b/
    │   │   │   │   ├── tauri-runtime-0d1222dd99f8b7e5/
    │   │   │   │   ├── tauri-runtime-3723af45fd834327/
    │   │   │   │   ├── tauri-runtime-a13ac4922ff7c59c/
    │   │   │   │   ├── tauri-runtime-wry-036d91b36f9380cc/
    │   │   │   │   ├── tauri-runtime-wry-e0d5d34e90e6e101/
    │   │   │   │   ├── tauri-runtime-wry-f472acfdebe97cd9/
    │   │   │   │   ├── tauri-utils-a5a7119b6f50db6b/
    │   │   │   │   ├── tauri-utils-dd97b7bea91d1584/
    │   │   │   │   ├── tauri-winres-6237407ccd5e4f0b/
    │   │   │   │   ├── tendril-66122cd327842a02/
    │   │   │   │   ├── thiserror-01736a456bb42081/
    │   │   │   │   ├── thiserror-2686001a48dd8322/
    │   │   │   │   ├── thiserror-36c492990601819d/
    │   │   │   │   ├── thiserror-491e4a8c4a891cad/
    │   │   │   │   ├── thiserror-8262331fa0a72a1b/
    │   │   │   │   ├── thiserror-83b5eed51332646f/
    │   │   │   │   ├── thiserror-impl-787099401eadf09b/
    │   │   │   │   ├── thiserror-impl-9dfafdba7bd64005/
    │   │   │   │   ├── time-09b575f931caa449/
    │   │   │   │   ├── time-core-789f3e0508057278/
    │   │   │   │   ├── time-macros-7176ffb4c11a7d5e/
    │   │   │   │   ├── tinystr-45a00e53fa6b75dd/
    │   │   │   │   ├── tinystr-e6000c213598a513/
    │   │   │   │   ├── tokio-d79bbce5f46a1c24/
    │   │   │   │   ├── toml-8aee31bdb1f4b640/
    │   │   │   │   ├── toml-a8f5714762a05769/
    │   │   │   │   ├── toml_datetime-3b2d833237860b68/
    │   │   │   │   ├── toml_datetime-86092fc29bfa12fd/
    │   │   │   │   ├── toml_parser-567a8b8b1dbfa4e4/
    │   │   │   │   ├── toml_writer-d0fc8c07d6b537f6/
    │   │   │   │   ├── tracing-8c1c20a7dad2a312/
    │   │   │   │   ├── tracing-core-a87c3c06642d6a39/
    │   │   │   │   ├── typeid-37eb4577a3338211/
    │   │   │   │   ├── typeid-792576aa4f3ba24f/
    │   │   │   │   ├── typeid-887d5fbf55c8ccbd/
    │   │   │   │   ├── typenum-1d39b9910b973578/
    │   │   │   │   ├── typenum-343e9acb0674a6d8/
    │   │   │   │   ├── typenum-a311083938855472/
    │   │   │   │   ├── unic-char-property-20ee4a48b2d1e953/
    │   │   │   │   ├── unic-char-range-40aa93b870b26861/
    │   │   │   │   ├── unic-common-a9942b662d17a0db/
    │   │   │   │   ├── unic-ucd-ident-8916650e3f3d7bb1/
    │   │   │   │   ├── unic-ucd-version-9d8d527e48bd1be5/
    │   │   │   │   ├── unicode-ident-10f4d069e44ba2e4/
    │   │   │   │   │   ├── dep-lib-unicode_ident
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-unicode_ident
    │   │   │   │   │   └── lib-unicode_ident.json
    │   │   │   │   ├── unicode-segmentation-44348d817729e022/
    │   │   │   │   ├── url-11572270981a9795/
    │   │   │   │   ├── url-eabf9b42d98ac2c8/
    │   │   │   │   ├── urlpattern-5d84b555b946cdd6/
    │   │   │   │   ├── urlpattern-a2a4db7fc42a0498/
    │   │   │   │   ├── utf-8-3534012a2f98b6f2/
    │   │   │   │   ├── utf8-width-c7b9fb16fa64117a/
    │   │   │   │   ├── utf8_iter-f228e7e8efe56842/
    │   │   │   │   ├── uuid-eb210c3ec76945cc/
    │   │   │   │   ├── uuid-f2f1f78c8d23f7f9/
    │   │   │   │   ├── value-bag-8efb82f3fc5830c3/
    │   │   │   │   ├── version_check-97d031e59f70f618/
    │   │   │   │   ├── vswhom-19e1a651a2917434/
    │   │   │   │   ├── vswhom-sys-0189c8fa32946c43/
    │   │   │   │   ├── vswhom-sys-314df2ec5d8a2278/
    │   │   │   │   ├── vswhom-sys-f76554a0a550c868/
    │   │   │   │   ├── walkdir-05c83f8b315898c0/
    │   │   │   │   ├── walkdir-aed6089edcab4998/
    │   │   │   │   ├── webview2-com-e39c88092791829b/
    │   │   │   │   ├── webview2-com-macros-aaf1061a99016d52/
    │   │   │   │   ├── webview2-com-sys-2bc825ae142c5c14/
    │   │   │   │   ├── webview2-com-sys-8a94faeec2e602f5/
    │   │   │   │   ├── webview2-com-sys-e288b059df39a7cf/
    │   │   │   │   ├── winapi-util-35f7121864282383/
    │   │   │   │   ├── winapi-util-6642c9c4560e19ff/
    │   │   │   │   ├── window-vibrancy-1ae177a1a15c6755/
    │   │   │   │   ├── windows-collections-7ea378d59834e97c/
    │   │   │   │   ├── windows-core-4f8db65e460bd6cf/
    │   │   │   │   ├── windows-d6fd639dcd3d07ae/
    │   │   │   │   ├── windows-future-a5f04c287b013a62/
    │   │   │   │   ├── windows-implement-0b32e9fbff766ee5/
    │   │   │   │   ├── windows-interface-a811d8a0e8d67da5/
    │   │   │   │   ├── windows-link-1d9231600f43e5c8/
    │   │   │   │   ├── windows-link-bc01748f223d1f99/
    │   │   │   │   │   ├── dep-lib-windows_link
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-windows_link
    │   │   │   │   │   └── lib-windows_link.json
    │   │   │   │   ├── windows-numerics-9e890833a6fdf560/
    │   │   │   │   ├── windows-result-730e80b5faeb5d2a/
    │   │   │   │   ├── windows-strings-2dc9ea71b0e37361/
    │   │   │   │   ├── windows-sys-26d101398d39ce6a/
    │   │   │   │   ├── windows-sys-630627a1c6a822fa/
    │   │   │   │   ├── windows-sys-aaaf24f4a7513c37/
    │   │   │   │   ├── windows-sys-c23bcd9b7e3ead52/
    │   │   │   │   ├── windows-sys-ccf52b5ab74ef77a/
    │   │   │   │   ├── windows-targets-5bbc085e8f34d82c/
    │   │   │   │   ├── windows-targets-c5947a7efeb48f22/
    │   │   │   │   ├── windows-threading-7d2cd5dde3c119cf/
    │   │   │   │   ├── windows-version-679f067510559ede/
    │   │   │   │   ├── windows_x86_64_msvc-04fde2036ac075a7/
    │   │   │   │   ├── windows_x86_64_msvc-34948bb2ece75ee8/
    │   │   │   │   ├── windows_x86_64_msvc-4e07052f4066e85c/
    │   │   │   │   ├── windows_x86_64_msvc-809630b7b58853ff/
    │   │   │   │   ├── windows_x86_64_msvc-a14dfd073ec5e750/
    │   │   │   │   ├── windows_x86_64_msvc-cb524d63dff4a587/
    │   │   │   │   ├── winnow-1d2f07ef90eeff6e/
    │   │   │   │   ├── winnow-60daf1775fb1484f/
    │   │   │   │   ├── winreg-22be3ac27ad12a4b/
    │   │   │   │   ├── writeable-55e368b85d6fddcc/
    │   │   │   │   │   ├── dep-lib-writeable
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   ├── lib-writeable
    │   │   │   │   │   └── lib-writeable.json
    │   │   │   │   ├── wry-113095c2a2d1c763/
    │   │   │   │   ├── wry-55cea717090ffc66/
    │   │   │   │   ├── wry-cccb8618325371c7/
    │   │   │   │   ├── yoke-0266c699b92b97c7/
    │   │   │   │   ├── yoke-62e50afc7c2478ef/
    │   │   │   │   ├── yoke-derive-d0460e29f7737bc4/
    │   │   │   │   ├── zerocopy-3f6eb75b09fa6fb5/
    │   │   │   │   ├── zerocopy-4188df97b8ec32f8/
    │   │   │   │   ├── zerocopy-c7095c1fd5124e49/
    │   │   │   │   │   ├── invoked.timestamp
    │   │   │   │   │   └── output-build-script-build-script-build
    │   │   │   │   ├── zerofrom-55a0f7125613dce7/
    │   │   │   │   ├── zerofrom-derive-e540c37788574e40/
    │   │   │   │   ├── zerotrie-b9acd9e7e4eb1af5/
    │   │   │   │   ├── zerotrie-ed6e9109c46155d0/
    │   │   │   │   ├── zerovec-245a5d996bcb6864/
    │   │   │   │   ├── zerovec-b18e2e34e87335a7/
    │   │   │   │   ├── zerovec-derive-c976e43125dc5558/
    │   │   │   │   ├── zmij-566e3279186aa171/
    │   │   │   │   ├── zmij-d3af101a4a102fa4/
    │   │   │   │   └── zmij-edb27c4d6462c5c0/
    │   │   │   ├── deps/
    │   │   │   │   ├── cfg_if-709781a0f9096a35.d
    │   │   │   │   ├── getrandom-e2f0731c7b3a3de7.d
    │   │   │   │   ├── itoa-35525c49b7e45c6c.d
    │   │   │   │   ├── libcfg_if-709781a0f9096a35.rlib
    │   │   │   │   ├── libcfg_if-709781a0f9096a35.rmeta
    │   │   │   │   ├── libgetrandom-e2f0731c7b3a3de7.rlib
    │   │   │   │   ├── libgetrandom-e2f0731c7b3a3de7.rmeta
    │   │   │   │   ├── libitoa-35525c49b7e45c6c.rlib
    │   │   │   │   ├── libitoa-35525c49b7e45c6c.rmeta
    │   │   │   │   ├── liblitemap-cf265ac91c812e91.rlib
    │   │   │   │   ├── liblitemap-cf265ac91c812e91.rmeta
    │   │   │   │   ├── libmemchr-3d7b66307f89874c.rlib
    │   │   │   │   ├── libmemchr-3d7b66307f89874c.rmeta
    │   │   │   │   ├── librand_core-4b3903806202d4f6.rlib
    │   │   │   │   ├── librand_core-4b3903806202d4f6.rmeta
    │   │   │   │   ├── libsiphasher-45af281d0fdcb55f.rlib
    │   │   │   │   ├── libsiphasher-45af281d0fdcb55f.rmeta
    │   │   │   │   ├── libsmallvec-373da207a4f9c630.rlib
    │   │   │   │   ├── libsmallvec-373da207a4f9c630.rmeta
    │   │   │   │   ├── libstable_deref_trait-7236b80e2b8dd665.rlib
    │   │   │   │   ├── libstable_deref_trait-7236b80e2b8dd665.rmeta
    │   │   │   │   ├── libunicode_ident-10f4d069e44ba2e4.rlib
    │   │   │   │   ├── libunicode_ident-10f4d069e44ba2e4.rmeta
    │   │   │   │   ├── libwindows_link-bc01748f223d1f99.rlib
    │   │   │   │   ├── libwindows_link-bc01748f223d1f99.rmeta
    │   │   │   │   ├── libwriteable-55e368b85d6fddcc.rlib
    │   │   │   │   ├── libwriteable-55e368b85d6fddcc.rmeta
    │   │   │   │   ├── litemap-cf265ac91c812e91.d
    │   │   │   │   ├── memchr-3d7b66307f89874c.d
    │   │   │   │   ├── rand_core-4b3903806202d4f6.d
    │   │   │   │   ├── siphasher-45af281d0fdcb55f.d
    │   │   │   │   ├── smallvec-373da207a4f9c630.d
    │   │   │   │   ├── stable_deref_trait-7236b80e2b8dd665.d
    │   │   │   │   ├── unicode_ident-10f4d069e44ba2e4.d
    │   │   │   │   ├── windows_link-bc01748f223d1f99.d
    │   │   │   │   └── writeable-55e368b85d6fddcc.d
    │   │   │   ├── examples/
    │   │   │   └── incremental/
    │   │   └── release/
    │   │       ├── .cargo-lock
    │   │       ├── .fingerprint/
    │   │       │   ├── adler2-b0847bd865363dd7/
    │   │       │   ├── aho-corasick-b05af3b7933a145a/
    │   │       │   ├── aho-corasick-d2cb8aaad9a6ecb8/
    │   │       │   ├── alloc-no-stdlib-26bb9fb7e4570883/
    │   │       │   ├── alloc-no-stdlib-f40b649cfc8e5830/
    │   │       │   ├── alloc-stdlib-22316f517b1b9767/
    │   │       │   ├── alloc-stdlib-a9f701b99ad980d8/
    │   │       │   ├── anyhow-2d126352a742942f/
    │   │       │   ├── anyhow-577c880fb81865c8/
    │   │       │   ├── anyhow-78f92faf0e35c53e/
    │   │       │   ├── anyhow-c2ab1d54954defe4/
    │   │       │   ├── anyhow-e9af92c2c4db5939/
    │   │       │   ├── app-48d2f956f9491d11/
    │   │       │   ├── app-4e7dc2d6835c5d74/
    │   │       │   ├── app-af192ab50e2a502f/
    │   │       │   ├── arrayvec-99cd38be5d872883/
    │   │       │   ├── autocfg-022c652a92cba33a/
    │   │       │   ├── base64-8e4bc74787da8fa1/
    │   │       │   ├── bitflags-1b01c23bea0e0ee2/
    │   │       │   ├── bitflags-28a444ca30819bc5/
    │   │       │   ├── block-buffer-79fbd0ea98a5cd47/
    │   │       │   ├── brotli-1d8bf24b375bf7ec/
    │   │       │   ├── brotli-3b23f91876852b34/
    │   │       │   ├── brotli-decompressor-1a5248ae1f495e86/
    │   │       │   ├── brotli-decompressor-1c8ecb27386b14e7/
    │   │       │   ├── byte-unit-d2c6d393d144459e/
    │   │       │   ├── byteorder-16db5dbdaf6f0cf0/
    │   │       │   ├── byteorder-c7943b507c59b739/
    │   │       │   ├── bytes-5a278ca4a8d5d660/
    │   │       │   ├── bytes-e5cd8003be50a700/
    │   │       │   ├── camino-0551a55ad51845aa/
    │   │       │   ├── camino-44e76ceaab7c30c7/
    │   │       │   ├── camino-5d4ca34469f11137/
    │   │       │   ├── cargo-platform-42066ba3ac35dc52/
    │   │       │   ├── cargo_metadata-e32d4fe1d4a9e618/
    │   │       │   ├── cargo_toml-5c297b5dc9f05eb0/
    │   │       │   ├── cc-e7cde5f407b9c373/
    │   │       │   ├── cfb-24bcc774e1da9171/
    │   │       │   ├── cfb-6baacd7fb95e792c/
    │   │       │   ├── cfg-if-af44c0454701f66a/
    │   │       │   ├── cfg-if-dd67501918e9f7e3/
    │   │       │   │   ├── dep-lib-cfg_if
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   ├── lib-cfg_if
    │   │       │   │   └── lib-cfg_if.json
    │   │       │   ├── convert_case-00097f98ded7258b/
    │   │       │   ├── cookie-68ab03d0cfefce0d/
    │   │       │   ├── cookie-a1d7a78dabdc7d14/
    │   │       │   ├── cookie-a96f73a04f145781/
    │   │       │   ├── cpufeatures-9db2133b955ff90e/
    │   │       │   ├── crc32fast-643c3d8b5b53acb7/
    │   │       │   ├── crc32fast-b6ae1177b7ee2c02/
    │   │       │   ├── crc32fast-b6ccc7c21471e29d/
    │   │       │   ├── crossbeam-channel-3c515594f771b168/
    │   │       │   ├── crossbeam-utils-595ec85a22fa0373/
    │   │       │   ├── crossbeam-utils-6339e993b32c9f12/
    │   │       │   ├── crossbeam-utils-93144d70f389f42a/
    │   │       │   ├── crypto-common-8fe6081b85735b8b/
    │   │       │   ├── cssparser-06ed0200e29dec27/
    │   │       │   ├── cssparser-24774c223784251a/
    │   │       │   ├── cssparser-e9b8ad594de62a02/
    │   │       │   ├── cssparser-macros-d218cc339e77c5f7/
    │   │       │   ├── ctor-ad8feb96d2dfe9c2/
    │   │       │   ├── darling-043d8b3c21838a8e/
    │   │       │   ├── darling_core-e8d2d9162081835c/
    │   │       │   ├── darling_macro-3722cd51396cf981/
    │   │       │   ├── deranged-ee72c79cfea81e7d/
    │   │       │   ├── derive_more-86e72478304b11af/
    │   │       │   ├── digest-1759027dc305bd49/
    │   │       │   ├── dirs-61612aa07bfa59bc/
    │   │       │   ├── dirs-a53ffa0b87c6c4d7/
    │   │       │   ├── dirs-sys-3645df5a0fbad305/
    │   │       │   ├── dirs-sys-cae34c930751ef4b/
    │   │       │   ├── displaydoc-064c65efeaf8fb40/
    │   │       │   ├── dpi-698f8a11948e836a/
    │   │       │   ├── dtoa-b9b11412649c83fd/
    │   │       │   ├── dtoa-short-a00b9df2150ae449/
    │   │       │   ├── dunce-10e3e9f8bf34cf7c/
    │   │       │   ├── dunce-c3113c03b9ea1bf4/
    │   │       │   ├── dyn-clone-b8eb7c0491cf2642/
    │   │       │   ├── embed-resource-3bcaa295c6b00917/
    │   │       │   ├── equivalent-b6de2fb841b5b1b4/
    │   │       │   ├── erased-serde-0b35d25e6e870654/
    │   │       │   ├── erased-serde-91f811ac4879a40f/
    │   │       │   ├── erased-serde-aa631ae5d580bdc1/
    │   │       │   ├── erased-serde-c75c2fa402404fe4/
    │   │       │   ├── erased-serde-d597c0677323c928/
    │   │       │   ├── fdeflate-891b19c757db88a2/
    │   │       │   ├── fern-87e22aca8f4331c4/
    │   │       │   ├── find-msvc-tools-124e52f65162e3a8/
    │   │       │   ├── flate2-ab69e588c0a633ab/
    │   │       │   ├── fnv-84d32b3b89f55e8e/
    │   │       │   ├── fnv-b340ba81dbd4ed31/
    │   │       │   ├── form_urlencoded-9d98dffc9f95ed13/
    │   │       │   ├── form_urlencoded-dc9c457e969eaac3/
    │   │       │   ├── futf-73c64181794fd409/
    │   │       │   ├── fxhash-81110565704d7820/
    │   │       │   ├── generic-array-66ee126946a68409/
    │   │       │   ├── generic-array-69676bf7a338a3df/
    │   │       │   ├── generic-array-f5bbaf4fcc530cc9/
    │   │       │   ├── getrandom-1a7dfca3fbd3c385/
    │   │       │   ├── getrandom-1ccfb7dad27ca75f/
    │   │       │   ├── getrandom-230f3a80ab735f29/
    │   │       │   ├── getrandom-45d548388fdc3d0a/
    │   │       │   ├── getrandom-59459885671d2db8/
    │   │       │   ├── getrandom-77a11dc4182b7018/
    │   │       │   ├── getrandom-9060217d6d6ea9ee/
    │   │       │   ├── getrandom-9437aac256105d2c/
    │   │       │   ├── getrandom-c085db71902d95f9/
    │   │       │   │   ├── dep-lib-getrandom
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   ├── lib-getrandom
    │   │       │   │   └── lib-getrandom.json
    │   │       │   ├── getrandom-f8b965acee364b2e/
    │   │       │   ├── glob-09e4a08e24369d5c/
    │   │       │   ├── glob-962ec6f80f3d30cd/
    │   │       │   ├── hashbrown-1f0ea399ea9fcaf1/
    │   │       │   ├── hashbrown-8e7c4deb0d45267b/
    │   │       │   ├── heck-1b5e6ac03cad32de/
    │   │       │   ├── heck-988214ea809f8deb/
    │   │       │   ├── html5ever-398375832a3f724a/
    │   │       │   ├── http-4ec15a31a08c273a/
    │   │       │   ├── http-5ba1a2481be7ce10/
    │   │       │   ├── ico-9aa315dd65387894/
    │   │       │   ├── icu_collections-60a0ac2f419843be/
    │   │       │   ├── icu_collections-6a72fd6675d5e06d/
    │   │       │   ├── icu_locale_core-274d755ccf80b153/
    │   │       │   ├── icu_locale_core-46a5df59a793bdb9/
    │   │       │   ├── icu_normalizer-a99a9ba3261cae20/
    │   │       │   ├── icu_normalizer-b0e7457188c12116/
    │   │       │   ├── icu_normalizer_data-2c21bc37d3eaf8d4/
    │   │       │   ├── icu_normalizer_data-6b254d2bd2e789c2/
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   └── output-build-script-build-script-build
    │   │       │   ├── icu_normalizer_data-6c20b3d21512b43a/
    │   │       │   ├── icu_normalizer_data-956488c4b558367e/
    │   │       │   ├── icu_normalizer_data-f4f91066b37be7f4/
    │   │       │   ├── icu_properties-be4f6ed8d9cf853e/
    │   │       │   ├── icu_properties-cd46b00dec782fa2/
    │   │       │   ├── icu_properties_data-46dc0703dc5beea1/
    │   │       │   ├── icu_properties_data-5abbaa9a94ebb7a0/
    │   │       │   ├── icu_properties_data-6d5086558f402bb6/
    │   │       │   ├── icu_properties_data-a33b0a3427596265/
    │   │       │   ├── icu_properties_data-c421ffb17ad484ed/
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   └── output-build-script-build-script-build
    │   │       │   ├── icu_provider-c1c026b2661abe7f/
    │   │       │   ├── icu_provider-e9c11866da82a690/
    │   │       │   ├── ident_case-44765c60988986d8/
    │   │       │   ├── idna-4f602e31452212c5/
    │   │       │   ├── idna-9674c4df049ff775/
    │   │       │   ├── idna_adapter-0424df95938fe8fa/
    │   │       │   ├── idna_adapter-450eee96a136af4a/
    │   │       │   ├── indexmap-7e397e492f35c117/
    │   │       │   ├── indexmap-88e854ce41a4f89a/
    │   │       │   ├── indexmap-90f6672c0ccd6927/
    │   │       │   ├── indexmap-ee6b980ae9fc469f/
    │   │       │   ├── infer-2033ba343b0a913f/
    │   │       │   ├── infer-9f24dbf1d76f0b1c/
    │   │       │   ├── itoa-29694e338d15ec01/
    │   │       │   ├── itoa-c2e65c2e5c696aa0/
    │   │       │   ├── json-patch-551fb033fabf38e8/
    │   │       │   ├── json-patch-98ad9a47aeff3a80/
    │   │       │   ├── jsonptr-448104c51a982962/
    │   │       │   ├── jsonptr-80afc660abfebfd4/
    │   │       │   ├── keyboard-types-bab136bfac5d6d54/
    │   │       │   ├── kuchikiki-866603516543f26e/
    │   │       │   ├── libc-1b3f8bb3f9bb7c6e/
    │   │       │   ├── libc-1f90a84cae009ed2/
    │   │       │   ├── libc-212444c7654f75e4/
    │   │       │   ├── libc-5ef94f2f2d10905d/
    │   │       │   ├── libc-a1b88f52a523a0d4/
    │   │       │   ├── litemap-fb82667dd57f7da3/
    │   │       │   ├── litemap-fe240c1b117684d8/
    │   │       │   ├── lock_api-abad632cb5caed72/
    │   │       │   ├── lock_api-f99ba7de14adf8ec/
    │   │       │   ├── log-2618d49a0ec8cbcd/
    │   │       │   ├── log-850dd70c838280e3/
    │   │       │   ├── mac-b789f53e597867ee/
    │   │       │   ├── markup5ever-0c39d83b3690ca70/
    │   │       │   ├── markup5ever-bac0c4f865bfa770/
    │   │       │   ├── markup5ever-e32c7147a5017163/
    │   │       │   ├── match_token-c825d3d463a9df1d/
    │   │       │   ├── matches-8acb72fd2a5f1dd2/
    │   │       │   ├── memchr-eb5a44eecd806cd6/
    │   │       │   ├── memchr-fd82cbf65e81c959/
    │   │       │   ├── mime-352124e292c9b0ca/
    │   │       │   ├── miniz_oxide-0218cddc84659f28/
    │   │       │   ├── muda-12d371c58deac4f5/
    │   │       │   ├── new_debug_unreachable-3421168b8593622e/
    │   │       │   ├── nodrop-537933129b88f408/
    │   │       │   ├── num-conv-30f29420f6cb9621/
    │   │       │   ├── num-conv-e20007af44df6c49/
    │   │       │   ├── num-traits-71252402cc8f3131/
    │   │       │   ├── num-traits-e97311c2aa16167d/
    │   │       │   ├── num-traits-fb10ba5e94451099/
    │   │       │   ├── once_cell-dc168f337e1a9b03/
    │   │       │   ├── option-ext-003d7f47099d700d/
    │   │       │   ├── option-ext-8e19d27407c6cc54/
    │   │       │   ├── parking_lot-a7b3d5ad2e44a7b8/
    │   │       │   ├── parking_lot-f0b387a274347709/
    │   │       │   ├── parking_lot_core-32440b1f9c526780/
    │   │       │   ├── parking_lot_core-79b5edfc98715d6f/
    │   │       │   ├── parking_lot_core-8d4686e51445bd56/
    │   │       │   ├── parking_lot_core-c661ff4dc574a5b1/
    │   │       │   ├── parking_lot_core-c7cafdc8526907c7/
    │   │       │   ├── percent-encoding-35a2c680c90f7948/
    │   │       │   ├── percent-encoding-fda0d96566839c9b/
    │   │       │   ├── phf-446758c90d2022ed/
    │   │       │   ├── phf-4f76345589efe013/
    │   │       │   ├── phf-9bc67ed61d2afc42/
    │   │       │   ├── phf-e4887e3d21c89ecf/
    │   │       │   ├── phf_codegen-ab464a7ec9cbc587/
    │   │       │   ├── phf_codegen-afe5da3a603a071d/
    │   │       │   ├── phf_generator-58312510a09b9f29/
    │   │       │   ├── phf_generator-d2e8610c37070ec3/
    │   │       │   ├── phf_generator-d97cb3ca332917ee/
    │   │       │   ├── phf_macros-3fabd5f93e2501a3/
    │   │       │   ├── phf_macros-98ce98e651ad5f53/
    │   │       │   ├── phf_shared-516514efb02f467a/
    │   │       │   ├── phf_shared-54bcc2cd4f98de7a/
    │   │       │   ├── phf_shared-bd39572bfecbc0f8/
    │   │       │   ├── phf_shared-e8e33f32674c548c/
    │   │       │   ├── pin-project-lite-b3d3d4de966b7c1e/
    │   │       │   ├── png-12d0a6c91e19945f/
    │   │       │   ├── potential_utf-5531f262c0e4afd1/
    │   │       │   ├── potential_utf-b5ee53da59d263ef/
    │   │       │   ├── powerfmt-a405d08bd18797ab/
    │   │       │   ├── ppv-lite86-05f79abe72dd2925/
    │   │       │   ├── precomputed-hash-6b0454c981e4e9a7/
    │   │       │   ├── proc-macro-hack-0c2d438ad12a23af/
    │   │       │   ├── proc-macro-hack-87d54b16b9c7c8e1/
    │   │       │   ├── proc-macro-hack-891e33e73289863b/
    │   │       │   ├── proc-macro2-3368b3c7988813dc/
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   └── output-build-script-build-script-build
    │   │       │   ├── proc-macro2-71a935cb6a754650/
    │   │       │   ├── proc-macro2-7b52a230c48e9f83/
    │   │       │   ├── quote-839af1a3468ce2c1/
    │   │       │   ├── quote-af97fe32c34a3449/
    │   │       │   ├── quote-b1609f9aa441b528/
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   └── output-build-script-build-script-build
    │   │       │   ├── rand-3e1c32f94d9b8bef/
    │   │       │   ├── rand-c32e0af066c6683b/
    │   │       │   ├── rand_chacha-cbf2c02e27524e99/
    │   │       │   ├── rand_chacha-e8433ebef10f1239/
    │   │       │   ├── rand_core-71307ae5a69cad4c/
    │   │       │   ├── rand_core-7d75eeaf7f2f33fc/
    │   │       │   ├── rand_pcg-5a33bef0fe81ce45/
    │   │       │   ├── raw-window-handle-c6225bbfabbf90c5/
    │   │       │   ├── regex-65faf9c2b943847f/
    │   │       │   ├── regex-automata-4e18977e952a72c3/
    │   │       │   ├── regex-automata-9cd4cd465849f2f2/
    │   │       │   ├── regex-f6d4d52591792674/
    │   │       │   ├── regex-syntax-67d9673a1e73eb03/
    │   │       │   ├── regex-syntax-e61baa05cad00bd0/
    │   │       │   ├── rust_decimal-074bff6f947cabe0/
    │   │       │   ├── rust_decimal-39d67cfe246cb954/
    │   │       │   ├── rust_decimal-f74fe4ebc772c37d/
    │   │       │   ├── rustc_version-96b2766ca3843e1f/
    │   │       │   ├── same-file-15200882845f4f4a/
    │   │       │   ├── same-file-1c0e1132506d8644/
    │   │       │   ├── schemars-37caeef2f5d75e9e/
    │   │       │   ├── schemars-51d9e0ce51d6fe84/
    │   │       │   ├── schemars-95be0c77fb3a7e00/
    │   │       │   ├── schemars_derive-44a17f6a2c2a301c/
    │   │       │   ├── scopeguard-78f73ddb4bfecf1e/
    │   │       │   ├── scopeguard-a383c32954938ee8/
    │   │       │   ├── selectors-7c9ee50ac77b436f/
    │   │       │   ├── selectors-ae5bc2dde8745a13/
    │   │       │   ├── selectors-d0e5b894c1bdf145/
    │   │       │   ├── semver-6745f90f79e28b9b/
    │   │       │   ├── semver-b277c369193b56aa/
    │   │       │   ├── serde-3b7793a17b496003/
    │   │       │   ├── serde-426c93ba9b01ed6e/
    │   │       │   ├── serde-5b7f04d5ca48598c/
    │   │       │   ├── serde-7c765ea23536e069/
    │   │       │   ├── serde-be20e613bcc77c9c/
    │   │       │   ├── serde-e63531b5e3bb2643/
    │   │       │   ├── serde-untagged-2c1c7cab5d997af6/
    │   │       │   ├── serde-untagged-f6e5d6ecb292b9fc/
    │   │       │   ├── serde_core-6a52c475ffdc4ce4/
    │   │       │   ├── serde_core-9f1aef232dce7ae3/
    │   │       │   ├── serde_core-ebd8972b9d93ed97/
    │   │       │   ├── serde_core-ed23577f2b7f6561/
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   └── output-build-script-build-script-build
    │   │       │   ├── serde_core-ef0014fcec01aeff/
    │   │       │   ├── serde_core-f2e759eba707a041/
    │   │       │   ├── serde_derive-60cf0a1c36cbf0e3/
    │   │       │   ├── serde_derive_internals-3dd888d4552bb001/
    │   │       │   ├── serde_json-01a7d4762f4593e2/
    │   │       │   ├── serde_json-2784439b594ecd6c/
    │   │       │   ├── serde_json-4a35266eb6fb5836/
    │   │       │   ├── serde_json-a54d5ab801489e4b/
    │   │       │   ├── serde_json-bf7c71f6d466f3cf/
    │   │       │   ├── serde_json-e2fed6314e134ddf/
    │   │       │   ├── serde_repr-ef64ce00c05637ec/
    │   │       │   ├── serde_spanned-c24b8fadb1f717c7/
    │   │       │   ├── serde_spanned-d856522246dbe532/
    │   │       │   ├── serde_with-3ca9b93c7e02cf13/
    │   │       │   ├── serde_with-53686f09ba08ad83/
    │   │       │   ├── serde_with_macros-0c9a665fa18d2c70/
    │   │       │   ├── serialize-to-javascript-5f7f3381f57e08d8/
    │   │       │   ├── serialize-to-javascript-impl-835898489da0bcf3/
    │   │       │   ├── servo_arc-c01433f3b5928659/
    │   │       │   ├── sha2-8a2bb4a0ce5a70f2/
    │   │       │   ├── shlex-e37aa60338000ea1/
    │   │       │   ├── simd-adler32-3a7ea31c4212b963/
    │   │       │   ├── siphasher-4d73c30be3f31dc4/
    │   │       │   ├── siphasher-57385efcf2bd02b3/
    │   │       │   ├── siphasher-c333dba69fc8c197/
    │   │       │   ├── smallvec-08fe0dcd11b188c1/
    │   │       │   ├── smallvec-94c9f70d9d8b8de9/
    │   │       │   ├── softbuffer-dd5417a719c45de9/
    │   │       │   ├── stable_deref_trait-e31024ddefd36ede/
    │   │       │   │   ├── dep-lib-stable_deref_trait
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   ├── lib-stable_deref_trait
    │   │       │   │   └── lib-stable_deref_trait.json
    │   │       │   ├── stable_deref_trait-ff17058854560cb6/
    │   │       │   ├── string_cache-7d8a38b9ae980277/
    │   │       │   ├── string_cache_codegen-3d323b8169d56218/
    │   │       │   ├── strsim-b73b4739e25986e3/
    │   │       │   ├── syn-1f9fb3df58315464/
    │   │       │   ├── syn-77fc66e39f7a83a0/
    │   │       │   ├── syn-9194b06f6d637932/
    │   │       │   ├── syn-c26a0a3145325a58/
    │   │       │   ├── synstructure-aff3948c621f4664/
    │   │       │   ├── tao-ae62bbd3ef495295/
    │   │       │   ├── tauri-0673ffd88ca7049c/
    │   │       │   ├── tauri-7b992197f3118c1a/
    │   │       │   ├── tauri-build-00e77dc67f0903e2/
    │   │       │   ├── tauri-codegen-a039eac8c4f19610/
    │   │       │   ├── tauri-df939de004706459/
    │   │       │   ├── tauri-macros-4f351f2ee5af128b/
    │   │       │   ├── tauri-plugin-76a0e5a3c7d6ce1c/
    │   │       │   ├── tauri-plugin-log-509d17b654e73c50/
    │   │       │   ├── tauri-plugin-log-53edbe2ba8b62654/
    │   │       │   ├── tauri-plugin-log-b7763a17c9a15286/
    │   │       │   ├── tauri-runtime-57205cb8e8bd6e92/
    │   │       │   ├── tauri-runtime-a762d2f6b92e8cdb/
    │   │       │   ├── tauri-runtime-b1769c37cd186f52/
    │   │       │   ├── tauri-runtime-wry-0988ca6a80dcb712/
    │   │       │   ├── tauri-runtime-wry-6dc4fea18e1a5aa5/
    │   │       │   ├── tauri-runtime-wry-ae5af6e3e86f6d12/
    │   │       │   ├── tauri-utils-dbec0dfc7acee74e/
    │   │       │   ├── tauri-utils-f0c0d91ee7155204/
    │   │       │   ├── tauri-winres-36d3e37cd44e8726/
    │   │       │   ├── tendril-675906de571b9c44/
    │   │       │   ├── thiserror-00a6fc899f600915/
    │   │       │   ├── thiserror-0544e4cbab487b4b/
    │   │       │   ├── thiserror-1262c263f2699dc0/
    │   │       │   ├── thiserror-1eb1a39fd77d2b24/
    │   │       │   ├── thiserror-5e115a17a77b495c/
    │   │       │   ├── thiserror-6413da79bcc544c7/
    │   │       │   ├── thiserror-6f91619bb1dcf9ec/
    │   │       │   ├── thiserror-a7c9fb0ac07c2226/
    │   │       │   ├── thiserror-b2dbb3bfe8334e43/
    │   │       │   ├── thiserror-ed5a89f5e30a401a/
    │   │       │   ├── thiserror-impl-44e20627a9da6309/
    │   │       │   ├── thiserror-impl-a5cebf86b4e27623/
    │   │       │   ├── time-68b0e5ed5d750012/
    │   │       │   ├── time-core-672a1fecd4817d28/
    │   │       │   ├── time-core-8ea088bf01151ffe/
    │   │       │   ├── time-macros-12c95ade9e7a002d/
    │   │       │   ├── tinystr-09d58e549167e1d5/
    │   │       │   ├── tinystr-54eb198dacd9f40c/
    │   │       │   ├── tokio-dc1b75b98d889ed5/
    │   │       │   ├── toml-705a3111bf6424e3/
    │   │       │   ├── toml-9ea080eaed88580d/
    │   │       │   ├── toml_datetime-08373c1f03fcd52d/
    │   │       │   ├── toml_datetime-bd8e02cdcf096c3a/
    │   │       │   ├── toml_parser-91c95006b91f2826/
    │   │       │   ├── toml_parser-e7e49d83add821fb/
    │   │       │   ├── toml_writer-3cd698e3b1b90de4/
    │   │       │   ├── toml_writer-6cb16e9ce1267e20/
    │   │       │   ├── tracing-4133714f0756adf6/
    │   │       │   ├── tracing-core-351ca4d2f463f887/
    │   │       │   ├── typeid-1647116b6b3c6f31/
    │   │       │   ├── typeid-566b388fa59979b0/
    │   │       │   ├── typeid-83b35201816a31af/
    │   │       │   ├── typeid-e19293ad217bfea5/
    │   │       │   ├── typeid-f898abb0f3eff615/
    │   │       │   ├── typenum-ca09fa6bc0a17091/
    │   │       │   ├── typenum-fc63d61bf05e54bf/
    │   │       │   ├── typenum-ff003f5abab60515/
    │   │       │   ├── unic-char-property-75c10e861936522e/
    │   │       │   ├── unic-char-property-b04eec8a5e67740d/
    │   │       │   ├── unic-char-range-172c851d1822247b/
    │   │       │   ├── unic-char-range-5d7e582e5b498c8c/
    │   │       │   ├── unic-common-c3bc39f55425d13e/
    │   │       │   ├── unic-common-cdf4cdf5bb2204a0/
    │   │       │   ├── unic-ucd-ident-55d855e520952e62/
    │   │       │   ├── unic-ucd-ident-8f26070b279175dc/
    │   │       │   ├── unic-ucd-version-30663f24ad54618c/
    │   │       │   ├── unic-ucd-version-8fb7faa824f1921e/
    │   │       │   ├── unicode-ident-3f3ff471a7541be3/
    │   │       │   │   ├── dep-lib-unicode_ident
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   ├── lib-unicode_ident
    │   │       │   │   └── lib-unicode_ident.json
    │   │       │   ├── unicode-segmentation-e0211c97511cf34c/
    │   │       │   ├── url-4131b897ed508550/
    │   │       │   ├── url-e3b22f56b90da1e4/
    │   │       │   ├── urlpattern-63c58c9a62fc5e5e/
    │   │       │   ├── urlpattern-81fe54ea0c6b2158/
    │   │       │   ├── utf-8-6a57ed7a61f4c789/
    │   │       │   ├── utf8-width-882be96c257c14a9/
    │   │       │   ├── utf8_iter-7f6c7ac8eb8b4b2a/
    │   │       │   ├── utf8_iter-88c0ecabe35ed2a6/
    │   │       │   ├── uuid-80f1cea295f15c96/
    │   │       │   ├── uuid-e24d441e04ec36f0/
    │   │       │   ├── value-bag-99dd65b9d2a8110c/
    │   │       │   ├── version_check-1c987787a7e47685/
    │   │       │   ├── vswhom-bb54e448b63097d6/
    │   │       │   ├── vswhom-sys-8abb8e1963132577/
    │   │       │   ├── vswhom-sys-af8e5b7ac5223244/
    │   │       │   ├── vswhom-sys-eb269f645e12d0d5/
    │   │       │   ├── walkdir-5a8c56b86a8df8c3/
    │   │       │   ├── walkdir-b6193013e1c1961c/
    │   │       │   ├── webview2-com-67f0f9da6c31cfda/
    │   │       │   ├── webview2-com-macros-1bada8df6f25520a/
    │   │       │   ├── webview2-com-sys-13b54f68a2faec1a/
    │   │       │   ├── webview2-com-sys-4de3eda674295cb2/
    │   │       │   ├── webview2-com-sys-b7c417700cfa8da9/
    │   │       │   ├── winapi-util-989074b1b7f75f81/
    │   │       │   ├── winapi-util-de7d21494965841b/
    │   │       │   ├── window-vibrancy-2d99750cae223355/
    │   │       │   ├── windows-c3885fff7309d497/
    │   │       │   ├── windows-collections-172e876208329e62/
    │   │       │   ├── windows-core-ecd4241f8737d305/
    │   │       │   ├── windows-future-a5341eb5a02ef5ea/
    │   │       │   ├── windows-implement-7c75fd1d7d2b8345/
    │   │       │   ├── windows-interface-bb7811c4be423876/
    │   │       │   ├── windows-link-2cb74cf514b43e66/
    │   │       │   ├── windows-link-47777e9887890022/
    │   │       │   ├── windows-link-e1ef2a0843046b0f/
    │   │       │   ├── windows-numerics-3c9e2194ca0a572c/
    │   │       │   ├── windows-result-bb4dd34ceada74db/
    │   │       │   ├── windows-strings-8a17f8e25432788f/
    │   │       │   ├── windows-sys-1b11690bf1985233/
    │   │       │   ├── windows-sys-1e27fde01ad376ee/
    │   │       │   ├── windows-sys-7a93acdba38c7519/
    │   │       │   ├── windows-sys-c5524f1f59100c06/
    │   │       │   ├── windows-sys-fab5787df78bc3e2/
    │   │       │   ├── windows-targets-96e30dbbe7f3ca77/
    │   │       │   ├── windows-targets-c6384226d7e5dff3/
    │   │       │   ├── windows-targets-e500650c3699748d/
    │   │       │   ├── windows-threading-d68cb983701d5f54/
    │   │       │   ├── windows-version-b4c51351db784c35/
    │   │       │   ├── windows_x86_64_msvc-1a459fb031d87911/
    │   │       │   ├── windows_x86_64_msvc-1d379f1a90500111/
    │   │       │   ├── windows_x86_64_msvc-1f18f8eb5d56f071/
    │   │       │   ├── windows_x86_64_msvc-20b7852f416410c4/
    │   │       │   ├── windows_x86_64_msvc-40092a184a8eefb8/
    │   │       │   ├── windows_x86_64_msvc-5ffff851a8815370/
    │   │       │   ├── windows_x86_64_msvc-8431021c59707462/
    │   │       │   ├── windows_x86_64_msvc-e4bac8a54a96d21c/
    │   │       │   ├── winnow-302787c113cfd3ab/
    │   │       │   ├── winnow-82619a96d8e35e14/
    │   │       │   ├── winnow-ea62406a22700930/
    │   │       │   ├── winnow-f7028873d77b2c25/
    │   │       │   ├── winreg-0d7ef9ae6e59c9ec/
    │   │       │   ├── writeable-63d45bff0c246e38/
    │   │       │   ├── writeable-d9b9e739a2cc1f8a/
    │   │       │   ├── wry-1b5a6b4cafff9957/
    │   │       │   ├── wry-825880846436a7fd/
    │   │       │   ├── wry-f4f485d4bee1b1cc/
    │   │       │   ├── yoke-28c2a07236523ab7/
    │   │       │   ├── yoke-derive-3dec2c4e3428dc70/
    │   │       │   ├── yoke-eb128c2d597be582/
    │   │       │   ├── zerocopy-0a2a8a74dae85565/
    │   │       │   │   ├── invoked.timestamp
    │   │       │   │   └── output-build-script-build-script-build
    │   │       │   ├── zerocopy-b03663f617a4b485/
    │   │       │   ├── zerocopy-cb1071a1f8dc98c1/
    │   │       │   ├── zerofrom-25e285df35ffe86c/
    │   │       │   ├── zerofrom-derive-2bb856919251dce4/
    │   │       │   ├── zerofrom-e3e2b5b87270fa6c/
    │   │       │   ├── zerotrie-4046895470c0cf85/
    │   │       │   ├── zerotrie-c92aae41d2496652/
    │   │       │   ├── zerovec-3f53652bcc6222f6/
    │   │       │   ├── zerovec-b9a371f4d7b51dae/
    │   │       │   ├── zerovec-derive-2fd92b209af08182/
    │   │       │   ├── zmij-14329d74cc670529/
    │   │       │   ├── zmij-a3058948c412ebe8/
    │   │       │   ├── zmij-ad0d3ee57a1ea86f/
    │   │       │   ├── zmij-d3cb6846e4a06465/
    │   │       │   └── zmij-ff5499e104f3bded/
    │   │       ├── deps/
    │   │       │   ├── cfg_if-dd67501918e9f7e3.d
    │   │       │   ├── getrandom-c085db71902d95f9.d
    │   │       │   ├── libcfg_if-dd67501918e9f7e3.rlib
    │   │       │   ├── libcfg_if-dd67501918e9f7e3.rmeta
    │   │       │   ├── libgetrandom-c085db71902d95f9.rlib
    │   │       │   ├── libgetrandom-c085db71902d95f9.rmeta
    │   │       │   ├── libstable_deref_trait-e31024ddefd36ede.rlib
    │   │       │   ├── libstable_deref_trait-e31024ddefd36ede.rmeta
    │   │       │   ├── libunicode_ident-3f3ff471a7541be3.rlib
    │   │       │   ├── libunicode_ident-3f3ff471a7541be3.rmeta
    │   │       │   ├── stable_deref_trait-e31024ddefd36ede.d
    │   │       │   └── unicode_ident-3f3ff471a7541be3.d
    │   │       ├── examples/
    │   │       └── incremental/
    │   └── tauri.conf.json
    ├── tailwind.config.js
    ├── tsconfig.app.json
    ├── tsconfig.json
    ├── tsconfig.node.json
    └── vite.config.ts
```
