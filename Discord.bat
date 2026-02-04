@echo off
:: ***************************************************************
:: 1. KOMUT İSTEMCİSİNİN KOD SAYFASINI AYARLA (Türkçe Karakterler İçin)
:: ***************************************************************
chcp 65001 >nul

:: ***************************************************************
:: 2. YÖNETİCİ HAKLARI (UAC) İSTE
:: ***************************************************************
:: Yönetici haklarına sahip olup olmadığını kontrol et
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo.
    echo Yönetici hakları gerekiyor...
    goto UACPrompt
) else (
    goto GotAdmin
)

:UACPrompt
echo Set UAC = CreateObject("Shell.Application") > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "%~f0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
del "%temp%\getadmin.vbs"
exit /B

:GotAdmin
pushd "%CD%"
cd /D "%~dp0"

:: ***************************************************************
:: 3. SERVICE_REMOVE.CMD DOSYASINI ÇALIŞTIR (Sessiz)
:: ***************************************************************
echo.
echo "service_remove.cmd" çalıştırılıyor...
if exist "goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" (
    call "goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" >nul 2>&1
    if %errorlevel% NEQ 0 (
        echo.
        echo HATA: "service_remove.cmd" çalıştırılamadı.
        pause
        exit /B 1
    )
) else (
    echo.
    echo HATA: "service_remove.cmd" bulunamadı.
    pause
    exit /B 1
)

:: ***************************************************************
:: 4. DISCORD KLASÖRÜNÜ OLUŞTUR (Mevcutsa Üzerine Yaz)
:: ***************************************************************
set "DISCORD_PATH=%ProgramFiles%\Discord"

echo.
echo Discord klasörü kontrol ediliyor: "%DISCORD_PATH%"
if not exist "%DISCORD_PATH%" (
    echo Discord klasörü oluşturuluyor...
    mkdir "%DISCORD_PATH%"
) else (
    echo Discord klasörü zaten mevcut. İçeriği güncelleniyor...
)

:: ***************************************************************
:: 5. goodbyedpi-0.2.3rc3-turkey KLASÖRÜNÜ KOPYALA (Üzerine Yaz)
:: ***************************************************************
echo.
echo "goodbyedpi-0.2.3rc3-turkey" klasörü kopyalanıyor...
xcopy "goodbyedpi-0.2.3rc3-turkey" "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey" /E /I /Y
if %errorlevel% NEQ 0 (
    echo.
    echo HATA: "goodbyedpi-0.2.3rc3-turkey" klasörü kopyalanamadı. Bu klasör, bu dosyayla aynı dizinde olmalı!
    pause
    exit /B 1
)

:: ***************************************************************
:: 6. Varsayılan Kurulum Dosyasını Çalıştır (Sessiz)
:: ***************************************************************
echo.
echo Varsayılan kurulum dosyası çalıştırılıyor...
if exist "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_install_dnsredir_turkey.cmd" (
    call "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_install_dnsredir_turkey.cmd" >nul 2>&1
    if %errorlevel% NEQ 0 (
        echo.
        echo HATA: "service_install_dnsredir_turkey.cmd" çalıştırılamadı.
        pause
        exit /B 1
    )
) else (
    echo.
    echo HATA: "service_install_dnsredir_turkey.cmd" bulunamadı.
    pause
    exit /B 1
)

:: ***************************************************************
:: 7. Discord Çalışıyor Mu? SORUSU VE ALTERNATİF ÇÖZÜMLER
:: ***************************************************************
:ASK1
echo.
set /p "cevap=Discord çalışıyor mu? (e/h): "

if /I "%cevap%"=="e" (
    echo Harika! İşleminiz tamamlandı.
    goto END
) else if /I "%cevap%"=="h" (
    echo.
    echo "service_remove.cmd" çalıştırılıyor...
    if exist "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" (
        call "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" >nul 2>&1
        if %errorlevel% NEQ 0 (
            echo.
            echo HATA: "service_remove.cmd" çalıştırılamadı.
            pause
            exit /B 1
        )
    ) else (
        echo.
        echo HATA: "service_remove.cmd" bulunamadı.
        pause
        exit /B 1
    )

    echo.
    echo Alternatif kurulum 1: "service_install_dnsredir_turkey_alternative_superonline.cmd" çalıştırılıyor...
    if exist "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_install_dnsredir_turkey_alternative_superonline.cmd" (
        call "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_install_dnsredir_turkey_alternative_superonline.cmd" >nul 2>&1
        if %errorlevel% NEQ 0 (
            echo.
            echo HATA: "service_install_dnsredir_turkey_alternative_superonline.cmd" çalıştırılamadı.
            pause
            exit /B 1
        )
    ) else (
        echo.
        echo HATA: "service_install_dnsredir_turkey_alternative_superonline.cmd" bulunamadı.
        pause
        exit /B 1
    )

    goto ASK2
) else (
    echo Geçersiz yanıt. Lütfen 'e' veya 'h' giriniz.
    goto ASK1
)

:ASK2
echo.
set /p "cevap=Discord çalışıyor mu? (e/h): "

if /I "%cevap%"=="e" (
    echo Harika! İşleminiz tamamlandı.
    goto END
) else if /I "%cevap%"=="h" (
    echo.
    echo "service_remove.cmd" çalıştırılıyor...
    if exist "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" (
        call "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" >nul 2>&1
        if %errorlevel% NEQ 0 (
            echo.
            echo HATA: "service_remove.cmd" çalıştırılamadı.
            pause
            exit /B 1
        )
    ) else (
        echo.
        echo HATA: "service_remove.cmd" bulunamadı.
        pause
        exit /B 1
    )

    echo.
    echo Alternatif kurulum 2: "service_install_dnsredir_turkey_alternative2_superonline.cmd" çalıştırılıyor...
    if exist "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_install_dnsredir_turkey_alternative2_superonline.cmd" (
        call "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_install_dnsredir_turkey_alternative2_superonline.cmd" >nul 2>&1
        if %errorlevel% NEQ 0 (
            echo.
            echo HATA: "service_install_dnsredir_turkey_alternative2_superonline.cmd" çalıştırılamadı.
            pause
            exit /B 1
        )
    ) else (
        echo.
        echo HATA: "service_install_dnsredir_turkey_alternative2_superonline.cmd" bulunamadı.
        pause
        exit /B 1
    )

    goto ASK3
) else (
    echo Geçersiz yanıt. Lütfen 'e' veya 'h' giriniz.
    goto ASK2
)

:ASK3
echo.
set /p "cevap=Discord çalışıyor mu? (e/h): "

if /I "%cevap%"=="e" (
    echo Harika! İşleminiz tamamlandı.
    goto END
) else if /I "%cevap%"=="h" (
    echo.
    echo "service_remove.cmd" çalıştırılıyor ve değişiklikler geri alınıyor...
    if exist "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" (
        call "%DISCORD_PATH%\goodbyedpi-0.2.3rc3-turkey\service_remove.cmd" >nul 2>&1
        if %errorlevel% NEQ 0 (
            echo.
            echo HATA: "service_remove.cmd" çalıştırılamadı.
            pause
            exit /B 1
        )
    ) else (
        echo.
        echo HATA: "service_remove.cmd" bulunamadı.
        pause
        exit /B 1
    )

    echo.
    echo Maalesef halen çözüm sağlanamadı. Değişiklikler geri alındı.
    goto END
) else (
    echo Geçersiz yanıt. Lütfen 'e' veya 'h' giriniz.
    goto ASK3
)

:END
echo.
echo Program sonlandırıldı.
pause
exit /B
