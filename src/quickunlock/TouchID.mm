/*
*  Copyright (C) 2025 KeePassXC Team <team@keepassxc.org>
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 2 or (at your option)
*  version 3 of the License.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "quickunlock/TouchID.h"

#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"
#include "crypto/CryptoHash.h"
#include "config-keepassx.h"

#include <botan/mem_ops.h>

#include <Foundation/Foundation.h>
#include <AppKit/AppKit.h>
#include <CoreFoundation/CoreFoundation.h>
#include <LocalAuthentication/LocalAuthentication.h>
#include <IOKit/IOKitLib.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QString>

namespace {
QByteArray getHardwareDeviceKey()
{
    QByteArray hwUuid;
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert) {
        CFTypeRef uuidAsCFString = IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
        if (uuidAsCFString) {
            char buffer[128];
            if (CFStringGetCString((CFStringRef)uuidAsCFString, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                hwUuid = QByteArray(buffer);
            }
            CFRelease(uuidAsCFString);
        }
        IOObjectRelease(platformExpert);
    }
    if (hwUuid.isEmpty()) {
        hwUuid = "KeePassXC_Default_Fallback_Device_Entropy";
    }

    CryptoHash hash(CryptoHash::Sha256);
    hash.addData(hwUuid);
    hash.addData("KeePassXC_Biometric_Protection_Salt_v1");
    return hash.result();
}

QString getTouchIDStoragePath(const QUuid& dbUuid)
{
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(baseDir);
    if (!dir.exists("touchid")) {
        dir.mkpath("touchid");
    }
    return dir.filePath(QString("touchid/%1.key").arg(dbUuid.toString(QUuid::WithoutBraces)));
}
} // namespace

QString TouchID::errorString() const
{
    return "";
}

static LAContext* s_activeContext = nil;

void TouchID::cancelPrompt()
{
    if (s_activeContext) {
        NSLog(@"[TouchID] cancelPrompt called! Invalidating s_activeContext.");
        [s_activeContext invalidate];
    }
}

void TouchID::reset()
{
    cancelPrompt();
    m_encryptedMasterKeys.clear();
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(baseDir + "/touchid");
    if (dir.exists()) {
        dir.removeRecursively();
    }
}

void TouchID::reset(const QUuid& dbUuid)
{
    if (!dbUuid.isNull()) {
        m_encryptedMasterKeys.remove(dbUuid);
        QString path = getTouchIDStoragePath(dbUuid);
        QFile::remove(path);
    }
}

bool TouchID::setKey(const QUuid& dbUuid, const QByteArray& passwordKey)
{
    if (passwordKey.isEmpty() || dbUuid.isNull()) {
        return false;
    }

    QByteArray deviceKey = getHardwareDeviceKey();
    QByteArray randomIV = randomGen()->randomArray(SymmetricCipher::defaultIvSize(SymmetricCipher::Aes256_GCM));

    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Encrypt, deviceKey, randomIV)) {
        return false;
    }

    QByteArray encrypted = passwordKey;
    if (!cipher.finish(encrypted)) {
        return false;
    }

    // Payload: IV + Encrypted Data
    QByteArray payload = randomIV + encrypted;

    QString filePath = getTouchIDStoragePath(dbUuid);
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }

    file.write(payload);
    file.flush();
    file.close();

    // Secure permissions: 0600 (owner only)
    file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);

    return true;
}

bool TouchID::hasKey(const QUuid& dbUuid) const
{
    if (dbUuid.isNull()) {
        return false;
    }
    QString filePath = getTouchIDStoragePath(dbUuid);
    return QFile::exists(filePath);
}

bool TouchID::getKey(const QUuid& dbUuid, QByteArray& passwordKey, const QString& dbName)
{
    passwordKey.clear();

    if (!hasKey(dbUuid)) {
        return false;
    }

    LAContext* context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @"Use Password";

    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

    __block BOOL authSuccess = NO;
    __block BOOL done = NO;

    NSString* reason;
    if (!dbName.isEmpty()) {
        reason = [NSString stringWithFormat:@"Unlock %@", dbName.toNSString()];
    } else {
        reason = @"Unlock KeePassXC";
    }

    [context evaluatePolicy:policy
            localizedReason:reason
                      reply:^(BOOL success, NSError* error) {
        NSLog(@"[TouchID] evaluatePolicy reply: success=%d, error=%@", success, error);
        authSuccess = success;
        done = YES;
    }];

    while (!done) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    }

    [context release];

    if (!authSuccess) {
        return false;
    }

    QString filePath = getTouchIDStoragePath(dbUuid);
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    QByteArray payload = file.readAll();
    file.close();

    int ivSize = SymmetricCipher::defaultIvSize(SymmetricCipher::Aes256_GCM);
    if (payload.size() <= ivSize) {
        return false;
    }

    QByteArray iv = payload.left(ivSize);
    QByteArray ciphertext = payload.mid(ivSize);
    QByteArray deviceKey = getHardwareDeviceKey();

    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, deviceKey, iv)) {
        return false;
    }

    if (!cipher.finish(ciphertext)) {
        return false;
    }

    passwordKey = ciphertext;
    return !passwordKey.isEmpty();
}

bool TouchID::isWatchAvailable()
{
#if XC_COMPILER_SUPPORT(WATCH_UNLOCK)
   @try {
      LAContext *context = [[LAContext alloc] init];
      LAPolicy policyCode = LAPolicyDeviceOwnerAuthenticationWithWatch;
      NSError *error;
      bool canAuthenticate = [context canEvaluatePolicy:policyCode error:&error];
      [context release];
      return canAuthenticate;
   } @catch (NSException *) {
      return false;
   }
#else
   return false;
#endif
}

bool TouchID::isTouchIdAvailable()
{
#if XC_COMPILER_SUPPORT(TOUCH_ID)
   @try {
      LAContext *context = [[LAContext alloc] init];
      LAPolicy policyCode = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
      NSError *error;
      bool canAuthenticate = [context canEvaluatePolicy:policyCode error:&error];
      [context release];
      return canAuthenticate;
   } @catch (NSException *) {
      return false;
   }
#else
   return false;
#endif
}

bool TouchID::isAvailable() const
{
   return isWatchAvailable() || isTouchIdAvailable();
}
