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

#include "config-keepassx.h"

#include <botan/mem_ops.h>

#include <AppKit/AppKit.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <LocalAuthentication/LocalAuthentication.h>
#include <Security/Security.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QSaveFile>
#include <QStandardPaths>
#include <QString>
#include <QtEndian>

#include <atomic>
#include <memory>
#include <mutex>

namespace {
constexpr char kSecureEnclaveMagic[] = "KXSE02";
constexpr int kSecureEnclaveMagicLen = 6;
constexpr int kDbUuidRawLen = 16;
constexpr quint32 kMaxTokenOidLen = 4096;
constexpr qint64 kMaxKeyFileSize = 65536;

std::mutex s_contextMutex;
LAContext* s_activeContext = nil;
std::atomic<bool> s_promptInProgress{false};

struct PromptState
{
    std::atomic<bool> done{false};
    std::atomic<bool> authSuccess{false};
};

struct PromptGuard
{
    ~PromptGuard()
    {
        s_promptInProgress.store(false, std::memory_order_release);
    }
};

QString getTouchIDStorageDir()
{
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return QDir(baseDir).filePath(QStringLiteral("touchid"));
}

QString getTouchIDStoragePath(const QUuid& dbUuid, bool createDir)
{
    QString touchIdDir = getTouchIDStorageDir();
    if (createDir) {
        QDir dir;
        if (!dir.exists(touchIdDir) && !dir.mkpath(touchIdDir)) {
            return {};
        }
        if (!QFile::setPermissions(touchIdDir, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner)) {
            return {};
        }
        @autoreleasepool {
            NSURL* dirUrl = [NSURL fileURLWithPath:touchIdDir.toNSString() isDirectory:YES];
            [dirUrl setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
        }
    }
    return QDir(touchIdDir).filePath(QString("%1.key").arg(dbUuid.toString(QUuid::WithoutBraces)));
}

SecAccessControlCreateFlags biometricAccessControlFlags()
{
    SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet;
#if XC_COMPILER_SUPPORT(WATCH_UNLOCK)
#if defined(MAC_OS_VERSION_15_0) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_15_0
    flags = flags | kSecAccessControlOr | kSecAccessControlCompanion;
#else
    flags = flags | kSecAccessControlOr | kSecAccessControlWatch;
#endif
#endif
    return flags;
}
} // namespace

QString TouchID::errorString() const
{
    return m_error;
}

void TouchID::cancelPrompt()
{
    LAContext* ctx = nil;
    {
        std::lock_guard<std::mutex> lock(s_contextMutex);
        if (s_activeContext) {
            ctx = [s_activeContext retain];
        }
    }
    if (ctx) {
        [ctx invalidate];
        [ctx release];
    }
}

void TouchID::reset()
{
    cancelPrompt();
    QDir dir(getTouchIDStorageDir());
    if (dir.exists()) {
        dir.removeRecursively();
    }
}

void TouchID::reset(const QUuid& dbUuid)
{
    if (!dbUuid.isNull()) {
        QString path = getTouchIDStoragePath(dbUuid, false);
        QFile::remove(path);
    }
}

bool TouchID::setKey(const QUuid& dbUuid, const QByteArray& passwordKey)
{
    m_error.clear();

    if (passwordKey.isEmpty() || dbUuid.isNull()) {
        return false;
    }

    QString filePath = getTouchIDStoragePath(dbUuid, true);
    if (filePath.isEmpty()) {
        m_error = QObject::tr("Failed to prepare Touch ID key storage directory.");
        return false;
    }

    @autoreleasepool {
        CFErrorRef error = nullptr;
        SecAccessControlRef sac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            biometricAccessControlFlags(),
            &error);
        if (!sac) {
            if (error) {
                CFRelease(error);
            }
            m_error = QObject::tr("Failed to create Secure Enclave access control.");
            return false;
        }

        NSDictionary* attrs = @{
            (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits : @256,
            (__bridge id)kSecAttrTokenID : (__bridge id)kSecAttrTokenIDSecureEnclave,
            (__bridge id)kSecPrivateKeyAttrs : @{
                (__bridge id)kSecAttrIsPermanent : @NO,
                (__bridge id)kSecAttrAccessControl : (__bridge id)sac
            }
        };

        SecKeyRef privKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);
        CFRelease(sac);
        if (!privKey) {
            if (error) {
                CFRelease(error);
            }
            m_error = QObject::tr("Failed to generate Secure Enclave key.");
            return false;
        }

        CFDictionaryRef keyAttrs = SecKeyCopyAttributes(privKey);
        if (!keyAttrs) {
            CFRelease(privKey);
            return false;
        }

        NSData* tokenOID = [(__bridge NSDictionary*)keyAttrs objectForKey:@"toid"];
        QByteArray tokenOidBytes;
        if (tokenOID && tokenOID.length > 0 && tokenOID.length <= kMaxTokenOidLen) {
            tokenOidBytes = QByteArray(static_cast<const char*>(tokenOID.bytes), static_cast<int>(tokenOID.length));
        }
        CFRelease(keyAttrs);

        if (tokenOidBytes.isEmpty()) {
            CFRelease(privKey);
            return false;
        }

        SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
        CFRelease(privKey);
        if (!pubKey) {
            return false;
        }

        // Bind dbUuid inside the encrypted plaintext to prevent cross-database key swapping
        QByteArray plainBuf = dbUuid.toRfc4122();
        plainBuf.append(passwordKey);

        NSData* plaintextData = [NSData dataWithBytesNoCopy:plainBuf.data()
                                                     length:static_cast<NSUInteger>(plainBuf.size())
                                               freeWhenDone:NO];
        CFDataRef ciphertextRef = SecKeyCreateEncryptedData(
            pubKey,
            kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
            (__bridge CFDataRef)plaintextData,
            &error);
        CFRelease(pubKey);
        Botan::secure_scrub_memory(plainBuf.data(), static_cast<size_t>(plainBuf.size()));
        plainBuf.clear();

        if (!ciphertextRef) {
            if (error) {
                CFRelease(error);
            }
            m_error = QObject::tr("Failed to encrypt key with Secure Enclave.");
            return false;
        }

        QByteArray ciphertextBytes(reinterpret_cast<const char*>(CFDataGetBytePtr(ciphertextRef)),
                                   static_cast<int>(CFDataGetLength(ciphertextRef)));
        CFRelease(ciphertextRef);

        // Payload: Magic ("KXSE02") + uint32_be(toidLen) + tokenOID + ECIES ciphertext
        QByteArray payload;
        payload.reserve(kSecureEnclaveMagicLen + static_cast<int>(sizeof(quint32)) + tokenOidBytes.size()
                        + ciphertextBytes.size());
        payload.append(kSecureEnclaveMagic, kSecureEnclaveMagicLen);

        quint32 toidLenBe = qToBigEndian(static_cast<quint32>(tokenOidBytes.size()));
        payload.append(reinterpret_cast<const char*>(&toidLenBe), sizeof(toidLenBe));
        payload.append(tokenOidBytes);
        payload.append(ciphertextBytes);

        QSaveFile file(filePath);
        if (!file.open(QIODevice::WriteOnly)) {
            return false;
        }

        // Secure permissions: 0600 (owner only) before writing payload and committing
        if (!file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)) {
            file.cancelWriting();
            return false;
        }

        if (file.write(payload) != payload.size()) {
            file.cancelWriting();
            return false;
        }

        if (!file.commit()) {
            return false;
        }

        return true;
    }
}

bool TouchID::hasKey(const QUuid& dbUuid) const
{
    if (dbUuid.isNull()) {
        return false;
    }
    QFileInfo info(getTouchIDStoragePath(dbUuid, false));
    return info.exists() && info.isFile() && !info.isSymLink();
}

bool TouchID::getKey(const QUuid& dbUuid, QByteArray& passwordKey, const QString& dbName)
{
    passwordKey.clear();
    m_error.clear();

    if (!hasKey(dbUuid)) {
        return false;
    }

    bool expected = false;
    if (!s_promptInProgress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return false;
    }
    PromptGuard guard;

    QString filePath = getTouchIDStoragePath(dbUuid, false);
    QFileInfo fileInfo(filePath);
    if (!fileInfo.isFile() || fileInfo.isSymLink() || fileInfo.size() <= 0 || fileInfo.size() > kMaxKeyFileSize) {
        QFile::remove(filePath);
        m_error = QObject::tr("Stored Touch ID key file is invalid. Please unlock with your password to re-enable Touch ID.");
        return false;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    QByteArray payload = file.read(kMaxKeyFileSize);
    file.close();

    const int minHeaderLen = kSecureEnclaveMagicLen + static_cast<int>(sizeof(quint32));
    if (payload.size() <= minHeaderLen
        || memcmp(payload.constData(), kSecureEnclaveMagic, kSecureEnclaveMagicLen) != 0) {
        // Remove legacy or corrupted key file so user can cleanly re-enroll
        QFile::remove(filePath);
        m_error = QObject::tr("Stored Touch ID credentials use an outdated format and were cleared. Please unlock with your password to re-enable Touch ID.");
        return false;
    }

    quint32 toidLenBe = 0;
    memcpy(&toidLenBe, payload.constData() + kSecureEnclaveMagicLen, sizeof(toidLenBe));
    quint32 toidLen = qFromBigEndian(toidLenBe);

    if (toidLen == 0 || toidLen > kMaxTokenOidLen
        || payload.size() <= minHeaderLen + static_cast<int>(toidLen)) {
        QFile::remove(filePath);
        m_error = QObject::tr("Stored Touch ID key file is corrupted and was cleared. Please unlock with your password to re-enable Touch ID.");
        return false;
    }

    QByteArray tokenOidBytes = payload.mid(minHeaderLen, static_cast<int>(toidLen));
    QByteArray ciphertextBytes = payload.mid(minHeaderLen + static_cast<int>(toidLen));

    @autoreleasepool {
        LAContext* context = [[LAContext alloc] init];
        context.localizedFallbackTitle = @"Use Password";

        LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
#if XC_COMPILER_SUPPORT(WATCH_UNLOCK)
        if (@available(macOS 10.15, *)) {
            if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch error:nil]) {
                policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch;
            }
        }
#endif

        auto state = std::make_shared<PromptState>();

        NSString* reason;
        if (!dbName.isEmpty()) {
            reason = [NSString stringWithFormat:@"Unlock %@", dbName.toNSString()];
        } else {
            reason = @"Unlock KeePassXC";
        }

        {
            std::lock_guard<std::mutex> lock(s_contextMutex);
            if (s_activeContext) {
                [s_activeContext release];
            }
            s_activeContext = [context retain];
        }

        [context evaluatePolicy:policy
                localizedReason:reason
                          reply:^(BOOL success, NSError* error) {
            Q_UNUSED(error);
            state->authSuccess.store(success == YES, std::memory_order_relaxed);
            state->done.store(true, std::memory_order_release);
        }];

        while (!state->done.load(std::memory_order_acquire)) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 50);
        }

        {
            std::lock_guard<std::mutex> lock(s_contextMutex);
            if (s_activeContext == context) {
                [s_activeContext release];
                s_activeContext = nil;
            }
        }

        if (!state->authSuccess.load(std::memory_order_relaxed)) {
            [context release];
            return false;
        }

        NSData* tokenOID = [NSData dataWithBytes:tokenOidBytes.constData()
                                          length:static_cast<NSUInteger>(tokenOidBytes.size())];
        NSDictionary* restoreAttrs = @{
            (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrTokenID : (__bridge id)kSecAttrTokenIDSecureEnclave,
            (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
            @"toid" : tokenOID,
            (__bridge id)kSecUseAuthenticationContext : context
        };

        CFErrorRef error = nullptr;
        SecKeyRef restoredKey = SecKeyCreateWithData((__bridge CFDataRef)[NSData data],
                                                     (__bridge CFDictionaryRef)restoreAttrs,
                                                     &error);

        if (!restoredKey) {
            [context release];
            if (error) {
                qWarning("TouchID: SecKeyCreateWithData failed: %s",
                         [[(__bridge NSError*)error localizedDescription] UTF8String]);
                CFRelease(error);
            }
            QFile::remove(filePath);
            m_error = QObject::tr("Stored Touch ID credentials are no longer valid. Please unlock with your password to re-enable Touch ID.");
            return false;
        }

        NSData* ciphertextData = [NSData dataWithBytesNoCopy:const_cast<char*>(ciphertextBytes.constData())
                                                      length:static_cast<NSUInteger>(ciphertextBytes.size())
                                                freeWhenDone:NO];
        CFDataRef decryptedRef = SecKeyCreateDecryptedData(
            restoredKey,
            kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
            (__bridge CFDataRef)ciphertextData,
            &error);
        CFRelease(restoredKey);
        [context release];

        if (!decryptedRef) {
            if (error) {
                qWarning("TouchID: SecKeyCreateDecryptedData failed: %s",
                         [[(__bridge NSError*)error localizedDescription] UTF8String]);
                CFRelease(error);
            }
            QFile::remove(filePath);
            m_error = QObject::tr("Stored Touch ID credentials are no longer valid (for example, after changing fingerprints). Please unlock with your password to re-enable Touch ID.");
            return false;
        }

        const CFIndex decryptedLen = CFDataGetLength(decryptedRef);
        const UInt8* decryptedPtr = CFDataGetBytePtr(decryptedRef);
        const QByteArray expectedUuid = dbUuid.toRfc4122();

        if (!decryptedPtr || decryptedLen <= kDbUuidRawLen
            || !Botan::same_mem(decryptedPtr,
                                reinterpret_cast<const uint8_t*>(expectedUuid.constData()),
                                static_cast<size_t>(kDbUuidRawLen))) {
            CFRelease(decryptedRef);
            QFile::remove(filePath);
            m_error = QObject::tr("Stored Touch ID credentials did not match this database and were cleared. Please unlock with your password to re-enable Touch ID.");
            return false;
        }

        passwordKey = QByteArray(reinterpret_cast<const char*>(decryptedPtr + kDbUuidRawLen),
                                 static_cast<int>(decryptedLen - kDbUuidRawLen));
        CFRelease(decryptedRef);
        return !passwordKey.isEmpty();
    }
}

bool TouchID::isWatchAvailable()
{
#if XC_COMPILER_SUPPORT(WATCH_UNLOCK)
    @try {
        LAContext* context = [[LAContext alloc] init];
        LAPolicy policyCode = LAPolicyDeviceOwnerAuthenticationWithWatch;
        NSError* error;
        bool canAuthenticate = [context canEvaluatePolicy:policyCode error:&error];
        [context release];
        return canAuthenticate;
    } @catch (NSException*) {
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
        LAContext* context = [[LAContext alloc] init];
        LAPolicy policyCode = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
        NSError* error;
        bool canAuthenticate = [context canEvaluatePolicy:policyCode error:&error];
        [context release];
        return canAuthenticate;
    } @catch (NSException*) {
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
