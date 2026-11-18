#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const FiberHomeSMSClientErrorDomain;

typedef NS_ENUM(NSInteger, FiberHomeSMSBox) {
    FiberHomeSMSBoxInbox = 0,
    FiberHomeSMSBoxSent = 1,
};

/// Minimal client for FiberHome LG6121F (RP0108) cloud account SMS operations.
/// No requests are made until an explicit method is called.
@interface FiberHomeSMSClient : NSObject

/// Production initializer. Uses the vendor HTTPS endpoint and device-only Keychain.
- (instancetype)init;

/// Login is explicit. Password is SHA-256 hex encoded before transmission.
- (BOOL)loginWithUsername:(NSString *)username
                 password:(NSString *)password
                    error:(NSError * _Nullable * _Nullable)error;

/// Returns minimal display fields and an opaque array index; MACs are not exposed.
- (nullable NSArray<NSDictionary<NSString *, id> *> *)listBoundDevices:(NSError * _Nullable * _Nullable)error;

/// Fetches a chosen mailbox on demand. No polling is performed.
- (nullable NSArray<NSDictionary<NSString *, id> *> *)fetchMessagesForDeviceAtIndex:(NSUInteger)deviceIndex
                                                                               box:(FiberHomeSMSBox)box
                                                                              error:(NSError * _Nullable * _Nullable)error;

/// Cloud acceptance is reported separately from delivery, which this API cannot confirm.
- (nullable NSDictionary<NSString *, id> *)sendSMS:(NSString *)text
                                            toNumber:(NSString *)number
                               deviceAtIndex:(NSUInteger)deviceIndex
                                          error:(NSError * _Nullable * _Nullable)error;

- (void)logout;
- (void)cancel;

@end

NS_ASSUME_NONNULL_END
