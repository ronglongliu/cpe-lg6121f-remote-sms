#import "../src/FiberHomeSMSClient.h"

/// 在串行后台队列由用户点击触发后调用；完成后切回主线程更新 UI。密码来自安全文本框，不要打印。
static BOOL FHSUserInitiatedLogin(FiberHomeSMSClient *client,
                                NSString *account,
                                NSString *password,
                                NSError **error) {
    return [client loginWithUsername:account password:password error:error];
}

/// 在用户点击“刷新收件箱/发件箱”后调用；没有轮询。
static NSArray<NSDictionary<NSString *, id> *> * _Nullable
FHSUserInitiatedRefresh(FiberHomeSMSClient *client,
                        NSUInteger deviceIndex,
                        FiberHomeSMSBox box,
                        NSError **error) {
    return [client fetchMessagesForDeviceAtIndex:deviceIndex box:box error:error];
}

/// 在用户明确点击“发送”后调用。返回 accepted=YES 不代表运营商已送达。
static NSDictionary<NSString *, id> * _Nullable
FHSUserInitiatedSend(FiberHomeSMSClient *client,
                     NSString *message,
                     NSString *recipient,
                     NSUInteger deviceIndex,
                     NSError **error) {
    return [client sendSMS:message toNumber:recipient deviceAtIndex:deviceIndex error:error];
}

/// 退出账号时调用；不打印令牌、手机号或短信正文。
static void FHSUserInitiatedLogout(FiberHomeSMSClient *client) {
    [client logout];
}
