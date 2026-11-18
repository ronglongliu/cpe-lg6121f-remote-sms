#import "FiberHomeSMSClient.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

NSErrorDomain const FiberHomeSMSClientErrorDomain = @"FiberHomeSMSClientErrorDomain";
static NSString * const kHost = @"home.mifon.com";
static NSString * const kRoot = @"/NetworkPlatform/rest";
static NSString * const kVersion = @"2.2.12";
static NSString * const kType = @"terminal";
static NSString * const kService = @"FiberHomeSMSClient.session";
static NSString * const kAccount = @"FiberHomeSMSClient";
static const NSUInteger kMaxResponse = 2 * 1024 * 1024;

static NSError *FError(NSInteger code, NSString *text) {
    return [NSError errorWithDomain:FiberHomeSMSClientErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey:text}];
}
static NSString *FString(id value) { return [value isKindOfClass:NSString.class] ? value : @""; }
static NSString *FJSON(NSArray<NSArray *> *pairs) {
    NSMutableArray *parts = [NSMutableArray arrayWithCapacity:pairs.count];
    for (NSArray *pair in pairs) {
        NSData *kd = [NSJSONSerialization dataWithJSONObject:pair[0] options:NSJSONWritingFragmentsAllowed error:nil];
        NSData *vd = [NSJSONSerialization dataWithJSONObject:pair[1] options:NSJSONWritingFragmentsAllowed error:nil];
        NSString *key = kd ? [[NSString alloc] initWithData:kd encoding:NSUTF8StringEncoding] : @"\"\"";
        NSString *value = vd ? [[NSString alloc] initWithData:vd encoding:NSUTF8StringEncoding] : @"null";
        [parts addObject:[NSString stringWithFormat:@"%@:%@",key,value]];
    }
    return [NSString stringWithFormat:@"{%@}",[parts componentsJoinedByString:@","]];
}
static NSString *FCompact(id obj) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingFragmentsAllowed error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"{}";
}
static NSString *FHex(const unsigned char *bytes, NSUInteger length) {
    NSMutableString *s = [NSMutableString stringWithCapacity:length * 2];
    for (NSUInteger i=0; i<length; i++) [s appendFormat:@"%02x",bytes[i]];
    return s;
}
static NSString *FSHA256(NSString *text) {
    NSData *d = [text dataUsingEncoding:NSUTF8StringEncoding]; unsigned char out[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes,(CC_LONG)d.length,out); return FHex(out,sizeof(out));
}
static NSString *FUUID(void) { return [[[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""] uppercaseString]; }

@interface FHSTicket : NSObject
@property(nonatomic,strong) NSMutableData *data;
@property(nonatomic,strong) NSError *error;
@property(nonatomic,strong) NSHTTPURLResponse *response;
@property(nonatomic,strong) dispatch_semaphore_t semaphore;
@end
@implementation FHSTicket
@end

@interface FHSNoRedirectDelegate : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
@property(nonatomic,strong) NSMutableDictionary<NSNumber *, FHSTicket *> *tickets;
@end
@implementation FHSNoRedirectDelegate
- (instancetype)init { if((self=[super init])) _tickets=[NSMutableDictionary dictionary]; return self; }
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    completionHandler(nil);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    FHSTicket *ticket; @synchronized(self){ticket=self.tickets[@(task.taskIdentifier)];}
    if(!ticket){completionHandler(NSURLSessionResponseCancel);return;}
    if(response.expectedContentLength>(int64_t)kMaxResponse){ticket.error=FError(4,@"HTTPS 响应超过大小限制。");completionHandler(NSURLSessionResponseCancel);return;}
    if([response isKindOfClass:NSHTTPURLResponse.class])ticket.response=(NSHTTPURLResponse *)response;
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data {
    FHSTicket *ticket; @synchronized(self){ticket=self.tickets[@(task.taskIdentifier)];}
    if(!ticket)return;
    if(data.length>kMaxResponse-ticket.data.length){ticket.error=FError(4,@"HTTPS 响应超过大小限制。");[task cancel];return;}
    [ticket.data appendData:data];
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    FHSTicket *ticket; @synchronized(self){ticket=self.tickets[@(task.taskIdentifier)];}
    if(!ticket)return;
    if(error&&!ticket.error)ticket.error=error;
    dispatch_semaphore_signal(ticket.semaphore);
}
@end

@interface FiberHomeSMSClient ()
@property(nonatomic,strong) NSURLSession *session;
@property(nonatomic,strong) FHSNoRedirectDelegate *httpDelegate;
@property(nonatomic,strong) NSMutableArray<NSDictionary *> *devices;
@property(nonatomic,copy,nullable) NSString *token;
@property(nonatomic,copy,nullable) NSString *username;
@property(nonatomic) BOOL cancelled;
@end

@implementation FiberHomeSMSClient
- (instancetype)init {
    if ((self=[super init])) {
        NSURLSessionConfiguration *c=NSURLSessionConfiguration.ephemeralSessionConfiguration;
        c.timeoutIntervalForRequest=20; c.timeoutIntervalForResource=30;
        c.requestCachePolicy=NSURLRequestReloadIgnoringLocalCacheData; c.HTTPShouldSetCookies=NO; c.HTTPCookieStorage=nil;
        NSOperationQueue *queue=[NSOperationQueue new]; queue.maxConcurrentOperationCount=1;
        _httpDelegate=[FHSNoRedirectDelegate new];
        _session=[NSURLSession sessionWithConfiguration:c delegate:_httpDelegate delegateQueue:queue]; _devices=[NSMutableArray array]; [self loadSession];
    }
    return self;
}
- (void)loadSession {
    NSDictionary *q=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:kService,(__bridge id)kSecAttrAccount:kAccount,(__bridge id)kSecReturnData:@YES,(__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitOne};
    CFTypeRef result=NULL; if(SecItemCopyMatching((__bridge CFDictionaryRef)q,&result)!=errSecSuccess)return;
    NSData *d=CFBridgingRelease(result); id obj=[NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if([obj isKindOfClass:NSDictionary.class]){self.token=FString(obj[@"token"]);self.username=FString(obj[@"username"]);}
}
- (BOOL)saveSession:(NSError **)error {
    NSData *d=[NSJSONSerialization dataWithJSONObject:@{@"token":self.token?:@"",@"username":self.username?:@""} options:0 error:error]; if(!d)return NO;
    NSDictionary *q=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:kService,(__bridge id)kSecAttrAccount:kAccount};
    OSStatus s=SecItemUpdate((__bridge CFDictionaryRef)q,(__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:d});
    if(s==errSecItemNotFound){NSMutableDictionary *a=[q mutableCopy];a[(__bridge id)kSecValueData]=d;a[(__bridge id)kSecAttrAccessible]=(__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;s=SecItemAdd((__bridge CFDictionaryRef)a,NULL);}
    if(s!=errSecSuccess){if(error)*error=FError(s,@"无法保存会话到本机 Keychain。");return NO;} return YES;
}
- (NSDictionary *)request:(NSString *)path method:(NSString *)method json:(NSString *)json query:(NSString *)query error:(NSError **)error {
    if(self.cancelled){if(error)*error=FError(1,@"请求已取消。");return nil;}
    NSString *ts=[NSString stringWithFormat:@"%.0f",NSDate.date.timeIntervalSince1970*1000.0],*uuid=FUUID();
    NSString *sig=FSHA256([NSString stringWithFormat:@"%@%@%@",ts,uuid,json?:@"{}"]);
    NSURLComponents *u=[NSURLComponents new];u.scheme=@"https";u.host=kHost;u.path=[kRoot stringByAppendingString:path];if(query.length)u.percentEncodedQuery=query;
    if(!u.URL){if(error)*error=FError(2,@"请求地址无效。");return nil;}
    NSMutableURLRequest *r=[NSMutableURLRequest requestWithURL:u.URL];r.HTTPMethod=method;r.timeoutInterval=20;
    [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];[r setValue:kType forHTTPHeaderField:@"appType"];
    [r setValue:ts forHTTPHeaderField:@"timestamp"];[r setValue:uuid forHTTPHeaderField:@"uuid"];[r setValue:sig forHTTPHeaderField:@"signature"];
    if(self.token.length)[r setValue:self.token forHTTPHeaderField:@"token"];
    if([method isEqualToString:@"POST"])r.HTTPBody=[json dataUsingEncoding:NSUTF8StringEncoding];
    FHSNoRedirectDelegate *delegate=self.httpDelegate;
    FHSTicket *ticket=[FHSTicket new];ticket.data=[NSMutableData data];ticket.semaphore=dispatch_semaphore_create(0);
    NSURLSessionDataTask *task=[self.session dataTaskWithRequest:r];
    @synchronized(delegate){delegate.tickets[@(task.taskIdentifier)]=ticket;}
    [task resume];
    if(dispatch_semaphore_wait(ticket.semaphore,dispatch_time(DISPATCH_TIME_NOW,25*NSEC_PER_SEC))!=0){[task cancel];@synchronized(delegate){[delegate.tickets removeObjectForKey:@(task.taskIdentifier)];}if(error)*error=FError(3,@"云端请求超时。");return nil;}
    @synchronized(delegate){[delegate.tickets removeObjectForKey:@(task.taskIdentifier)];}
    if(ticket.error){if(error)*error=ticket.error;return nil;}
    if(!ticket.response||ticket.response.statusCode<200||ticket.response.statusCode>=300){if(error)*error=FError(4,@"HTTPS 响应无效或超出大小限制。");return nil;}
    id obj=[NSJSONSerialization JSONObjectWithData:ticket.data options:NSJSONReadingFragmentsAllowed error:error];
    if(![obj isKindOfClass:NSDictionary.class]){if(error&&!*error)*error=FError(5,@"云端 JSON 响应格式无效。");return nil;}
    NSDictionary *dct=obj;if(![dct[@"resultCode"] isKindOfClass:NSNumber.class]||[dct[@"resultCode"] integerValue]!=0){if(error)*error=FError(6,@"烽火云端请求未通过。");return nil;}return dct;
}
- (BOOL)loginWithUsername:(NSString *)username password:(NSString *)password error:(NSError **)error {
    NSString *name=[username stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if(!name.length||!password.length){if(error)*error=FError(10,@"账号和密码不能为空。");return NO;}
    NSString *getJSON=FJSON(@[@[@"appVersion",kVersion],@[@"areaCode",@"86"],@[@"appType",kType]]);
    NSString *query=@"appType=terminal&appVersion=2.2.12&areaCode=86";
    if(![self request:@"/userInfo/getPlatform" method:@"GET" json:getJSON query:query error:error])return NO;
    NSString *body=FJSON(@[@[@"areaCode",@"86"],@[@"password",FSHA256(password)],@[@"clientType",@0],@[@"randomCode",@""],@[@"loginName",name],@[@"appVersion",kVersion]]);
    NSDictionary *res=[self request:@"/user/userLogin" method:@"POST" json:body query:nil error:error];if(!res)return NO;
    NSString *t=FString(res[@"token"]),*account=FString(res[@"username"]);if(!t.length||!account.length){if(error)*error=FError(11,@"登录响应缺少会话字段。");return NO;}
    self.token=t;self.username=account;if(![self saveSession:error]){self.token=nil;self.username=nil;return NO;}return YES;
}
- (NSArray<NSDictionary<NSString *,id> *> *)listBoundDevices:(NSError **)error {
    if(!self.token.length||!self.username.length){if(error)*error=FError(12,@"请先登录。");return nil;}
    NSString *body=FJSON(@[@[@"username",self.username],@[@"appType",kType],@[@"appVersion",kVersion],@[@"token",self.token]]);
    NSDictionary *res=[self request:@"/deviceBind/getAllDeviceByUser" method:@"POST" json:body query:nil error:error];if(!res)return nil;
    NSArray *items=[res[@"bindDeviceInfoVOs"] isKindOfClass:NSArray.class]?res[@"bindDeviceInfoVOs"]:nil;if(!items){if(error)*error=FError(13,@"设备列表响应格式无效。");return nil;}
        [self.devices removeAllObjects];NSMutableArray *out=[NSMutableArray array];
    for(id x in items){if(![x isKindOfClass:NSDictionary.class])continue;NSDictionary *d=x;NSString *mac=FString(d[@"mac"]);if(!mac.length)continue;
        NSString *model=FString(d[@"model"]);
        if([model caseInsensitiveCompare:@"LG6121F"]!=NSOrderedSame) continue;
        [self.devices addObject:d];NSString *name=FString(d[@"name"]);
        [out addObject:@{@"index":@(self.devices.count-1),@"name":name.length?name:(model.length?model:@"FiberHome device"),@"model":model}];}
    return [out copy];
}
- (NSDictionary *)invokeSMSCommand:(NSString *)command parameters:(NSDictionary *)params deviceAtIndex:(NSUInteger)idx timeout:(NSInteger)timeout error:(NSError **)error {
    // The sole invocation boundary has an explicit command and parameter allowlist.
    NSDictionary *allowed=@{@"SMS_UPGRADE_MESSAGE":[NSSet set],@"SMS_GET_MESSAGE":[NSSet setWithArray:@[@"recv_index_list",@"send_index_list"]],@"SMS_SEND_MESSAGE":[NSSet setWithArray:@[@"Sendtime",@"Receiver",@"Encode",@"Msg"]]};
    NSSet *keys=allowed[command];if(!keys){if(error)*error=FError(20,@"命令不在短信白名单中。");return nil;}
    for(id key in params)if(![key isKindOfClass:NSString.class]||![keys containsObject:key]){if(error)*error=FError(20,@"短信命令包含白名单之外的参数。");return nil;}
    if(!self.token.length||idx>=self.devices.count){if(error)*error=FError(21,@"请登录并刷新设备列表。");return nil;}
    NSString *mac=FString(self.devices[idx][@"mac"]);if(!mac.length){if(error)*error=FError(22,@"设备绑定字段缺失。");return nil;}
    NSMutableDictionary *cmd=[params mutableCopy]?:[NSMutableDictionary dictionary];cmd[@"CmdType"]=command;cmd[@"SequenceId"]=[NSString stringWithFormat:@"%x",arc4random_uniform(0xffffff)];
    NSString *req=FJSON(@[@[@"ID",FUUID()],@[@"Version",@1],@[@"Plugin_Name",@"Plugin_ID"],@[@"RPCMethod",@"Post"],@[@"Parameter",FCompact(cmd)]]);
    NSString *operatorID=[NSString stringWithFormat:@"%ld%u",(long)NSDate.date.timeIntervalSince1970,arc4random_uniform(1000)];
    NSString *body=FJSON(@[@[@"appVersion",kVersion],@[@"mac",mac],@[@"timeout",@(timeout)],@[@"token",self.token],@[@"appType",kType],@[@"reqParam",req],@[@"operatorId",operatorID]]);
    NSDictionary *outer=[self request:@"/device/invokeService" method:@"POST" json:body query:nil error:error];if(!outer)return nil;
    id env=outer[@"rspParam"];if([env isKindOfClass:NSString.class]){NSData *d=[FString(env) dataUsingEncoding:NSUTF8StringEncoding];env=d?[NSJSONSerialization JSONObjectWithData:d options:0 error:nil]:nil;}
    if(![env isKindOfClass:NSDictionary.class]){if(error)*error=FError(23,@"设备响应封装无效。");return nil;}
    id result=env[@"return_Parameter"];if([result isKindOfClass:NSString.class]){NSData *d=[[NSData alloc]initWithBase64EncodedString:result options:0];result=d?[NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingFragmentsAllowed error:nil]:nil;}
    if(![result isKindOfClass:NSDictionary.class]||![FString(result[@"CmdType"]) isEqualToString:command]){if(error)*error=FError(24,@"设备响应命令不匹配。");return nil;}
    id status=result[@"Status"];if(status&&!([status isKindOfClass:NSNumber.class]&&[status integerValue]==0)&&![FString(status)isEqualToString:@"0"]&&![FString(status)isEqualToString:@"success"]){if(error)*error=FError(25,@"设备没有确认该短信操作。");return nil;}return result;
}
- (NSArray<NSDictionary<NSString *,id> *> *)fetchMessagesForDeviceAtIndex:(NSUInteger)idx box:(FiberHomeSMSBox)box error:(NSError **)error {
    if(box!=FiberHomeSMSBoxInbox&&box!=FiberHomeSMSBoxSent){if(error)*error=FError(30,@"邮箱类型无效。");return nil;}
    NSDictionary *indexRes=[self invokeSMSCommand:@"SMS_UPGRADE_MESSAGE" parameters:@{} deviceAtIndex:idx timeout:10 error:error];if(!indexRes)return nil;
    NSString *key=box==FiberHomeSMSBoxInbox?@"recv_index_list":@"send_index_list";NSMutableArray *wanted=[NSMutableArray array];
    for(id item in ([indexRes[key] isKindOfClass:NSArray.class]?indexRes[key]:@[])){if(![item isKindOfClass:NSDictionary.class]||!item[@"Index"])continue;NSMutableDictionary *row=[@{@"Index":item[@"Index"]} mutableCopy];if(box==FiberHomeSMSBoxInbox)row[@"Isopened"]=item[@"Isopened"]?:@0;[wanted addObject:row];}
    if(!wanted.count)return @[];
    NSDictionary *args=@{@"recv_index_list":box==FiberHomeSMSBoxInbox?wanted:@[],@"send_index_list":box==FiberHomeSMSBoxSent?wanted:@[]};
    NSDictionary *res=[self invokeSMSCommand:@"SMS_GET_MESSAGE" parameters:args deviceAtIndex:idx timeout:10 error:error];if(!res)return nil;
    NSString *listKey=box==FiberHomeSMSBoxInbox?@"recv_msg_list":@"send_msg_list";NSMutableArray *out=[NSMutableArray array];
    for(id item in ([res[listKey] isKindOfClass:NSArray.class]?res[listKey]:@[])){if(![item isKindOfClass:NSDictionary.class])continue;NSDictionary *m=item;
        [out addObject:@{@"number":FString(m[@"Sender"]),@"text":FString(m[@"Msg"]),@"time":FString(m[@"Recvtime"]?:m[@"Sendtime"]),@"index":FString(m[@"Index"]),@"box":box==FiberHomeSMSBoxInbox?@"inbox":@"sent"}];}
    return [out copy];
}
- (NSDictionary<NSString *,id> *)sendSMS:(NSString *)text toNumber:(NSString *)number deviceAtIndex:(NSUInteger)idx error:(NSError **)error {
    NSString *n=[number stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSRegularExpression *rx=[NSRegularExpression regularExpressionWithPattern:@"^[+]?[0-9]{5,20}$" options:0 error:nil];
    if(![rx numberOfMatchesInString:n options:0 range:NSMakeRange(0,n.length)]||!text.length||text.length>500){if(error)*error=FError(40,@"号码或短信内容格式无效。");return nil;}
    BOOL han=[[NSRegularExpression regularExpressionWithPattern:@"[\\p{Han}]" options:0 error:nil]numberOfMatchesInString:text options:0 range:NSMakeRange(0,text.length)]>0;
    NSDateFormatter *f=[NSDateFormatter new];f.locale=[[NSLocale alloc]initWithLocaleIdentifier:@"en_US_POSIX"];f.dateFormat=@"yyyy/MM/dd HH:mm";
    NSDictionary *params=@{@"Sendtime":[f stringFromDate:NSDate.date],@"Receiver":n,@"Encode":han?@"8":@"246",@"Msg":text};
    if(![self invokeSMSCommand:@"SMS_SEND_MESSAGE" parameters:params deviceAtIndex:idx timeout:30 error:error])return nil;
    return @{@"accepted":@YES,@"delivered":@NO,@"message":@"设备/云端已接受请求；是否送达尚未确认，请手动刷新已发短信。"};
}
- (void)logout {
    self.token=nil;self.username=nil;[self.devices removeAllObjects];
    NSDictionary *q=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:kService,(__bridge id)kSecAttrAccount:kAccount};SecItemDelete((__bridge CFDictionaryRef)q);
}
- (void)cancel { self.cancelled=YES;[self.session invalidateAndCancel];[self.devices removeAllObjects]; }
@end
