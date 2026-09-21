#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

int cloak_authenticate_biometrics(const char *reason_str) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        context.localizedFallbackTitle = @"Enter Password";

        NSError *evalError = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&evalError]) {
            // If device owner authentication is not configured on this machine, permit unlock
            return 1;
        }

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int result = 0;
        NSString *reason = reason_str ? [NSString stringWithUTF8String:reason_str] : @"Unlock Cloak Hardware Vault";

        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:reason
                          reply:^(BOOL success, NSError * _Nullable error) {
            (void)error;
            result = success ? 1 : 0;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}
