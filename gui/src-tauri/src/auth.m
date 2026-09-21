#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

int cloak_authenticate_biometrics(const char *reason_str) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];

        NSError *evalError = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&evalError]) {
            NSLog(@"[Cloak Auth] Device cannot evaluate policy: %@", evalError);
            return 0;
        }

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int result = 0;
        NSString *reason = reason_str ? [NSString stringWithUTF8String:reason_str] : @"Touch ID or enter your password to unlock your vault.";

        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:reason
                          reply:^(BOOL success, NSError * _Nullable error) {
            if (success) {
                result = 1;
            } else {
                NSLog(@"[Cloak Auth] Biometric authentication failed or cancelled: %@", error);
                result = 0;
            }
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}
