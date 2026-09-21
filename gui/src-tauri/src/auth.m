#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

int cloak_authenticate_biometrics(const char *reason_str) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        // Empty fallback title hides the password fallback button so Touch ID is strictly prompted
        context.localizedFallbackTitle = @"";

        NSError *evalError = nil;
        BOOL canBio = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&evalError];

        LAPolicy policy = canBio ? LAPolicyDeviceOwnerAuthenticationWithBiometrics : LAPolicyDeviceOwnerAuthentication;
        if (![context canEvaluatePolicy:policy error:&evalError]) {
            NSLog(@"[Cloak Auth] Device cannot evaluate policy: %@", evalError);
            return 0;
        }

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int result = 0;
        NSString *reason = reason_str ? [NSString stringWithUTF8String:reason_str] : @"Unlock Cloak Hardware Vault";

        [context evaluatePolicy:policy
                localizedReason:reason
                          reply:^(BOOL success, NSError * _Nullable error) {
            if (success) {
                NSLog(@"[Cloak Auth] Biometric authentication SUCCEEDED");
                result = 1;
            } else {
                NSLog(@"[Cloak Auth] Biometric authentication FAILED or CANCELLED: %@", error);
                result = 0;
            }
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}
