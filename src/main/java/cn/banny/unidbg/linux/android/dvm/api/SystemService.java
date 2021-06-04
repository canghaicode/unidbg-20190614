package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;
import unicorn.UnicornException;

public class SystemService extends DvmObject<String> {

    public static final String WIFI_SERVICE = "wifi";
    public static final String CONNECTIVITY_SERVICE = "connectivity";
    public static final String TELEPHONY_SERVICE = "phone";
    public static final String ACCESSIBILITY_SERVICE = "accessibility";
    public static final String KEYGUARD_SERVICE = "keyguard";
    public static final String ACTIVITY_SERVICE = "activity";

    public SystemService(VM vm, String serviceName) {
        super(getObjectType(vm, serviceName), serviceName);
    }

    private static DvmClass getObjectType(VM vm, String serviceName) {
        switch (serviceName) {
            case TELEPHONY_SERVICE:
                return vm.resolveClass("android/telephony/TelephonyManager");
            case WIFI_SERVICE:
                return vm.resolveClass("android/net/wifi/WifiManager");
            case CONNECTIVITY_SERVICE:
                return vm.resolveClass("android/net/ConnectivityManager");
            case ACCESSIBILITY_SERVICE:
                return vm.resolveClass("android/view/accessibility/AccessibilityManager");
            case KEYGUARD_SERVICE:
                return vm.resolveClass("android/app/KeyguardManager");
            case ACTIVITY_SERVICE:
                return vm.resolveClass("android.os.BinderProxy"); // android/app/ActivityManager
            default:
                throw new UnicornException("service failed: " + serviceName);
        }
    }

}
