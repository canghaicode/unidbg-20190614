package cn.banny.unidbg.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.Arm32RegisterContext;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.hookzz.HookEntryInfo;
import cn.banny.unidbg.hook.hookzz.HookZz;
import cn.banny.unidbg.hook.hookzz.IHookZz;
import cn.banny.unidbg.hook.hookzz.WrapCallback;
import cn.banny.unidbg.hook.xhook.IxHook;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.XHookImpl;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.linux.android.dvm.api.ClassLoader;
import cn.banny.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import cn.banny.unidbg.linux.android.dvm.wrapper.DvmInteger;
import cn.banny.unidbg.linux.file.ByteArrayFileIO;
import cn.banny.unidbg.linux.file.SimpleFileIO;
import cn.banny.unidbg.memory.Memory;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class XSignso extends AbstractJni implements IOResolver {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator();
    }

    private final ARMEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass Native;

    ClassLoader securityBodyClassLoader = null;

    private XSignso() throws IOException {
//        Logger.getLogger("cn.banny.unidbg.AbstractEmulator").setLevel(Level.DEBUG);

        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(APK_FILE);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary("sgmainso-6.5.22", false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        dm = vm.loadLibrary("sgsecuritybodyso-6.5.28", false);
        dm.callJNI_OnLoad(emulator);
        dm = vm.loadLibrary("sgmiddletierso-6.5.24", false);
        dm.callJNI_OnLoad(emulator);

        Native = vm.resolveClass("com.taobao.wireless.security.adapter.JNICLibrary".replace(".", "/"));
    }

    private static final String APK_INSTALL_PATH = "/data/app/com.taobao.etao-9d70gDD153ymsdrZ8eSAnA==/base.apk";
    private static final File APK_FILE = new File("src/test/resources/app/etao.apk");

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        if (pathname.equals(APK_INSTALL_PATH)) {
            return new SimpleFileIO(oflags, APK_FILE, pathname);
        }

        if (("/proc/self/status").equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, "TracerPid:\t0\nState:\tr\n".getBytes());
        }
        if (("/proc/" + emulator.getPid() + "/stat").equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, (emulator.getPid() + " (a.out) R 6723 6873 6723 34819 6873 8388608 77 0 0 0 41958 31 0 0 25 0 3 0 5882654 1409024 56 4294967295 134512640 134513720 3215579040 0 2097798 0 0 0 0 0 0 0 17 0 0 0\n").getBytes());
        }
        if (("/proc/" + emulator.getPid() + "/wchan").equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, "sys_epoll".getBytes());
        }

        return null;
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        XSignso test = new XSignso();
        test.test();
        test.destroy();
    }

    private void test() {
        IHookZz hookZz = HookZz.getInstance(emulator);
        System.out.println("module.base -> :0x" + Long.toHexString(module.base));
        hookZz.wrap(module.base + 0xcc29, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                Object[] objects = (Object[]) vm.getObject(ctx.getLongArg(3) & 0xffffffffL).getValue();
//                System.out.println("hook -> " + ctx.getLongArg(2) + " -> R3=" + objects.toString() + ", R10=0x" + Long.toHexString(ctx.getR10Long()));
//                for (int i = 0; i < objects.length; i++){
//                    System.out.println("\t\t-> " + objects[i]);
//                }
            }
        });
        //hook doCommandForString
        hookZz.wrap(module.base + 0x1629b, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                Object[] objects = (Object[]) vm.getObject(ctx.getLongArg(3) & 0xffffffffL).getValue();
//                System.out.println("hook -> " + ctx.getLongArg(2) + " -> R3=" + objects.toString() + ", R10=0x" + Long.toHexString(ctx.getR10Long()));
//                for (int i = 0; i < objects.length; i++){
//                    System.out.println("\t\t-> " + objects[i]);
//                }
            }
        });

        DvmObject context = vm.resolveClass("com/taobao/sns/ISApplication").newObject(null);

        long start = System.currentTimeMillis();
        Number ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10101,
                new ArrayObject(context, DvmInteger.valueOf(vm, 3), new StringObject(vm, ""), new StringObject(vm, new File("target/app_SGLib").getAbsolutePath()), new StringObject(vm, ""))
        );
        long hash = ret.intValue() & 0xffffffffL;
        DvmObject dvmObject = vm.getObject(hash);
        System.out.println("10101 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10102,
                new ArrayObject(new StringObject(vm, "main"), new StringObject(vm, "6.5.22"),
                        new StringObject(vm, "E:\\Learn\\unidbg-20190613\\src\\test\\resources\\example_binaries\\armeabi-v7a\\libsgmainso-6.5.22.so")));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10102 -> 【libsgmainso-6.5.22.so】 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        //libsgsecuritybodyso-6.5.28
        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10102,
                new ArrayObject(new StringObject(vm, "securitybody"), new StringObject(vm, "6.5.28"),
                        new StringObject(vm, "E:\\Learn\\unidbg-20190613\\src\\test\\resources\\example_binaries\\armeabi-v7a\\libsgsecuritybodyso-6.5.28.so")));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10102 -> 【libsgsecuritybodyso-6.5.28】 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();
        //10602
        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10602,
                new ArrayObject(DvmInteger.valueOf(vm, 0), new StringObject(vm, "")));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10602 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10602,
                new ArrayObject(DvmInteger.valueOf(vm, 0), null));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10602 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();
        //22301
//        start = System.currentTimeMillis();
//        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
//                22301,
//                new ArrayObject(DvmInteger.valueOf(vm, 0)));
//        hash = ret.intValue() & 0xffffffffL;
//        dvmObject = vm.getObject(hash);
//        System.out.println("22301 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
//        vm.deleteLocalRefs();

        //libsgmiddletierso-6.5.24.so
        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10102,
                new ArrayObject(new StringObject(vm, "middletier"), new StringObject(vm, "6.5.24"),
                        new StringObject(vm, "E:\\Learn\\unidbg-20190613\\src\\test\\resources\\example_binaries\\armeabi-v7a\\libsgmiddletierso-6.5.24.so")));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10102 -> 【libsgmiddletierso-6.5.24】 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();
        //70201
//        start = System.currentTimeMillis();
//        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
//                70201,
//                new ArrayObject(new StringObject(vm, "mwua"), new StringObject(vm, "sgcipher")));
//        hash = ret.intValue() & 0xffffffffL;
//        dvmObject = vm.getObject(hash);
//        System.out.println("70201 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
//        vm.deleteLocalRefs();
        //70101
//        start = System.currentTimeMillis();
//        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
//                70101,
//                new ArrayObject(null));
//        hash = ret.intValue() & 0xffffffffL;
//        dvmObject = vm.getObject(hash);
//        System.out.println("70101 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
//        vm.deleteLocalRefs();
        //10502
//        start = System.currentTimeMillis();
//        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
//                10502,
//                new ArrayObject(DvmInteger.valueOf(vm, 6),));
//        hash = ret.intValue() & 0xffffffffL;
//        dvmObject = vm.getObject(hash);
//        System.out.println("70101 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
//        vm.deleteLocalRefs();

        Map<String, String> map = new HashMap<>();
        map.put("INPUT", "YHPAD8SWj+gDALwiyqQdaUNN21783927");
        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10401,
                new ArrayObject(vm.resolveClass("java/util/HashMap").newObject(map),
                        new StringObject(vm, "21783927"), DvmInteger.valueOf(vm, 3), null, DvmBoolean.valueOf(vm, true)));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10401 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();


        //12611
        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                12611,
                new ArrayObject(vm.resolveClass("com/taobao/sns/app/advertise/SplashAdActivity").newObject(null), DvmInteger.valueOf(vm, 4), new StringObject(vm, "com.taobao.sns.app.advertise.SplashAdActivity"), vm.resolveClass("android/os/Handler").newObject(null)));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("12611 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        start = System.currentTimeMillis();
        long timestamp = start / 1000;
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                70102,
                new ArrayObject(new StringObject(vm, "21783927"), new StringObject(vm, "YHPAD8SWj+gDALwiyqQdaUNN&&&21783927&c64691d9e52aa725f910cceb9e4212da&" + timestamp + "&mtop.common.gettimestamp&1.0&&10019998@etao_android_8.29.2&AmaGermHzPICx1YWwN725S1WF0knlYcTZ_knQ2CO2nY7&&&openappkey=DEFAULT_AUTH&27&&&&&&&"),
                        DvmBoolean.valueOf(vm, false), DvmInteger.valueOf(vm, 0), new StringObject(vm, "mtop.common.gettimestamp"), new StringObject(vm, "pageName=&pageId="),
                        null, null, null));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("70102 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                70102,
                new ArrayObject(new StringObject(vm, "21783927"), new StringObject(vm, "YHPAD8SWj+gDALwiyqQdaUNN&&&21783927&d40956d318541ebe2a992db318066950&" + timestamp + "&mtop.alimama.etao.config.query&1.0&&10019998@etao_android_8.29.2&AmaGermHzPICx1YWwN725S1WF0knlYcTZ_knQ2CO2nY7&&&openappkey=DEFAULT_AUTH&27&&&&&&&"),
                        DvmBoolean.valueOf(vm, false), DvmInteger.valueOf(vm, 0), new StringObject(vm, "mtop.alimama.etao.config.query"), new StringObject(vm, "pageName=&pageId="),
                        null, null, null));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("70102 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();
    }

    @Override
    public DvmObject callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
//            case "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->getMainPluginClassLoader()Ljava/lang/ClassLoader;":
            case "com/alibaba/wireless/security/securitybody/SecurityGuardSecurityBodyPlugin->getPluginClassLoader()Ljava/lang/ClassLoader;":
                securityBodyClassLoader = new ClassLoader(vm, "dalvik.system.PathClassLoader[DexPathList[[zip file \"/example_binaries/armeabi-v7a/libsgsecuritybody.so\"],nativeLibraryDirectories=[/data/app/com.taobao.etao-2/lib/arm, /target/app_SGLib/app_1616639107/main, /system/lib, /vendor/lib]]]");
                System.out.println("securityBodyClassLoader:" + securityBodyClassLoader);
//                return vm.resolveClass("java/lang/ClassLoader").newObject(null);
                return securityBodyClassLoader;
            case "com/taobao/wireless/security/adapter/common/SPUtility2->readFromSPUnified(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                StringObject a1 = varArg.getObject(0);
                StringObject a2 = varArg.getObject(1);
                StringObject a3 = varArg.getObject(2);
                System.out.println("readFromSPUnified a1=" + a1 + ", a2=" + a2 + ", a3=" + a3);
                return null;
            /*case "com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForString(I)Ljava/lang/String;":
                int value = varArg.getInt(0);
                System.out.println("com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForString value=" + value);
                if (value == 122)
                    return new StringObject(vm, "com.taobao.etao");
//                else if (value == 135)
//                    return new StringObject(vm, "YHPAD8SWj+gDALwiyqQdaUNN");
                return null;*/
            case "com/taobao/dp/util/CallbackHelper->getInstance()Lcom/taobao/dp/util/CallbackHelper;":
                return vm.resolveClass("com/taobao/dp/util/CallbackHelper").newObject(null);
        }

        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/alibaba/wireless/security/open/SecException-><init>(Ljava/lang/String;I)V": {
                StringObject msg = varArg.getObject(0);
                int value = varArg.getInt(1);
                return dvmClass.newObject(msg.getValue() + "[" + value + "]");
            }
            case "java/lang/Integer-><init>(I)V":
                int value = varArg.getInt(0);
                return DvmInteger.valueOf(vm, value);
            case "java/lang/Long-><init>(J)V": {
                StringObject msg = varArg.getObject(0);
                int val = varArg.getInt(1);
                return dvmClass.newObject(val);
            }
        }

        return super.newObject(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/util/HashMap->keySet()Ljava/util/Set;": {
                HashMap map = (HashMap) dvmObject.getValue();
                return vm.resolveClass("java/util/Set").newObject(map.keySet());
            }
            case "java/util/Set->toArray()[Ljava/lang/Object;":
                Set set = (Set) dvmObject.getValue();
                Object[] array = set.toArray();
                DvmObject[] objects = new DvmObject[array.length];
                for (int i = 0; i < array.length; i++) {
                    if (array[i] instanceof String) {
                        objects[i] = new StringObject(vm, (String) array[i]);
                    } else {
                        throw new IllegalStateException("array=" + array[i]);
                    }
                }
                return new ArrayObject(objects);
            case "java/util/HashMap->get(Ljava/lang/Object;)Ljava/lang/Object;": {
                HashMap map = (HashMap) dvmObject.getValue();
                Object key = varArg.getObject(0).getValue();
                Object obj = map.get(key);
                if (obj instanceof String) {
                    return new StringObject(vm, (String) obj);
                } else {
                    throw new IllegalStateException("array=" + obj);
                }
            }
            case "com/taobao/sns/ISApplication->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, APK_INSTALL_PATH);
            case "com/uc/crashsdk/JNIBridge->registerInfoCallback(Ljava/lang/String;IJI)I":
                return DvmInteger.valueOf(vm, 257);
            case "com/taobao/sns/ISApplication->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(new File("target"));
            case "com/taobao/sns/ISApplication->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":

                return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(new File("target"));
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
                File file = (File) dvmObject.getValue();
                return new StringObject(vm, file.getAbsolutePath());
        }

        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/taobao/dp/util/CallbackHelper->onCallBack(ILjava/lang/String;I)V":
                int i1 = varArg.getInt(0);
                StringObject str = varArg.getObject(1);
                int i2 = varArg.getInt(2);
                System.out.println("com/taobao/dp/util/CallbackHelper->onCallBack i1=" + i1 + ", str=" + str + ", i2=" + i2);
                return;
            case "com/alibaba/wireless/security/open/edgecomputing/ECMiscInfo->registerAppLifeCyCleCallBack()V":
                System.out.println("registerAppLifeCyCleCallBack");
                return;
        }

        super.callStaticVoidMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject getObjectField(BaseVM vm, DvmObject dvmObject, String signature) {
        switch (signature) {
            case "android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;":
                return new StringObject(vm, new File("target").getAbsolutePath());
        }

        return super.getObjectField(vm, dvmObject, signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "android/os/Build$VERSION->SDK_INT:I":
                return 19;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/alibaba/wireless/security/framework/utils/UserTrackMethodJniBridge->utAvaiable()I":
                return 1;
            case "com/taobao/wireless/security/adapter/common/SPUtility2->saveToFileUnifiedForNative(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I":
                StringObject a1 = varArg.getObject(0);
                StringObject a2 = varArg.getObject(1);
                StringObject a3 = varArg.getObject(2);
                boolean b4 = varArg.getInt(3) != 0;
                System.out.println("saveToFileUnifiedForNative a1=" + a1 + ", a2=" + a2 + ", a3=" + a3 + ", b4=" + b4);
            case "com/uc/crashsdk/JNIBridge->registerInfoCallback(Ljava/lang/String;IJI)I":
                System.out.println("registerInfoCallback a1=" + varArg.getObject(0) + ", a2=" + varArg.getObject(1) + ", a3=" + varArg.getObject(2) + ", b4=" + varArg.getObject(3));
                return 257;
        }

        return super.callStaticIntMethod(vm, dvmClass, signature, varArg);
    }

    private long count;

    @Override
    public void setStaticLongField(BaseVM vm, String signature, long value) {
        switch (signature) {
            case "com/alibaba/wireless/security/framework/SGPluginExtras->slot:J":
                System.out.println("set -> slot:" + value);
                count = value;
//                DvmClass dvmClass = vm.findClass("com/alibaba/wireless/security/framework/SGPluginExtras");
//                vm.findClass("")
//                java.lang.ClassLoader classLoader =  super.callObjectMethodV(vm,null,"android/app/Application->getClassLoader()Ljava/lang/ClassLoader;",null);

//                cl dvmClass.getClassName();
//                vm.resolveClass()

                try {
//                    Class<?> clazz = classLoader.loadClass(dvmClass.getClassName());
//                    Field field = clazz.getDeclaredFields()[0];
//                    field.setAccessible(true);
//                    field.getLong("slot");
//                    clazz.getDeclaredField("slot");

//                    fields[0].get(sgPluginExtras);
                } catch (Exception e) {
                    e.printStackTrace();
                }
//                DvmClass dvmClass = vm.resolveClass("com/alibaba/wireless/security/framework/SGPluginExtras");

//                DvmClass dvmClass = vm.findClass("com.alibaba.wireless.security.framework.SGPluginExtras");
//                Class<?> clazz = classLoader.loadClass(dvmClass.getClassName());
//                ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
//                field.setLong(null, value);
                return;

        }
        super.setStaticLongField(vm, signature, value);
    }

    @Override
    public long getStaticLongField(BaseVM vm, String signature) {
        switch (signature) {
            case "com/alibaba/wireless/security/framework/SGPluginExtras->slot:J":
                System.out.println("get -> slot:" + count);
                return count;
        }
        return super.getStaticLongField(vm, signature);
    }

}
