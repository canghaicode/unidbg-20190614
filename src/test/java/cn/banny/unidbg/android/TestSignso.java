package cn.banny.unidbg.android;

import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import cn.banny.unidbg.linux.android.dvm.wrapper.DvmInteger;
import cn.banny.unidbg.linux.file.ByteArrayFileIO;
import cn.banny.unidbg.linux.file.SimpleFileIO;
import cn.banny.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TestSignso extends AbstractJni implements IOResolver {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator();
    }

    private final ARMEmulator emulator;
    private final VM vm;

    private final DvmClass Native;

    private TestSignso() throws IOException {
//        Logger.getLogger("cn.banny.unidbg.AbstractEmulator").setLevel(Level.DEBUG);

        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(APK_FILE);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary("sgmainso-6.4.152", false);
        dm.callJNI_OnLoad(emulator);

        Native = vm.resolveClass("com.taobao.wireless.security.adapter.JNICLibrary".replace(".", "/"));
    }

    private static final String APK_INSTALL_PATH = "/data/app/test.apk";
    private static final File APK_FILE = new File("src/test/resources/app/taobao_8.8.0.apk");

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
        TestSignso test = new TestSignso();
        test.test();
        test.destroy();
    }

    private void test() {
        DvmObject context = vm.resolveClass("android/content/Context").newObject(null);
        long start = System.currentTimeMillis();
        Number ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10101,
                new ArrayObject(context, DvmInteger.valueOf(vm, 3), new StringObject(vm, ""), new StringObject(vm, new File("target/taobao_SGLib").getAbsolutePath()), new StringObject(vm, ""))
        );
        long hash = ret.intValue() & 0xffffffffL;
        DvmObject dvmObject = vm.getObject(hash);
        System.out.println("hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10102,
                new ArrayObject(new StringObject(vm, "main"), new StringObject(vm, "6.4.152"),
                        new StringObject(vm, "E:\\Learn\\unidbg-20190613\\src\\test\\resources\\example_binaries\\armeabi-v7a\\libsgmainso-6.4.152.so")));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        Map<String, String> map = new HashMap<>();
//        map.put("INPUT", "XPDlGfM+zOoDAMHyPLa9+Okq&&&21646297&99914b932bd37a50b983c5e7c90ae93b&1560149480&mtop.common.gettimestamp&*&&231200@taobao_android_8.8.0&AjA1TIyT9T8vcuFw8Osrli35ALbE3ZW2SHLZNuihw8Ku&&&27&&&&&&&");
        map.put("INPUT", "YHPAD8SWj+gDALwiyqQdaUNN&&&21646297&42d063fc9d54cd0df3e77756027cbf1b&1618397404&mtop.alimama.zz.ad.get&1.0&&700407@taobao_android_8.8.0&AmaGermHzPICx1YWwN725S3LHWyX4OCN5LoQG5nPXJJf&&&27&&&&&&&");
        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                10401,
                new ArrayObject(vm.resolveClass("java/util/HashMap").newObject(map),
                        new StringObject(vm, "21646297"), DvmInteger.valueOf(vm, 7), null, DvmBoolean.valueOf(vm, true)));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("10401 -> hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();

        start = System.currentTimeMillis();
        ret = Native.callStaticJniMethod(emulator, "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                12302,
                new ArrayObject(DvmInteger.valueOf(vm, 0), DvmBoolean.valueOf(vm, false)));
        hash = ret.intValue() & 0xffffffffL;
        dvmObject = vm.getObject(hash);
        System.out.println("12302 hash:" + hash + ", dvmObject=" + dvmObject + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        vm.deleteLocalRefs();
    }

    @Override
    public DvmObject callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->getMainPluginClassLoader()Ljava/lang/ClassLoader;":
                return vm.resolveClass("java/lang/ClassLoader").newObject(null);
            case "com/taobao/wireless/security/adapter/common/SPUtility2->readFromSPUnified(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                StringObject a1 = varArg.getObject(0);
                StringObject a2 = varArg.getObject(1);
                StringObject a3 = varArg.getObject(2);
                System.out.println("readFromSPUnified a1=" + a1 + ", a2=" + a2 + ", a3=" + a3);
                return null;
            case "com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForString(I)Ljava/lang/String;":
                int value = varArg.getInt(0);
                System.out.println("com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForString value=" + value);
                if (value == 122)
                    return new StringObject(vm, "com.taobao.taobao");
                else if (value == 135)
                    return new StringObject(vm, "YHPAD8SWj+gDALwiyqQdaUNN");
                return null;
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
                    if(array[i] instanceof String) {
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
                if(obj instanceof String) {
                    return new StringObject(vm, (String) obj);
                } else {
                    throw new IllegalStateException("array=" + obj);
                }
            }
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, APK_INSTALL_PATH);
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(new File("target"));
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
                return 1;
        }

        return super.callStaticIntMethod(vm, dvmClass, signature, varArg);
    }
}
